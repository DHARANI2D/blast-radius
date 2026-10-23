"""Business impact of a caught canary regression, derived from the digital twin.

A flat "4 h x $300K/h" says nothing about *this* change, so instead we replay the
counterfactual on the twin and price what the replay shows:

1. Counterfactual plan. A conventional risk-ranked canary (``cohorts.risk_ranked_canary``)
   replaces the approved canary: each risk-ranked pick trades places with an
   approved canary host (same cluster first), so every target is still upgraded
   exactly once and the later waves keep their shape.
2. Timeline. Waves run back to back with the plan model's durations
   (``constraints.wave_duration``): hosts in a wave are flashed in parallel and
   return to service before the soak, and the post-check at the end of the soak
   detects the regression in the first wave that holds an affected host. A
   regression that only the statistical canary judge saw is not caught by a fleet
   wave's threshold post-check (unless ``canary_stats.all_waves``), so it is noticed
   ``business.missed_detection_delay_min`` later. The rollout halts at detection;
   affected hosts are evacuated and rolled back (evacuate + component times), all
   hosts of one original wave in parallel, one wave after another.
3. Exposure. Each affected host's VMs (twin placement: DRS returns workloads to
   their home host after maintenance) are degraded from the host's return to
   service until it is evacuated for rollback. Summed by tier and service, with a
   check for services left without a healthy replica.
4. Cost. Explicit rates from policy ``business.*``: degraded cost per VM-hour by
   tier, a Sev-1 (incident response + SLA credits) when a tier-0 VM is degraded,
   and diagnosis effort (automated when the canary's per-component probe pinned the
   culprit, manual otherwise). The same replay on the approved plan gives what
   actually happened, and avoided = counterfactual - actual.

Every rate is returned with its value and source. Company-wide downtime figures
(such as ITIC's hourly cost) describe a whole business outage, not one pod's
degraded VMs, so none is applied here.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Callable

from .cohorts import build as build_cohorts, coverage, risk_ranked_canary
from .constraints import check_plan, wave_duration
from .policy import Policy
from .topology import Topology

# Fallbacks only: the rates are listed, with their source, in policy.yaml (business).
DEFAULT_VM_HOUR_USD = {0: 20000, 1: 2500, 2: 150, 3: 10}
DEFAULT_DIAGNOSIS_HOURS = {"manual": 24, "automated": 1}
# Regression metrics that mean VMs lose service rather than run degraded.
OUTAGE_METRICS = {"reachability", "vm_heartbeats", "during:reachability"}


def _rates(policy: Policy) -> dict:
    g = policy.get
    vm = g("business.degraded_cost_per_vm_hour_usd", None) or DEFAULT_VM_HOUR_USD
    return {
        "vm_hour": {int(k): float(v) for k, v in vm.items()},
        "sev1_tier_max": int(g("business.sev1_tier_max", 0)),
        "sev1_hours": float(g("business.sev1_response_engineer_hours", 30)),
        "sla_credits": float(g("business.sev1_sla_credits_usd", 50000)),
        "eng_rate": float(g("business.engineer_rate_usd_per_hour", 150)),
        "diag_hours": {**DEFAULT_DIAGNOSIS_HOURS, **(g("business.diagnosis_engineer_hours", None) or {})},
        "detection_delay": int(g("business.detection_delay_min", 0)),
        "missed_delay": int(g("business.missed_detection_delay_min", 240)),
        "rebalance_delay": int(g("business.rebalance_delay_min", 0)),
        "sensitivity": [int(x) for x in g("business.sensitivity_detection_delays_min", [0, 60, 240])],
    }


def _usd(x: float) -> float:
    return round(float(x), 2)


def _role(vm: str) -> str:
    """'payments-db-01' -> 'payments-db': instances of one role can stand in for each other."""
    stem, _, num = vm.rpartition("-")
    return stem if stem and num.isdigit() else vm


# ------------------------------------------------------------------ replay
def matcher(lesson: dict, topo: Topology, components: list[str], target_versions: dict | None = None) -> Callable[[str], bool]:
    """Hosts a learned regression applies to: a listed model, the culprit component in this change (at the culprit
    version, when target versions are known) and every untouched-firmware condition met (e.g. NIC 229.x)."""
    conds = (lesson.get("conditions") or {}).get("firmware_prefix", {})
    comp, ver, models = lesson.get("component"), lesson.get("version"), set(lesson.get("models", []))
    tv = target_versions or {}

    def affected(h: str) -> bool:
        s = topo.servers.get(h)
        if s is None or s["model"] not in models or comp not in components:
            return False
        if ver and tv.get(h, {}).get(comp, ver) != ver:
            return False
        return all(s["firmware"].get(c, "").startswith(p) for c, p in conds.items())

    return affected


def baseline_waves(plan: dict, canary: list[str], topo: Topology) -> list[dict]:
    """The approved plan with ``canary`` as wave 1. Each new canary host trades places with an approved canary host
    (same cluster first); approved canary hosts left without a partner go into an extra last wave."""
    waves = plan["waves"]
    approved = list(waves[0]["assets"]) if waves else []
    pulled = [h for h in canary if h not in approved]
    free = [h for h in approved if h not in canary]
    swap: dict[str, str] = {}
    for p in pulled:
        cl = (topo.servers.get(p) or {}).get("cluster")
        pick = [d for d in free if (topo.servers.get(d) or {}).get("cluster") == cl] or free
        if pick:
            swap[p] = pick[0]
            free.remove(pick[0])
    out = [{"name": "Wave 1 - canary (risk-ranked)", "assets": list(canary), "evacuate": []}]
    for w in waves[1:]:
        out.append({**w, "assets": [swap.get(a, a) for a in w["assets"] if a not in pulled or a in swap]})
    if free:
        out.append({"name": f"Wave {len(out) + 1} - hosts", "assets": free, "evacuate": []})
    return out


def replay(waves: list[dict], affected: Callable[[str], bool], topo: Topology, components: list[str], policy: Policy,
           detection_delay: int = 0, rebalance_delay: int = 0) -> dict:
    """Minute-by-minute outcome of running ``waves`` when ``affected`` hosts regress after their upgrade.

    Minute 0 is the start of wave 1. The canary (wave 1) always catches a regression at the end of its soak (probe
    + statistical judge); ``detection_delay`` > 0 models a fleet-wave post-check that misses it, so it is noticed
    that many minutes after the first affected wave's soak and waves already started keep going."""
    d = policy.get("execution.durations_min", {})
    soak, evac = int(d.get("soak", 10)), int(d.get("evacuate", 5))
    whole_wave = policy.get("execution.rollback_scope", "wave") == "wave"
    t, detect, detect_wave, delay = 0, None, None, 0
    rows: list[dict] = []
    back: dict[str, int] = {}
    wave_of: dict[str, int] = {}
    for i, w in enumerate(waves, start=1):
        servers = [a for a in w["assets"] if a in topo.servers]
        bad = [h for h in servers if affected(h)]
        row = {"wave": i, "name": w.get("name") or f"Wave {i}", "assets": len(w["assets"]), "affected_hosts": bad}
        if detect is not None and t >= detect:
            rows.append(row | {"start_min": None, "end_min": None, "back_in_service_min": None, "started": False})
            continue
        dur = wave_duration(w["assets"], w.get("evacuate", []), topo, components, policy)
        ret = t + wave_duration(servers, [], topo, components, policy) - soak if servers else None
        for h in bad:
            back[h], wave_of[h] = ret, i
        if bad and detect is None:
            delay = 0 if i == 1 else detection_delay
            detect, detect_wave = t + dur + delay, i
        rows.append(row | {"start_min": t, "end_min": t + dur, "back_in_service_min": ret, "started": True})
        t += dur

    for r in rows:
        if not r["started"]:
            r["status"] = "not started: rollout halted"
        elif detect is None or r["wave"] < detect_wave:
            r["status"] = "passed"
        elif r["wave"] == detect_wave:
            r["status"] = "regression detected by post-check" if delay == 0 else \
                f"post-check missed it; noticed {delay} min after the soak"
        elif r["end_min"] <= detect:
            r["status"] = "completed before the regression was noticed"
        else:
            r["status"] = "halted in flight"

    # Rollback: one batch per original wave (that set already fits the cluster limits), assets in parallel, each
    # taking evacuate + component time; batches run one after another from the moment of detection.
    batches, evacuated, tb = [], {}, detect
    for i in sorted(set(wave_of.values())):
        hosts = [h for h in back if wave_of[h] == i]
        scope = waves[i - 1]["assets"] if whole_wave else hosts
        dur = wave_duration(scope, [], topo, components, policy) - soak
        for h in hosts:
            evacuated[h] = tb + evac if back[h] < detect else None  # in-flight hosts are still in maintenance
        batches.append({"wave": i, "hosts": hosts, "assets_reverted": len(scope), "start_min": tb, "end_min": tb + dur})
        tb += dur

    hosts_out, vm_rows = [], []
    for h in back:
        start, end = back[h] + rebalance_delay, evacuated[h]
        minutes = max(0, end - start) if end is not None else 0
        vms = topo.vms_on(h)
        hosts_out.append({"host": h, "wave": wave_of[h], "cluster": topo.servers[h]["cluster"],
                          "back_in_service_min": back[h] if back[h] < detect else None, "evacuated_min": end,
                          "exposed_min": minutes, "vms": len(vms), "tier0_vms": sorted(v["name"] for v in vms if v["tier"] == 0)})
        if minutes:
            vm_rows += [{"vm": v["name"], "tier": v["tier"], "service": v["service"], "host": h,
                         "start_min": start, "end_min": end, "minutes": minutes} for v in vms]

    events: list[dict] = []
    for r in rows:
        if r["started"]:
            events.append({"t_min": r["start_min"], "event": f"{r['name']} starts"})
        exposed = [h for h in r["affected_hosts"] if h in back and back[h] < detect]
        if exposed:
            events.append({"t_min": r["back_in_service_min"],
                           "event": f"{len(exposed)} affected host(s) back in service on the bad firmware: {', '.join(exposed)}"})
    if detect is not None:
        events.append({"t_min": detect, "event": f"regression detected (wave {detect_wave}"
                       + (" post-check at the end of its soak)" if delay == 0 else f", {delay} min after its soak)")
                       + "; rollout halted"})
        for b in batches:
            events.append({"t_min": b["start_min"] + evac, "event": f"wave {b['wave']} affected hosts evacuated for rollback: exposure ends"})
        events.append({"t_min": tb, "event": "rollback complete"})
        events.append({"t_min": tb + soak, "event": "recovery verified after soak"})
    events.sort(key=lambda e: e["t_min"])
    return {"waves": rows, "hosts": hosts_out, "vm_rows": vm_rows, "events": events, "detected_wave": detect_wave,
            "detected_at_min": detect, "detection_delay_min": delay if detect is not None else None, "rollback": batches,
            "rollback_complete_min": tb if detect is not None else None,
            "recovery_verified_min": tb + soak if detect is not None else None}


# --------------------------------------------------------------- exposure
def exposure(vm_rows: list[dict], topo: Topology, outage: bool = False) -> dict:
    """Degraded VM-minutes by tier and service. A role (e.g. payments-db) whose every instance is exposed at the same
    time has no healthy replica; with an outage-class regression that service is unavailable, otherwise degraded."""
    tiers: dict[int, dict] = defaultdict(lambda: {"vms": 0, "vm_minutes": 0})
    by_svc: dict[str, list[dict]] = defaultdict(list)
    for r in vm_rows:
        tiers[r["tier"]]["vms"] += 1
        tiers[r["tier"]]["vm_minutes"] += r["minutes"]
        by_svc[r["service"]].append(r)
    services = {}
    for svc in sorted(by_svc):
        exposed = {r["vm"]: r for r in by_svc[svc]}
        members = [v for v in topo.vms.values() if v["service"] == svc]
        roles: dict[str, list[str]] = defaultdict(list)
        for v in members:
            roles[_role(v["name"])].append(v["name"])
        no_replica = sorted(role for role, names in roles.items()
                            if all(n in exposed for n in names)
                            and max(exposed[n]["start_min"] for n in names) < min(exposed[n]["end_min"] for n in names))
        services[svc] = {"service": svc, "tier": min(v["tier"] for v in members), "vms_exposed": len(exposed),
                         "vms_total": len(members), "vm_minutes": sum(r["minutes"] for r in exposed.values()),
                         "exposed_vms": sorted(exposed), "roles_without_healthy_replica": no_replica,
                         "state": "unavailable" if outage and no_replica else "degraded"}
    total = sum(r["minutes"] for r in vm_rows)
    return {"tiers": [{"tier": k, **tiers[k], "vm_hours": round(tiers[k]["vm_minutes"] / 60, 2)} for k in sorted(tiers)],
            "services": services,
            "vm_minutes": total,
            "vm_hours": round(total / 60, 2),
            "tier0_vms": sorted(r["vm"] for r in vm_rows if r["tier"] == 0),
            "tier0_services": sorted(s for s, x in services.items() if x["tier"] == 0),
            "unavailable_services": sorted(s for s, x in services.items() if x["state"] == "unavailable")}


def _cost(exp: dict, rates: dict, regressed: bool, automated: bool) -> dict:
    vm_hour = rates["vm_hour"]

    def rate(tier: int) -> float:
        return vm_hour.get(tier, vm_hour[max(vm_hour)])

    tiers = [{"tier": t["tier"], "vm_hours": t["vm_hours"], "rate_usd_per_vm_hour": rate(t["tier"]),
              "usd": _usd(t["vm_minutes"] / 60 * rate(t["tier"]))} for t in exp["tiers"]]
    sev1 = any(t["tier"] <= rates["sev1_tier_max"] for t in exp["tiers"])
    diag_h = rates["diag_hours"]["automated" if automated else "manual"] if regressed else 0
    out = {
        "degraded_vms_usd": _usd(sum(t["usd"] for t in tiers)),
        "by_tier": tiers,
        "sev1": sev1,
        "sev1_usd": _usd(rates["sev1_hours"] * rates["eng_rate"] + rates["sla_credits"]) if sev1 else 0.0,
        "diagnosis_engineer_hours": diag_h,
        "diagnosis_usd": _usd(diag_h * rates["eng_rate"]),
    }
    out["customer_impact_usd"] = _usd(out["degraded_vms_usd"] + out["sev1_usd"])
    out["total_usd"] = _usd(out["customer_impact_usd"] + out["diagnosis_usd"])
    return out


def scenario(label: str, waves: list[dict], affected: Callable[[str], bool], topo: Topology, components: list[str],
             policy: Policy, rates: dict, detection_delay: int = 0, outage: bool = False) -> dict:
    """Replay ``waves``, then price the exposure."""
    rp = replay(waves, affected, topo, components, policy, detection_delay, rates["rebalance_delay"])
    exp = exposure(rp.pop("vm_rows"), topo, outage)
    regressed = rp["detected_wave"] is not None
    # The executor probes golden signals after each component only in the canary (wave 1).
    automated = regressed and rp["detected_wave"] == 1 and bool(policy.get("execution.canary_component_probe", True))
    diagnosis = None if not regressed else ("automated: per-component probe in the canary pins the culprit" if automated
                                            else "manual: fleet waves have no per-component probe, so engineers must isolate the culprit")
    return {"label": label, "canary": list(waves[0]["assets"]) if waves else [], **rp, **exp,
            "hosts_exposed": sum(1 for h in rp["hosts"] if h["exposed_min"]), "diagnosis": diagnosis,
            "cost": _cost(exp, rates, regressed, automated)}


def fleet_detection(regressions: list[dict], policy: Policy) -> dict:
    """Would a fleet wave's post-check see this regression? The threshold check runs on every wave; the statistical
    canary judge only on the canary unless ``canary_stats.all_waves``."""
    if not regressions:
        return {"detects": True, "reason": "no measured regression to judge; assume the fleet post-check sees it"}
    if any(r.get("check") != "statistical" for r in regressions):
        return {"detects": True, "reason": "the threshold post-check (run after every wave) flagged it"}
    if bool(policy.get("canary_stats.all_waves", False)):
        return {"detects": True, "reason": "only the statistical judge flagged it, and it runs on every wave"}
    return {"detects": False, "reason": "only the statistical canary judge flagged it; fleet waves run the threshold check only"}


# ------------------------------------------------------------------- entry
def counterfactual_impact(lesson: dict, plan: dict, topo: Topology, policy: Policy, components: list[str],
                          risk: dict | None = None, actual_exec: dict | None = None) -> dict:
    """Business impact of a caught canary regression: counterfactual (risk-ranked canary) vs what actually happened.

    ``risk`` is the RiskAgent result (scores rank the conventional canary; target versions sharpen the match);
    without it the risk-ranked canary falls back to name order. ``actual_exec`` is the halted wave's execution
    record: its measured regressions define the actually affected hosts, the regression class and whether a fleet
    post-check would see it; its twin clock and post-check heartbeats are reported as cross-checks."""
    rates = _rates(policy)
    risk = risk or {}
    affected = matcher(lesson, topo, components, risk.get("target_versions"))
    targets = [a for w in plan["waves"] for a in w["assets"]]
    scheduled = [a for a in targets if a in topo.servers]
    scores = {a: r["score"] for a, r in (risk.get("assets") or {}).items()}
    naive = risk_ranked_canary(scheduled, topo, scores, policy)
    cov = coverage(naive, build_cohorts(scheduled, topo.servers, components), topo, policy)
    cf_waves = baseline_waves(plan, naive, topo)
    cf_check = check_plan({"waves": cf_waves}, topo, targets, components, policy, window_minutes=10 ** 6)

    regs = (actual_exec or {}).get("regressions", [])
    measured = sorted({r["asset"] for r in regs if r["asset"] in topo.servers})
    outage = any(r["metric"] in OUTAGE_METRICS for r in regs)
    actual_affected = (lambda h: h in measured) if measured else affected
    fleet = fleet_detection(regs, policy)
    base_delay = rates["detection_delay"] if fleet["detects"] else rates["missed_delay"]

    cf = scenario("Risk-ranked canary (conventional)", cf_waves, affected, topo, components, policy, rates, base_delay, outage)
    cf["canary_cohorts"] = f"{cov['covered']}/{cov['total']}"
    cf["canary_would_catch"] = any(affected(h) for h in naive)
    cf["plan_violations"] = sorted({v["code"] for v in cf_check["violations"]} - {"CANARY_COVERAGE"})
    act = scenario(("Cohort-coverage" if policy.get("planning.canary_cohort_coverage", True) else "Risk-ranked")
                   + " canary (what happened)", plan["waves"], actual_affected, topo, components, policy, rates, 0, outage)

    at_risk = [h for w in cf_waves[1:] for h in w["assets"] if h in topo.servers and affected(h)]
    at_risk_vms = [v for h in at_risk for v in topo.vms_on(h)]
    cf["if_undetected"] = {"hosts": at_risk, "vms": len(at_risk_vms),
                           "tier0_vms": sorted(v["name"] for v in at_risk_vms if v["tier"] == 0)}

    tier0 = [sum(t["vm_hours"] for t in s["tiers"] if t["tier"] == 0) for s in (cf, act)]
    # A regression first caught in a fleet wave got past the canary that ran: the canary earns no saving. Whatever the
    # two replays still differ by comes from the wave ordering, and is reported as that.
    fleet_caught = act["detected_wave"] not in (None, 1)
    earned = 0.0 if fleet_caught else 1.0
    avoided = {
        "usd": _usd(earned * (cf["cost"]["total_usd"] - act["cost"]["total_usd"])),
        "customer_impact_usd": _usd(earned * (cf["cost"]["customer_impact_usd"] - act["cost"]["customer_impact_usd"])),
        "vm_hours": round(earned * (cf["vm_hours"] - act["vm_hours"]), 2),
        "tier0_vm_hours": round(earned * (tier0[0] - tier0[1]), 2),
        "sev1_avoided": bool(earned) and cf["cost"]["sev1"] and not act["cost"]["sev1"],
        "caught_in_fleet_wave": act["detected_wave"] if fleet_caught else None,
        "ordering_difference_usd": _usd(cf["cost"]["total_usd"] - act["cost"]["total_usd"]) if fleet_caught else None,
    }
    sensitivity = []
    for dly in rates["sensitivity"]:
        s = cf if dly == base_delay else scenario("", cf_waves, affected, topo, components, policy, rates, dly, outage)
        sensitivity.append({"detection_delay_min": dly, "detected_at_min": s["detected_at_min"], "hosts_exposed": s["hosts_exposed"],
                            "vm_hours": s["vm_hours"], "tier0_vms": s["tier0_vms"], "counterfactual_usd": s["cost"]["total_usd"],
                            "avoided_usd": _usd(earned * (s["cost"]["total_usd"] - act["cost"]["total_usd"]))})

    twin_check = None
    if actual_exec is not None:
        idx = actual_exec.get("index", 0)
        halted = plan["waves"][idx - 1] if 0 < idx <= len(plan["waves"]) else {"assets": []}
        predicted = sorted(h for h in halted["assets"] if affected(h))
        post = {s["asset"]: s for s in actual_exec.get("post", [])}
        clock = (actual_exec.get("t_end_min", 0) - actual_exec.get("t_start_min", 0)) if "t_end_min" in actual_exec else None
        twin_check = {
            "measured_regressed_hosts": measured,
            "lesson_matches_in_halted_wave": predicted,
            "consistent": predicted == measured,
            "regression_class": "outage (VMs lose service)" if outage else "performance degradation (VMs keep running)",
            "fleet_postcheck": fleet,
            "vms_on_regressed_hosts_during_soak": {h: (post.get(h) or {}).get("vm_heartbeats", {}).get("expected") for h in measured},
            "halted_wave_twin_clock_min": clock,
            "halted_wave_model_min": wave_duration(halted["assets"], halted.get("evacuate", []), topo, components, policy) if idx else None,
            "note": "The twin applies writes one after another and does not model DRS rebalancing, so its clock runs longer "
                    "than the parallel plan model and evacuated hosts stay empty during the soak. The parallel model therefore "
                    "gives a shorter (conservative) counterfactual exposure, and the modelled actual exposure (workloads back "
                    "on their home host) is an upper bound.",
        }

    impact = {
        "lesson": {"id": lesson.get("id"), "culprit": f"{lesson.get('component')} {lesson.get('version')}",
                   "models": lesson.get("models", []),
                   "conditions": (lesson.get("conditions") or {}).get("firmware_prefix", {})},
        "counterfactual": cf,
        "actual": act,
        "avoided": avoided,
        "fleet_detection": fleet,
        "sensitivity": sensitivity,
        "twin_check": twin_check,
        "assumptions": assumptions(policy, rates),
    }
    impact["headline"] = _headline(impact)
    impact["explanation"] = explain(impact)
    return impact


# --------------------------------------------------------------- language
def assumptions(policy: Policy, rates: dict) -> list[dict]:
    d = policy.get("execution.durations_min", {})
    bus = policy.get("business", {}) or {}

    def illus(key: str) -> str:  # where an illustrative value came from
        return "illustrative (policy.yaml)" if key.split(".", 1)[1] in bus else "illustrative (code default)"

    dur = ", ".join(f"{k} {v} min" for k, v in d.items())
    vm = ", ".join(f"tier {k} ${v:,.0f}" for k, v in sorted(rates["vm_hour"].items()))
    dh = rates["diag_hours"]
    return [
        {"key": "execution.durations_min", "value": dur, "source": "policy.yaml (plan model)",
         "note": "wave timing; hosts in a wave are flashed and rolled back in parallel, as constraints.wave_duration assumes"},
        {"key": "timeline", "value": "waves back to back from minute 0", "source": "model",
         "note": "the fleet approval wait between the canary and wave 2 is not counted"},
        {"key": "business.detection_delay_min", "value": rates["detection_delay"], "source": illus("business.detection_delay_min"),
         "note": "counterfactual detection: the same per-wave post-check at the end of the soak (0) or this many minutes later"},
        {"key": "business.missed_detection_delay_min", "value": rates["missed_delay"], "source": illus("business.missed_detection_delay_min"),
         "note": "used instead when only the statistical canary judge saw the regression (fleet waves would miss it)"},
        {"key": "business.rebalance_delay_min", "value": rates["rebalance_delay"], "source": illus("business.rebalance_delay_min"),
         "note": "after exit-maintenance DRS returns each host's VMs (twin placement) after this delay; same for both scenarios"},
        {"key": "exposure_end", "value": "evacuated for rollback", "source": "model",
         "note": "a VM stops being degraded once live-migrated off the affected host; rollback batches follow the original waves"},
        {"key": "business.degraded_cost_per_vm_hour_usd", "value": vm, "source": illus("business.degraded_cost_per_vm_hour_usd"),
         "note": "lost revenue and productivity per degraded VM-hour; a degraded VM keeps running at reduced performance"},
        {"key": "business.sev1_tier_max", "value": rates["sev1_tier_max"], "source": illus("business.sev1_tier_max"),
         "note": "any degraded VM at or below this tier opens a Sev-1"},
        {"key": "business.sev1_response_engineer_hours", "value": rates["sev1_hours"], "source": illus("business.sev1_response_engineer_hours"),
         "note": "incident bridge, communications and post-incident review"},
        {"key": "business.sev1_sla_credits_usd", "value": rates["sla_credits"], "source": illus("business.sev1_sla_credits_usd"),
         "note": "SLA credits and penalties for a tier-0 degradation"},
        {"key": "business.engineer_rate_usd_per_hour", "value": rates["eng_rate"], "source": illus("business.engineer_rate_usd_per_hour"),
         "note": "loaded engineering cost"},
        {"key": "business.diagnosis_engineer_hours", "value": f"manual {dh['manual']:g} h, automated {dh['automated']:g} h",
         "source": illus("business.diagnosis_engineer_hours"), "note": "manual when the regression surfaces in a fleet wave (no per-component probe)"},
    ]


def _headline(impact: dict) -> dict:
    cf, act, av = impact["counterfactual"], impact["actual"], impact["avoided"]
    if av.get("caught_in_fleet_wave"):
        diff = av["ordering_difference_usd"]
        text = (f"No canary saving: the canary ({', '.join(act['canary'])}) passed and the regression was first caught in fleet "
                f"wave {av['caught_in_fleet_wave']}" + (f"; a risk-ranked canary would have met it in wave {cf['detected_wave']} too"
                                                        if cf["detected_wave"] else "")
                + (f". The optimised wave ordering exposed ${diff:,.0f} less than the greedy ordering would have" if diff > 0 else "")
                + ".")
    elif cf["detected_wave"] is None or cf["detected_wave"] == act["detected_wave"]:
        text = (f"Avoided ${av['usd']:,.0f}: a risk-ranked canary would have met this regression in the same wave"
                if cf["detected_wave"] else f"Avoided ${av['usd']:,.0f}: no host in the counterfactual plan matches the lesson")
    else:
        t0 = cf["tier0_vms"]
        text = (f"Avoided ~${av['usd']:,.0f} (illustrative rates): a risk-ranked canary would have passed; wave "
                f"{cf['detected_wave']}'s post-check catches the regression at minute {cf['detected_at_min']} after "
                f"{cf['hosts_exposed']} affected host(s) ran {cf['vm_hours']:.1f} degraded VM-hours"
                + (f", incl. tier-0 {', '.join(t0)} (Sev-1)" if t0 else "") + ".")
    return {"avoided_usd": av["usd"], "counterfactual_usd": cf["cost"]["total_usd"], "actual_usd": act["cost"]["total_usd"],
            "text": text}


def explain(impact: dict) -> str:
    """One plain-English paragraph."""
    cf, act, av, les = impact["counterfactual"], impact["actual"], impact["avoided"], impact["lesson"]
    cond = ", ".join(f"{k} {p}x" for k, p in les["conditions"].items())
    scope = f"{les['culprit']} on {', '.join(m.replace('HPE ProLiant ', '') for m in les['models'])}" + (f" with {cond}" if cond else "")
    if av.get("caught_in_fleet_wave"):
        return (f"The canary ({', '.join(act['canary'])}) held no host matching {scope} and passed; the regression surfaced "
                f"in fleet wave {av['caught_in_fleet_wave']} on {', '.join(h['host'] for h in act['hosts']) or 'its hosts'}, "
                f"where the post-check caught it (${act['cost']['total_usd']:,.0f}, manual diagnosis). A risk-ranked canary "
                + (f"would have met it in wave {cf['detected_wave']} as well (${cf['cost']['total_usd']:,.0f} on the greedy ordering), "
                   if cf["detected_wave"] else "would not have met it either, ")
                + "so no saving is credited to the canary.")
    if cf["detected_wave"] is None:
        return (f"No host in the counterfactual plan matches the learned regression ({scope}), so a risk-ranked canary "
                f"changes nothing here: avoided ${av['usd']:,.0f}.")
    if cf["detected_wave"] == 1:
        return (f"The risk-ranked canary ({', '.join(cf['canary'])}) also contains a host matching {scope}, so it would "
                f"have caught the regression in the canary too: counterfactual ${cf['cost']['total_usd']:,.0f}, actual "
                f"${act['cost']['total_usd']:,.0f}, avoided ${av['usd']:,.0f}.")
    exposed = [h for h in cf["hosts"] if h["exposed_min"]]
    t0, svc = cf["tier0_vms"], cf["services"]
    replica = "; ".join(f"{s} is {x['state']}" + (f" with no healthy {', '.join(x['roles_without_healthy_replica'])} replica"
                                                  if x["roles_without_healthy_replica"] else " but keeps a healthy replica")
                        for s, x in svc.items() if x["tier"] == 0)
    first_back = min(h["back_in_service_min"] for h in exposed) if exposed else cf["detected_at_min"]
    last_evac = max(h["evacuated_min"] for h in exposed) if exposed else cf["detected_at_min"]
    caught = (f"its post-check catches the regression at minute {cf['detected_at_min']}" if not cf["detection_delay_min"]
              else f"its post-check misses the regression, which is noticed at minute {cf['detected_at_min']}")
    ac = act["cost"]
    return (
        f"A conventional canary picked by lowest risk ({', '.join(cf['canary'])}) covers {cf['canary_cohorts']} configuration "
        f"cohorts and holds no host matching the learned regression ({scope}), so it would have passed. Replaying the plan "
        f"on the twin, wave {cf['detected_wave']} then returns {len(exposed)} affected host(s) to service from minute "
        f"{first_back}; {caught}, the hosts are evacuated by minute {last_evac} and rolled back by minute "
        f"{cf['rollback_complete_min']}. In that window {cf['vm_hours']:.1f} VM-hours run degraded across "
        f"{sum(x['vms_exposed'] for x in svc.values())} VMs"
        + (f", including tier-0 {', '.join(t0)} ({replica}), which opens a Sev-1" if t0 else "")
        + f"; with manual diagnosis that is ${cf['cost']['total_usd']:,.0f}. What actually happened: the cohort canary caught it on "
        f"{', '.join(h['host'] for h in act['hosts']) or 'the canary'}, which by policy runs no tier-0/1 workload "
        f"({act['vm_hours']:.1f} degraded VM-hours at most, {'a Sev-1' if ac['sev1'] else 'no Sev-1'}, automated diagnosis): "
        f"${ac['total_usd']:,.0f}. Avoided: ${av['usd']:,.0f}. Had the post-check missed it, all "
        f"{len(cf['if_undetected']['hosts'])} affected fleet hosts ({cf['if_undetected']['vms']} VMs) would be flashed wave by "
        f"wave (see the sensitivity rows). Dollar rates are illustrative policy assumptions, not measured costs."
    )


def cost_table(impact: dict) -> list[dict]:
    """Line items for both scenarios, for the UI table, the CLI and the report."""
    cf, act = impact["counterfactual"]["cost"], impact["actual"]["cost"]
    none = {"vm_hours": 0, "usd": 0.0, "rate_usd_per_vm_hour": None}
    rows = []
    for k in sorted({t["tier"] for t in cf["by_tier"]} | {t["tier"] for t in act["by_tier"]}):
        c = next((t for t in cf["by_tier"] if t["tier"] == k), none)
        a = next((t for t in act["by_tier"] if t["tier"] == k), none)
        rate = c["rate_usd_per_vm_hour"] or a["rate_usd_per_vm_hour"]
        rows.append({"item": f"Tier {k} degraded VM-hours (${rate:,.0f}/VM-h)", "counterfactual_qty": c["vm_hours"],
                     "counterfactual_usd": c["usd"], "actual_qty": a["vm_hours"], "actual_usd": a["usd"]})
    rows.append({"item": "Sev-1 incident (response + SLA credits)", "counterfactual_qty": int(cf["sev1"]),
                 "counterfactual_usd": cf["sev1_usd"], "actual_qty": int(act["sev1"]), "actual_usd": act["sev1_usd"]})
    rows.append({"item": "Diagnosis (engineer hours)", "counterfactual_qty": cf["diagnosis_engineer_hours"],
                 "counterfactual_usd": cf["diagnosis_usd"], "actual_qty": act["diagnosis_engineer_hours"], "actual_usd": act["diagnosis_usd"]})
    rows.append({"item": "Total", "counterfactual_qty": None, "counterfactual_usd": cf["total_usd"], "actual_qty": None,
                 "actual_usd": act["total_usd"]})
    for r in rows:
        r["avoided_usd"] = _usd(r["counterfactual_usd"] - r["actual_usd"])
    return rows


def markdown(impact: dict) -> str:
    """Report section (signed post-change report)."""
    cf = impact["counterfactual"]
    lines = ["## Business impact (derived from the twin)", "", f"**{impact['headline']['text']}**", "", impact["explanation"], "",
             "| Item | Counterfactual | Actual | Avoided |", "|---|---:|---:|---:|"]
    for r in cost_table(impact):
        q = f" ({r['counterfactual_qty']:g} / {r['actual_qty']:g})" if r["counterfactual_qty"] is not None else ""
        lines.append(f"| {r['item']}{q} | ${r['counterfactual_usd']:,.0f} | ${r['actual_usd']:,.0f} | ${r['avoided_usd']:,.0f} |")
    lines += ["", "Counterfactual timeline (minutes from the start of wave 1):"]
    lines += [f"- {e['t_min']}: {e['event']}" for e in cf["events"]]
    if impact["sensitivity"]:
        lines += ["", "Sensitivity (detection delay after the first affected fleet wave's soak):"]
        lines += [f"- +{s['detection_delay_min']} min: {s['hosts_exposed']} hosts, {s['vm_hours']:.1f} VM-hours, "
                  f"{len(s['tier0_vms'])} tier-0 VMs, avoided ${s['avoided_usd']:,.0f}" for s in impact["sensitivity"]]
    lines += ["", "Assumptions:"]
    lines += [f"- `{a['key']}` = {a['value']} ({a['source']}): {a['note']}" for a in impact["assumptions"]]
    return "\n".join(lines)


def summary_lines(impact: dict) -> list[str]:
    """Short form for the CLI demo summary."""
    h, cf, act = impact["headline"], impact["counterfactual"], impact["actual"]
    return [
        h["text"],
        f"  counterfactual ${h['counterfactual_usd']:,.0f} ({cf['vm_hours']:.1f} degraded VM-hours, "
        f"{'Sev-1' if cf['cost']['sev1'] else 'no Sev-1'}, {cf['cost']['diagnosis_engineer_hours']:g} h diagnosis) vs actual "
        f"${h['actual_usd']:,.0f} ({act['vm_hours']:.1f} VM-hours, {'Sev-1' if act['cost']['sev1'] else 'no Sev-1'})",
    ]
