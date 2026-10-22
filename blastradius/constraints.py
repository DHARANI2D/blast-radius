"""Deterministic plan constraints. These are code, never LLM judgement.

A plan is rejected if any wave:
  * takes both members of a redundant switch pair down together (REDUNDANT_PAIR)
  * causes any workload outage in simulation (PLANNED_OUTAGE)
  * puts more hosts of a cluster in maintenance than capacity/policy allow (CLUSTER_CAPACITY)
  * is larger than the policy wave size (WAVE_SIZE)
  * has a canary that is too big or hosts critical workloads (CANARY_FIRST); when no target server is eligible
    (switch-only change, or only tier-0/1 or single-homed hosts) the canary is instead exactly one asset
  * has a canary that leaves a required configuration cohort untested (CANARY_COVERAGE)
or the plan as a whole misses/duplicates targets (COVERAGE) or overruns the window (WINDOW). A plan that
schedules nothing (EMPTY_PLAN) or has a wave with nothing in it (EMPTY_WAVE) is rejected too.
"""

from __future__ import annotations

from collections import Counter

from .cohorts import build as build_cohorts, coverage, eligible
from .policy import Policy
from .topology import Topology


def wave_duration(assets: list[str], evacuate: list[str], topo: Topology, components: list[str], policy: Policy) -> int:
    d = policy.get("execution.durations_min", {})
    server_parts = [c for c in components if c in ("iLO 6", "System ROM")]
    times = [0]
    if any(a in topo.servers for a in assets) or evacuate:
        times.append(int(d.get("evacuate", 5)) + sum(int(d.get(c, 10)) for c in server_parts))
    if any(a in topo.switches for a in assets):
        times.append(int(d.get("Switch OS", 20)))
    return max(times) + int(d.get("soak", 10))


def impact_kwargs(policy: Policy) -> dict:
    return {
        "tier_weights": policy.get("impact.tier_weights", {}),
        "migrated_weight": float(policy.get("impact.migrated_vm_weight", 0.05)),
        "brs_scale": float(policy.get("impact.brs_scale", 30)),
    }


def wave_impact(wave: dict, topo: Topology, policy: Policy) -> dict:
    sw = [a for a in wave["assets"] if a in topo.switches]
    hosts = [a for a in wave["assets"] if a in topo.servers] + [e for e in wave.get("evacuate", []) if e in topo.servers]
    return topo.simulate(sw, hosts, **impact_kwargs(policy))


def describe_outage(imp: dict, limit: int = 3) -> str:
    n = len(imp["impacted_vms"])
    crit = imp["critical_vms"]
    parts = [f"{n} VM{'s' if n != 1 else ''} lose service"]
    if crit:
        parts.append("including tier-0 " + ", ".join(crit[:limit]) + ("..." if len(crit) > limit else ""))
    causes = []
    if imp["isolated_servers"]:
        causes.append(f"{len(imp['isolated_servers'])} host(s) lose every network path ({', '.join(imp['isolated_servers'][:limit])}{'...' if len(imp['isolated_servers']) > limit else ''})")
    if imp["arrays_unreachable"]:
        causes.append(f"storage array {', '.join(imp['arrays_unreachable'])} is cut off, so {len(imp['storage_lost_servers'])} other host(s) lose their datastores")
    if imp["capacity_shortfall_gb"]:
        causes.append("not enough cluster capacity to evacuate: " + ", ".join(f"{c} short {g} GB" for c, g in imp["capacity_shortfall_gb"].items()))
    return "; ".join(parts) + (" - " + "; ".join(causes) if causes else "")


def check_plan(plan: dict, topo: Topology, targets: list[str], components: list[str], policy: Policy,
               window_minutes: int, deferred: list[str] | None = None) -> dict:
    deferred = set(deferred or [])
    violations: list[dict] = []
    impacts: list[dict] = []
    canary_max = int(policy.get("planning.canary_max_assets", 2))
    canary_max_tier = int(policy.get("planning.canary_max_tier", 2))
    per_cluster = int(policy.get("planning.max_parallel_per_cluster", 5))
    wave_max = int(policy.get("planning.max_assets_per_wave", 12))
    cap = {c: min(per_cluster, topo.cluster_capacity(c)["max_hosts_down"]) for c in topo.clusters}
    single = {s["server"] for s in topo.single_homed()}
    no_eligible = not any(eligible(a, topo, policy, single) for a in targets if a in topo.servers and a not in deferred)
    fallback = None

    def v(code, msg, wave=None, assets=()):
        violations.append({"code": code, "wave": wave, "message": msg, "assets": list(assets)})

    total = 0
    seen: Counter = Counter()
    if not any(w["assets"] for w in plan["waves"]):
        v("EMPTY_PLAN", f"plan schedules no asset ({len(plan['waves'])} wave(s)); there is nothing to approve", None, [])
    for i, w in enumerate(plan["waves"], start=1):
        assets, evac = w["assets"], w.get("evacuate", [])
        if not assets and not evac:
            v("EMPTY_WAVE", f"wave {i} has no assets and no evacuations", i, [])
        unknown = [a for a in assets + evac if a not in topo.servers and a not in topo.switches]
        if unknown:
            v("UNKNOWN_ASSET", f"wave {i} references unknown assets {unknown}", i, unknown)
        seen.update(assets)
        imp = wave_impact(w, topo, policy)
        dur = wave_duration(assets, evac, topo, components, policy)
        total += dur
        impacts.append({"wave": i, "name": w.get("name", f"Wave {i}"), "duration_min": dur, **imp})

        sw = [a for a in assets if a in topo.switches]
        # An evacuated host must be a server the change upgrades, or single-homed to a switch this wave reboots.
        # DEFERRED is about firmware writes: a deferred host may still be evacuated for its switch.
        stray = [e for e in evac if (e in topo.servers or e in topo.switches) and not (
            e in topo.servers and (e in set(targets) - deferred or (len(topo.links_of(e)) < 2 and set(topo.links_of(e)) & set(sw))))]
        if stray:
            v("COVERAGE", f"wave {i} evacuates {stray}, outside the change scope: an evacuated host must be a scheduled target "
              "or single-homed to a switch upgraded in the same wave", i, stray)
        for a in sw:
            p = topo.peer_of(a)
            if p in sw and a < p:
                v("REDUNDANT_PAIR", f"wave {i} takes down both members of redundant pair {a}/{p}", i, [a, p])
        if imp["impacted_vms"]:
            v("PLANNED_OUTAGE", f"wave {i}: {describe_outage(imp)}", i, imp["isolated_servers"] + imp["storage_lost_servers"])
        hosts = [a for a in assets + evac if a in topo.servers]
        by_cluster = Counter(topo.servers[h]["cluster"] for h in hosts)
        for c, n in by_cluster.items():
            if n > cap[c]:
                v("CLUSTER_CAPACITY", f"wave {i} puts {n} hosts of {c} in maintenance; limit is {cap[c]} "
                  f"(policy {per_cluster}, capacity allows {topo.cluster_capacity(c)['max_hosts_down']})", i,
                  [h for h in hosts if topo.servers[h]["cluster"] == c])
        if len(assets) > wave_max:
            v("WAVE_SIZE", f"wave {i} has {len(assets)} assets; policy maximum is {wave_max}", i, assets)
        if i == 1 and no_eligible:
            # No low-tier dual-homed server to canary on: the canary is one asset (a pair member or a single host).
            if len(assets) != 1:
                v("CANARY_FIRST", f"no target is eligible for a low-tier canary, so wave 1 must be a one-asset canary "
                  f"(has {len(assets)})", 1, assets)
            else:
                fallback = assets[0]
        elif i == 1:
            if len(assets) > canary_max:
                v("CANARY_FIRST", f"wave 1 is the canary and may hold at most {canary_max} assets (has {len(assets)})", 1, assets)
            crit = [h for h in hosts if (topo.most_critical_tier(h) is not None and topo.most_critical_tier(h) < canary_max_tier)]
            if crit:
                v("CANARY_FIRST", f"canary hosts {crit} run tier-{min(topo.most_critical_tier(h) for h in crit)} workloads", 1, crit)
            if sw:
                v("CANARY_FIRST", f"canary wave includes network devices {sw}; canary with servers first", 1, sw)

    cov = None
    if plan["waves"] and policy.get("planning.canary_cohort_coverage", True):
        scheduled = [a for a in targets if a in topo.servers and a not in deferred]
        cov = coverage([a for a in plan["waves"][0]["assets"] if a in topo.servers],
                       build_cohorts(scheduled, topo.servers, components), topo, policy)
        if not cov["ok"]:
            miss = cov["missing"]
            v("CANARY_COVERAGE", f"canary covers {cov['covered']}/{cov['total']} configuration cohorts; untested: "
              + "; ".join(f"{m['label']} ({m['size']} hosts)" for m in miss), 1, [])

    rescheduled = sorted(a for a in seen if a in deferred)
    if rescheduled:
        v("DEFERRED", f"plan upgrades {len(rescheduled)} deferred asset(s) that match a known regression: "
          f"{rescheduled[:6]}{'...' if len(rescheduled) > 6 else ''}", None, rescheduled)
    dupes = [a for a, n in seen.items() if n > 1]
    if dupes:
        v("COVERAGE", f"assets scheduled more than once: {dupes}", None, dupes)
    expected = set(targets) - deferred
    missing = sorted(expected - set(seen))
    extra = sorted(set(seen) - set(targets))
    if missing:
        v("COVERAGE", f"{len(missing)} target(s) not scheduled: {missing[:6]}{'...' if len(missing) > 6 else ''}", None, missing)
    if extra:
        v("COVERAGE", f"assets outside the change request: {extra}", None, extra)
    if total > window_minutes:
        v("WINDOW", f"plan needs {total} min; maintenance window is {window_minutes} min", None, [])
    return {"ok": not violations, "violations": violations, "impacts": impacts, "total_duration_min": total,
            "max_brs": max((x["brs"] for x in impacts), default=0.0), "cluster_limits": cap, "canary_coverage": cov,
            "canary_fallback": fallback}
