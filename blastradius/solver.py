"""Deterministic wave solver.

Used as the safety net when the LLM planner cannot produce a feasible plan, and
as the reference the offline planner stand-in converges to. Greedy, but it
always satisfies ``constraints.check_plan`` for feasible inputs:

1. Canary: one lowest-risk, dual-homed host with no critical workloads from each
   configuration cohort (model + untouched firmware), up to ``canary_max_assets``.
   With no such host, a one-asset canary: a switch (one without single-homed hosts
   first) or else the lowest-risk host.
2. Members of each redundant switch pair go into different waves.
3. Hosts that are single-homed to a switch are scheduled (or evacuated) in that
   switch's wave, so they are already empty when it reboots.
4. Remaining hosts fill waves up to the per-cluster and per-wave limits.
"""

from __future__ import annotations

from .cohorts import build as build_cohorts, eligible, required as required_cohorts, risk_ranked_canary, select_canary
from .constraints import check_plan
from .policy import Policy
from .topology import Topology


def solve(target_servers: list[str], target_switches: list[str], topo: Topology, risk: dict[str, float],
          policy: Policy, components: list[str], window_minutes: int) -> list[dict]:
    wave_max = int(policy.get("planning.max_assets_per_wave", 12))
    per_cluster = int(policy.get("planning.max_parallel_per_cluster", 5))
    cap = {c: max(1, min(per_cluster, topo.cluster_capacity(c)["max_hosts_down"])) for c in topo.clusters}
    single = {s["server"]: s["up_links"] for s in topo.single_homed()}

    servers = sorted(target_servers, key=lambda s: (risk.get(s, 0), s))

    # 1. canary: one eligible host per configuration cohort (see cohorts.py), or the
    #    conventional lowest-risk-per-cluster rule if cohort coverage is switched off.
    if policy.get("planning.canary_cohort_coverage", True):
        canary = select_canary(servers, topo, risk, policy, components)
    else:
        canary = risk_ranked_canary(servers, topo, risk, policy)
    remaining = [s for s in servers if s not in canary]
    waves: list[dict] = []
    if canary:
        waves.append({"name": "Wave 1 - canary", "assets": canary, "evacuate": []})

    # 2. switches: one member of each pair per wave
    switch_waves: list[list[str]] = []
    placed: set[str] = set()
    for sw in sorted(target_switches):
        if sw in placed:
            continue
        group = [sw]
        peer = topo.peer_of(sw)
        if peer in target_switches and peer not in placed:
            group.append(peer)
        for k, member in enumerate(group):
            while len(switch_waves) <= k:
                switch_waves.append([])
            switch_waves[k].append(member)
            placed.add(member)

    body: list[dict] = [{"assets": list(sws), "evacuate": []} for sws in switch_waves]

    # 3. single-homed hosts ride with the switch they depend on
    for s, ups in single.items():
        for w in body:
            if any(u in w["assets"] for u in ups):
                if s in remaining:
                    w["assets"].append(s)
                    remaining.remove(s)
                elif s not in target_servers and s not in w["evacuate"]:
                    w["evacuate"].append(s)

    # 4. fill
    def count(w: dict, cluster: str) -> int:
        return sum(1 for a in w["assets"] + w["evacuate"] if a in topo.servers and topo.servers[a]["cluster"] == cluster)

    for s in remaining:
        c = topo.servers[s]["cluster"]
        for w in body:
            if count(w, c) < cap[c] and len(w["assets"]) < wave_max:
                w["assets"].append(s)
                break
        else:
            body.append({"assets": [s], "evacuate": []})

    for w in body:
        waves.append({"name": "", "assets": w["assets"], "evacuate": w["evacuate"]})
    if not canary and waves:
        # No eligible canary host: one asset goes first on its own, with the hosts single-homed to it evacuated.
        hosted = {sw: [s for s, ups in single.items() if sw in ups] for sw in target_switches}
        first = (sorted(target_switches, key=lambda sw: (len(hosted[sw]), sw))[:1]
                 or sorted(target_servers, key=lambda s: (risk.get(s, 0), s))[:1])
        if first:
            c = first[0]
            evac = hosted.get(c, [])
            for w in waves:
                w["assets"] = [a for a in w["assets"] if a != c]
                if c in topo.switches:
                    w["evacuate"] = [e for e in w["evacuate"] if e not in evac]
            waves = [{"name": "", "assets": [c], "evacuate": evac}] + [w for w in waves if w["assets"] or w["evacuate"]]
            canary = [c]

    # Safety net: split any wave that still violates a per-wave constraint.
    targets = target_servers + target_switches
    for _ in range(10):
        res = check_plan({"waves": waves}, topo, targets, components, policy, window_minutes)
        bad = sorted({v["wave"] for v in res["violations"] if v["wave"] and v["code"] in ("CLUSTER_CAPACITY", "WAVE_SIZE", "PLANNED_OUTAGE")})
        if not bad:
            break
        i = bad[0] - 1
        w = waves[i]
        hosts = [a for a in w["assets"] if a in topo.servers and a not in single]
        if len(hosts) < 2:
            break
        moved = hosts[len(hosts) // 2:]
        w["assets"] = [a for a in w["assets"] if a not in moved]
        waves.insert(i + 1, {"name": "", "assets": moved, "evacuate": []})
    for i, w in enumerate(waves, start=1):
        sws = [a for a in w["assets"] if a in topo.switches]
        if i == 1 and canary:
            w["name"] = "Wave 1 - canary"
        else:
            w["name"] = f"Wave {i} - " + (f"{', '.join(sws)} + hosts" if sws else "hosts")
    return waves


def plan_facts(topo: Topology, targets: dict, policy: Policy, components: list[str] | None = None,
               deferred: list[str] | set[str] = ()) -> dict:
    per_cluster = int(policy.get("planning.max_parallel_per_cluster", 5))
    scheduled = [s for s in targets["servers"] if s not in set(deferred)]
    on_targets = [s for s in topo.single_homed() if set(s["up_links"]) & set(targets["switches"])]
    cohorts = build_cohorts(scheduled, topo.servers, components or [])
    req = {c["id"] for c in required_cohorts(cohorts, topo, policy)}
    limits = {c: min(per_cluster, topo.cluster_capacity(c)["max_hosts_down"]) for c in topo.clusters}
    tgt_sw = set(targets["switches"])
    return {
        "redundant_target_pairs": [p for p in topo.redundant_pairs() if p[0] in tgt_sw and p[1] in tgt_sw],
        "no_eligible_canary": not any(eligible(s, topo, policy) for s in scheduled),
        "_low_tier_servers": [s for s in scheduled if (topo.most_critical_tier(s) is None
                                                       or topo.most_critical_tier(s) >= int(policy.get("planning.canary_max_tier", 2)))],
        "single_homed": topo.single_homed(),
        # Hosts to upgrade in their switch's wave; a deferred or non-target host must not look schedulable,
        # so it is listed apart: it goes in that wave's `evacuate` (maintenance mode, no upgrade).
        "single_homed_on_targets": [s for s in on_targets if s["server"] in scheduled],
        "evacuate_with_switch": [{**s, "reason": "deferred" if s["server"] in set(deferred) else "not a target"}
                                 for s in on_targets if s["server"] not in scheduled],
        "cluster_limits": limits,
        "per_cluster_limit": min(limits.values()) if limits else per_cluster,
        "cohorts": [{"id": c["id"], "label": c["label"], "size": len(c["hosts"]), "required_in_canary": c["id"] in req}
                    for c in cohorts],
        "_cohorts_full": cohorts,
    }


def grounded_rationale(waves: list[dict], facts: dict, components: list[str], duration_min: int) -> str:
    s = []
    # Only what is true of this plan: a one-asset fallback canary on a switch or a tier-0/1 host is not called low-tier.
    if waves and set(waves[0]["assets"]) <= set(facts.get("_low_tier_servers", [])):
        s.append(f"Wave 1 is a canary of {' and '.join(waves[0]['assets'])} with no tier-0 or tier-1 workloads.")
    full = facts.get("_cohorts_full") or []
    req = {c["id"] for c in facts.get("cohorts", []) if c["required_in_canary"]}
    if waves and req:
        canary = set(waves[0]["assets"])
        hit = {c["id"] for c in full if canary & set(c["hosts"])}
        if req <= hit:
            n = len(facts["cohorts"])
            s.append(f"The canary covers all {n} configuration cohorts." if len(req) == n
                     else f"The canary covers the {len(req)} largest of {n} configuration cohorts.")
    for a, b, _t in facts["redundant_target_pairs"]:
        s.append(f"{a} and {b} are upgraded in different waves.")
    for sh in facts["single_homed_on_targets"]:
        if sh["up_links"]:
            s.append(f"{sh['server']} is single-homed and is scheduled in the same wave as {sh['up_links'][0]}.")
    for sh in facts.get("evacuate_with_switch", []):
        if sh["up_links"]:
            s.append(f"{sh['server']} is single-homed and is evacuated in the same wave as {sh['up_links'][0]}.")
    s.append(f"No wave has more than {facts['per_cluster_limit']} hosts of one cluster in maintenance.")
    s.append("No wave causes a workload outage.")
    if "iLO 6" in components and "System ROM" in components:
        s.append("Update iLO 6 before System ROM.")
    s.append(f"The plan takes about {duration_min} minutes and fits the window.")
    return " ".join(s)
