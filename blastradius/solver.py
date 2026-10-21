"""Deterministic wave solver.

Used as the safety net when the LLM planner cannot produce a feasible plan, and
as the reference the offline planner stand-in converges to. Greedy, but it
always satisfies ``constraints.check_plan`` for feasible inputs:

1. Canary: up to ``canary_max_assets`` lowest-risk, dual-homed hosts running no
   critical workloads, one per cluster where possible.
2. Members of each redundant switch pair go into different waves.
3. Hosts that are single-homed to a switch are scheduled (or evacuated) in that
   switch's wave, so they are already empty when it reboots.
4. Remaining hosts fill waves up to the per-cluster and per-wave limits.
"""

from __future__ import annotations

from .constraints import check_plan
from .policy import Policy
from .topology import Topology


def solve(target_servers: list[str], target_switches: list[str], topo: Topology, risk: dict[str, float],
          policy: Policy, components: list[str], window_minutes: int) -> list[dict]:
    canary_max = int(policy.get("planning.canary_max_assets", 2))
    canary_max_tier = int(policy.get("planning.canary_max_tier", 2))
    wave_max = int(policy.get("planning.max_assets_per_wave", 12))
    per_cluster = int(policy.get("planning.max_parallel_per_cluster", 5))
    cap = {c: max(1, min(per_cluster, topo.cluster_capacity(c)["max_hosts_down"])) for c in topo.clusters}
    single = {s["server"]: s["up_links"] for s in topo.single_homed()}

    servers = sorted(target_servers, key=lambda s: (risk.get(s, 0), s))
    remaining = list(servers)

    # 1. canary
    canary: list[str] = []
    for cluster in sorted({topo.servers[s]["cluster"] for s in servers}):
        if len(canary) >= canary_max:
            break
        for s in remaining:
            tier = topo.most_critical_tier(s)
            if topo.servers[s]["cluster"] == cluster and s not in single and (tier is None or tier >= canary_max_tier):
                canary.append(s)
                remaining.remove(s)
                break
    for s in list(remaining):  # fewer clusters than canary slots: fill from any cluster
        if len(canary) >= canary_max:
            break
        tier = topo.most_critical_tier(s)
        if s not in single and (tier is None or tier >= canary_max_tier):
            canary.append(s)
            remaining.remove(s)
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


def plan_facts(topo: Topology, targets: dict, policy: Policy) -> dict:
    per_cluster = int(policy.get("planning.max_parallel_per_cluster", 5))
    limits = {c: min(per_cluster, topo.cluster_capacity(c)["max_hosts_down"]) for c in topo.clusters}
    tgt_sw = set(targets["switches"])
    return {
        "redundant_target_pairs": [p for p in topo.redundant_pairs() if p[0] in tgt_sw and p[1] in tgt_sw],
        "single_homed": topo.single_homed(),
        "single_homed_on_targets": [s for s in topo.single_homed() if set(s["up_links"]) & tgt_sw],
        "cluster_limits": limits,
        "per_cluster_limit": min(limits.values()) if limits else per_cluster,
    }


def grounded_rationale(waves: list[dict], facts: dict, components: list[str], duration_min: int) -> str:
    s = []
    if waves:
        s.append(f"Wave 1 is a canary of {' and '.join(waves[0]['assets'])} with no tier-0 or tier-1 workloads.")
    for a, b, _t in facts["redundant_target_pairs"]:
        s.append(f"{a} and {b} are upgraded in different waves.")
    for sh in facts["single_homed_on_targets"]:
        if sh["up_links"]:
            s.append(f"{sh['server']} is single-homed and is scheduled in the same wave as {sh['up_links'][0]}.")
    s.append(f"No wave has more than {facts['per_cluster_limit']} hosts of one cluster in maintenance.")
    s.append("No wave causes a workload outage.")
    if "iLO 6" in components and "System ROM" in components:
        s.append("Update iLO 6 before System ROM.")
    s.append(f"The plan takes about {duration_min} minutes and fits the window.")
    return " ".join(s)
