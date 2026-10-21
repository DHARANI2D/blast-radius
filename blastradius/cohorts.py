"""Configuration cohorts and cohort-coverage canary selection.

A canary only tests the configurations it contains. If every host it picks
shares one hardware/firmware configuration, a regression that only appears on
another configuration rides straight into the fleet waves. Picking the canary
by *risk* makes this worse: the lowest-risk hosts are usually dev/CI boxes,
which are also the hosts that got firmware first and least resemble production.

So BlastRadius groups the target servers into *configuration cohorts*: hosts
that share a model and the major version of every firmware component the
change does *not* touch (for example NIC firmware 229.x vs 230.x). Those are the
attributes that interact with the new firmware and that the change will not
make uniform. The canary must contain one eligible host from each cohort (up to
the canary budget, largest cohorts first). Cohorts that share a model but differ
in one attribute also act as controls for each other, which is what lets the
Reporter pin a canary regression on the attribute that actually matters.
"""

from __future__ import annotations

from collections import Counter

from .policy import Policy
from .topology import Topology


def major(version: str) -> str:
    """'229.1.123.0' -> '229.', 'U54 v2.16' -> 'U54 v2.'"""
    v = str(version)
    return v.split(".")[0] + "." if "." in v else v


def short_model(model: str) -> str:
    return model.replace("HPE ProLiant ", "")


def fingerprint(server: dict, changed: list[str]) -> tuple:
    attrs = tuple(sorted((c, major(v)) for c, v in server.get("firmware", {}).items() if c not in changed))
    return (server["model"], attrs)


def label(fp: tuple) -> str:
    model, attrs = fp
    return " · ".join([short_model(model)] + [f"{c} {p}x" for c, p in attrs])


def build(servers: list[str], server_info: dict[str, dict], changed: list[str]) -> list[dict]:
    """Group ``servers`` into cohorts, largest first. ``server_info`` maps name -> server record."""
    groups: dict[tuple, list[str]] = {}
    for s in servers:
        if s in server_info:
            groups.setdefault(fingerprint(server_info[s], changed), []).append(s)
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), label(kv[0])))
    return [{"id": f"K{i}", "label": label(fp), "model": fp[0], "attrs": dict(fp[1]), "hosts": sorted(hosts)}
            for i, (fp, hosts) in enumerate(ordered, 1)]


def eligible(host: str, topo: Topology, policy: Policy, single: set[str] | None = None) -> bool:
    """A host may be a canary if it is dual-homed and runs no tier-0/1 workloads."""
    single = {s["server"] for s in topo.single_homed()} if single is None else single
    tier = topo.most_critical_tier(host)
    return host not in single and (tier is None or tier >= int(policy.get("planning.canary_max_tier", 2)))


def required(cohorts: list[dict], topo: Topology, policy: Policy) -> list[dict]:
    """Cohorts the canary must cover: the largest ones that have an eligible host, up to the canary budget."""
    budget = int(policy.get("planning.canary_max_assets", 3))
    single = {s["server"] for s in topo.single_homed()}
    out = [c for c in cohorts if any(eligible(h, topo, policy, single) for h in c["hosts"])]
    return out[:budget]


def coverage(canary: list[str], cohorts: list[dict], topo: Topology, policy: Policy) -> dict:
    canary = set(canary)
    req = required(cohorts, topo, policy)
    covered = [c for c in cohorts if canary & set(c["hosts"])]
    missing = [c for c in req if not canary & set(c["hosts"])]
    total = sum(len(c["hosts"]) for c in cohorts)
    return {
        "cohorts": [{k: c[k] for k in ("id", "label")} | {"size": len(c["hosts"]),
                                                          "canary": sorted(canary & set(c["hosts"]))} for c in cohorts],
        "covered": len(covered),
        "total": len(cohorts),
        "required": len(req),
        "missing": [{"id": c["id"], "label": c["label"], "size": len(c["hosts"])} for c in missing],
        "hosts_represented": sum(len(c["hosts"]) for c in covered),
        "hosts_total": total,
        "ok": not missing,
    }


def select_canary(servers: list[str], topo: Topology, risk: dict[str, float], policy: Policy,
                  changed: list[str]) -> list[str]:
    """One lowest-risk eligible host per required cohort, spreading across clusters where there is a choice."""
    cohorts = build(servers, topo.servers, changed)
    single = {s["server"] for s in topo.single_homed()}
    picked: list[str] = []
    for c in required(cohorts, topo, policy):
        cands = [h for h in c["hosts"] if eligible(h, topo, policy, single)]
        used = Counter(topo.servers[h]["cluster"] for h in picked)
        cands.sort(key=lambda h: (used[topo.servers[h]["cluster"]], risk.get(h, 0), h))
        picked.append(cands[0])
    return picked


def risk_ranked_canary(servers: list[str], topo: Topology, risk: dict[str, float], policy: Policy) -> list[str]:
    """The conventional rule (lowest-risk eligible host per cluster, then fill), kept as the counterfactual baseline."""
    budget = int(policy.get("planning.canary_max_assets", 3))
    single = {s["server"] for s in topo.single_homed()}
    pool = sorted((s for s in servers if s in topo.servers and eligible(s, topo, policy, single)), key=lambda s: (risk.get(s, 0), s))
    picked: list[str] = []
    for cluster in sorted({topo.servers[s]["cluster"] for s in pool}):
        h = next((s for s in pool if topo.servers[s]["cluster"] == cluster and s not in picked), None)
        if h and len(picked) < budget:
            picked.append(h)
    for s in pool:
        if len(picked) >= budget:
            break
        if s not in picked:
            picked.append(s)
    return picked
