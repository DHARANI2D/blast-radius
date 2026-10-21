"""Risk & Advisory agent.

Scores every target asset from tool evidence: release notes, advisories and
incidents for the target version (RAG over the knowledge MCP), workload
criticality, redundancy, change history, and the asset's propagated exposure:
the simulated impact on downstream VMs and services if it failed to come back.
That last term is how a single-homed host makes its *switch* risky.
"""

from __future__ import annotations

from ..constraints import impact_kwargs
from ..topology import Topology

TIER_POINTS = {0: 20, 1: 12, 2: 5, 3: 0}
KI_POINTS = {"low": 3, "medium": 8, "high": 20, "critical": 30}
INCIDENT_POINTS = {"sev1": 15, "sev2": 10, "high": 45, "critical": 60}


def _prefix_match(firmware: dict, prefixes: dict) -> bool:
    return all(firmware.get(c, "").startswith(p) for c, p in prefixes.items())


class RiskAgent:
    name = "risk"

    def __init__(self, sv):
        self.sv = sv
        self._cache: dict = {}

    def _kb(self, tool: str, **args):
        key = (tool, tuple(sorted(args.items())))
        if key not in self._cache:
            self._cache[key] = self.sv.bus.call(self.name, tool, **args)
        return self._cache[key]

    def target_versions(self, targets: dict, components: list[str], topo: Topology) -> tuple[dict, list[str]]:
        bus = self.sv.bus
        base, e1 = bus.call(self.name, "compute.get_firmware_baseline", name="latest")
        nets, e2 = bus.call(self.name, "network.list_network_baselines")
        net = next((b for b in nets if b.get("latest")), nets[0])
        out = {}
        for s in targets["servers"]:
            model = topo.servers[s]["model"]
            comps = base["components"].get(model, {})
            out[s] = {c: comps[c] for c in components if c in comps and c != "Switch OS"}
        for sw in targets["switches"]:
            model = topo.switches[sw]["model"]
            ver = net["components"].get(model, {}).get("Switch OS")
            if ver and "Switch OS" in components:
                out[sw] = {"Switch OS": ver}
        return out, [e1, e2]

    def run(self, targets: dict, components: list[str], topo: Topology) -> dict:
        self._cache.clear()  # knowledge changes between runs (learned incidents)
        policy = self.sv.policy
        defer = bool(policy.get("planning.defer_known_regressions", True))
        tv, base_ev = self.target_versions(targets, components, topo)
        risks: dict[str, dict] = {}
        for asset in targets["servers"] + targets["switches"]:
            if asset in topo.servers:
                risks[asset] = self._server(asset, tv.get(asset, {}), topo)
            else:
                risks[asset] = self._switch(asset, tv.get(asset, {}), topo)
            r = risks[asset]
            r["score"] = min(100, r["score"])
            r["blocked"] = bool(r.pop("regression_match", False)) and defer
            r["evidence"] = sorted(set(r["evidence"] + base_ev))

        deferred = [{"asset": a, "reason": next((x for x in r["reasons"] if "regression" in x.lower()), "known regression")}
                    for a, r in risks.items() if r["blocked"]]
        services = self._service_exposure(risks, topo)
        return {"assets": risks, "target_versions": tv, "deferred": deferred, "services": services}

    # ----------------------------------------------------------- servers
    def _server(self, name: str, versions: dict, topo: Topology) -> dict:
        srv, ev = self.sv.bus.call(self.name, "compute.get_server", name=name)
        evidence = [ev]
        score, reasons, match = 0, [], False
        tier = topo.most_critical_tier(name)
        if tier is not None and TIER_POINTS.get(tier):
            crit = [v["name"] for v in topo.vms_on(name) if v["tier"] == tier][:3]
            score += TIER_POINTS[tier]
            reasons.append(f"hosts tier-{tier} workloads ({', '.join(crit)})")
        single = next((s for s in topo.single_homed() if s["server"] == name), None)
        if single:
            score += 20
            reasons.append(f"single-homed: only uplink {', '.join(single['up_links']) or 'none'}"
                           + (f"; {single['dead_ports'][0]} {single['note']}" if single["dead_ports"] else ""))
        if any(h.get("result") == "rolled_back" for h in srv.get("changeHistory", [])):
            score += 10
            reasons.append("a previous firmware change on this host was rolled back")
        if srv["state"]["health"] != "OK":
            score += 15
            reasons.append(f"current health {srv['state']['health']}")
        for comp, ver in versions.items():
            s, r, e, m = self._version_risk(comp, ver, srv["model"], srv["firmware"])
            score, reasons, evidence, match = score + s, reasons + r, evidence + e, match or m
        return {"asset": name, "kind": "server", "score": score, "reasons": reasons, "evidence": evidence,
                "exposure_brs": 0.0, "regression_match": match, "current": srv["firmware"], "target": versions}

    # ---------------------------------------------------------- switches
    def _switch(self, name: str, versions: dict, topo: Topology) -> dict:
        sw, ev = self.sv.bus.call(self.name, "network.get_switch", name=name)
        evidence = [ev]
        score, reasons, match = 0, [], False
        imp = topo.simulate([name], [], **impact_kwargs(self.sv.policy))
        sim_ev = self.sv.evidence.add(self.name, "blastradius.simulate", {"down_switches": [name]},
                                      {k: imp[k] for k in ("impacted_vms", "critical_vms", "isolated_servers", "brs")})
        evidence.append(sim_ev)
        if imp["impacted_vms"]:
            score += min(40, 10 + int(imp["brs"] / 2))
            reasons.append(f"if {name} goes down alone, {', '.join(imp['isolated_servers'])} lose every uplink "
                           f"({len(imp['impacted_vms'])} VMs incl. {', '.join(imp['critical_vms'][:2]) or 'none critical'})")
        deps = topo.servers_depending_on(name)
        if deps:
            reasons.append(f"{len(deps)} hosts attached")
        arrays = sorted(a for a, arr in topo.arrays.items() if any(p["switch"] == name for p in arr["ports"]))
        if arrays:
            score += 10
            reasons.append(f"carries storage ports of {', '.join(arrays)}: every cluster using that array depends on this switch pair")
        cur = sw["firmware"]
        for comp, ver in versions.items():
            s, r, e, m = self._version_risk(comp, ver, sw["model"], {"Switch OS": cur}, current=cur)
            score, reasons, evidence, match = score + s, reasons + r, evidence + e, match or m
        return {"asset": name, "kind": "switch", "score": score, "reasons": reasons, "evidence": evidence,
                "exposure_brs": imp["brs"], "regression_match": match, "current": {"Switch OS": cur}, "target": versions}

    # ------------------------------------------------------------ shared
    def _version_risk(self, comp: str, ver: str, model: str, firmware: dict, current: str | None = None):
        score, reasons, evidence, match = 0, [], [], False
        rn, e = self._kb("knowledge.get_release_notes", component=comp, version=ver)
        evidence.append(e)
        if rn.get("found") is False:
            score += 10
            reasons.append(f"no release notes found for {comp} {ver}")
        for ki in rn.get("known_issues", []):
            score += KI_POINTS.get(ki.get("severity", "medium"), 8)
            reasons.append(f"{comp} {ver} known issue {ki['id']}: {ki['summary']}")
        advs, e = self._kb("knowledge.list_advisories", component=comp, version=ver)
        evidence.append(e)
        for a in advs:
            fixed = a.get("fixed_in", {})
            reasons.append(f"{a['id']} ({', '.join(a['cves'])}) still applies after the upgrade; fixed in {fixed.get('component')} {fixed.get('version')}")
        versions = {ver} | ({current} if current else set())
        for v in sorted(versions):
            incs, e = self._kb("knowledge.list_incidents", component=comp, version=v, model=model)
            evidence.append(e)
            for inc in incs:
                cond = inc.get("conditions") or {}
                if cond.get("firmware_prefix") and not _prefix_match(firmware, cond["firmware_prefix"]):
                    continue
                pts = INCIDENT_POINTS.get(inc.get("severity", "sev2"), 10)
                score += pts
                if inc.get("kind") == "regression" and v == ver:
                    match = True
                    reasons.append(f"known regression {inc['id']}: {inc['symptom']}")
                else:
                    reasons.append(f"past incident {inc['id']}: {inc['lesson']}")
        return score, reasons, evidence, match

    def _service_exposure(self, risks: dict, topo: Topology) -> dict:
        out: dict[str, dict] = {}
        for asset, r in risks.items():
            hosts = [asset] if asset in topo.servers else topo.servers_depending_on(asset)
            for h in hosts:
                for v in topo.vms_on(h):
                    s = out.setdefault(v["service"], {"service": v["service"], "tier": v["tier"], "max_asset_risk": 0, "assets": set()})
                    s["tier"] = min(s["tier"], v["tier"])
                    s["max_asset_risk"] = max(s["max_asset_risk"], r["score"])
                    s["assets"].add(asset)
        return {k: {**v, "assets": sorted(v["assets"])[:6]} for k, v in sorted(out.items(), key=lambda kv: (kv[1]["tier"], -kv[1]["max_asset_risk"]))}
