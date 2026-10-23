"""Cross-domain dependency graph and failure simulation.

The graph joins compute (servers), network (switch ports, LLDP, redundancy
pairs), virtualization (clusters, VMs, datastores) and storage (array ports).
``simulate`` answers the planning question: "if these switches reboot and these
hosts are in maintenance at the same time, which workloads lose service?"
"""

from __future__ import annotations

import math
from collections import defaultdict

import networkx as nx


class Topology:
    def __init__(self, servers: list[dict], switches: list[dict], lldp: list[dict], clusters: list[dict],
                 vms: list[dict], datastores: list[dict], arrays: list[dict]):
        self.servers = {s["name"]: s for s in servers}
        self.switches = {s["name"]: s for s in switches}
        self.clusters = {c["name"]: c for c in clusters}
        self.vms = {v["name"]: v for v in vms}
        self.datastores = {d["name"]: d for d in datastores}
        self.arrays = {a["name"]: a for a in arrays}
        self.lldp = lldp
        self.g = nx.MultiGraph()
        self._build()

    # ----------------------------------------------------------------- build
    def _build(self) -> None:
        g = self.g
        for n, s in self.servers.items():
            g.add_node(n, kind="server", model=s["model"], cluster=s["cluster"], rack=s["rack"], memoryGB=s["memoryGB"])
        for n, s in self.switches.items():
            g.add_node(n, kind="switch", role=s["role"], model=s["model"], rack=s["rack"])
        for n, a in self.arrays.items():
            g.add_node(n, kind="array", model=a["model"])
        for n, c in self.clusters.items():
            g.add_node(n, kind="cluster")
            for h in c["hosts"]:
                g.add_edge(h, n, kind="member")
        for n, d in self.datastores.items():
            g.add_node(n, kind="datastore")
            g.add_edge(n, d["array"], kind="backed_by")
        for n, v in self.vms.items():
            g.add_node(n, kind="vm", tier=v["tier"], service=v["service"], memoryGB=v["memoryGB"])
            g.add_edge(n, v["host"], kind="runs_on")
            g.add_edge(n, v["datastore"], kind="uses")
            svc = "svc:" + v["service"]
            if svc not in g:
                g.add_node(svc, kind="service")
            g.add_edge(n, svc, kind="part_of")
        for n, s in self.switches.items():
            red = s.get("redundancy") or {}
            if red.get("peer"):
                g.add_edge(n, red["peer"], kind="peer", type=red.get("type"))
        seen = set()
        for p in self.lldp:
            nb = p.get("neighbor")
            if p["status"] == "up" and nb:
                key = tuple(sorted((p["switch"], nb))) + (p["port"],)
                if key in seen:
                    continue
                seen.add(key)
                if nb in g:
                    g.add_edge(p["switch"], nb, kind="link", port=p["port"], status="up")
        # Down ports have no LLDP neighbour; record them on the server they used
        # to serve so the UI can show the dead link.
        self.down_ports = [p for p in self.lldp if p["status"] != "up"]

    # ----------------------------------------------------------------- facts
    def links_of(self, server: str) -> list[str]:
        return sorted({v for _, v, d in self.g.edges(server, data=True) if d["kind"] == "link"})

    def single_homed(self) -> list[dict]:
        out = []
        for s in self.servers:
            ups = self.links_of(s)
            if len(ups) < 2:
                # A dead port has no LLDP neighbour; its interface description
                # still names the host it used to serve.
                dead = [p for p in self.down_ports if (p.get("description") or "").split(" ")[0] == s]
                out.append({"server": s, "up_links": ups, "dead_ports": [f"{p['switch']} {p['port']}" for p in dead],
                            "note": dead[0].get("note") if dead else None})
        return out

    def redundant_pairs(self) -> list[tuple[str, str, str]]:
        out = []
        for a, b, d in self.g.edges(data=True):
            if d["kind"] == "peer":
                out.append(tuple(sorted((a, b))) + (d.get("type") or "",))
        return sorted(set(out))

    def peer_of(self, switch: str) -> str | None:
        red = (self.switches.get(switch) or {}).get("redundancy") or {}
        return red.get("peer")

    def vms_on(self, host: str) -> list[dict]:
        return [v for v in self.vms.values() if v["host"] == host]

    def most_critical_tier(self, host: str) -> int | None:
        tiers = [v["tier"] for v in self.vms_on(host)]
        return min(tiers) if tiers else None  # tier 0 is most critical

    def servers_depending_on(self, switch: str) -> list[str]:
        return sorted(v for _, v, d in self.g.edges(switch, data=True) if d["kind"] == "link" and v in self.servers)

    def cluster_capacity(self, cluster: str) -> dict:
        c = self.clusters[cluster]
        hosts = c["hosts"]
        mem = {h: self.servers[h]["memoryGB"] for h in hosts}
        demand = sum(v["memoryGB"] for v in self.vms.values() if v["cluster"] == cluster)
        limit = c.get("maxMemoryUtilPct", 85) / 100.0
        per_host = sum(mem.values()) / len(hosts)
        max_down = 0
        for k in range(len(hosts)):
            if demand <= limit * per_host * (len(hosts) - k):
                max_down = k
        return {"cluster": cluster, "hosts": len(hosts), "capacity_gb": sum(mem.values()), "demand_gb": demand,
                "util_pct": round(100 * demand / sum(mem.values()), 1), "max_util_pct": round(limit * 100),
                "max_hosts_down": max_down}

    # -------------------------------------------------------------- simulate
    def simulate(self, down_switches: set[str] | list[str] = (), maintenance_hosts: set[str] | list[str] = (),
                 tier_weights: dict | None = None, migrated_weight: float = 0.05, brs_scale: float = 30.0) -> dict:
        down_switches = set(down_switches)
        maint = set(maintenance_hosts)
        tw = {int(k): float(v) for k, v in (tier_weights or {0: 10, 1: 4, 2: 2, 3: 1}).items()}

        phys = nx.Graph()
        for n, d in self.g.nodes(data=True):
            if d["kind"] in ("server", "switch", "array") and n not in down_switches:
                phys.add_node(n)
        for a, b, d in self.g.edges(data=True):
            if d["kind"] == "link" and a in phys and b in phys:
                phys.add_edge(a, b)
        cores = [n for n, s in self.switches.items() if s["role"] == "spine" and n not in down_switches]
        reachable: set[str] = set()
        for c in cores:
            if c not in reachable:
                reachable |= nx.node_connected_component(phys, c)
        arrays_ok = {a for a in self.arrays if a in reachable}

        net_ok = {h: (h in reachable) for h in self.servers}
        ds_ok = {d: (self.datastores[d]["array"] in arrays_ok) for d in self.datastores}

        impacted: dict[str, str] = {}
        migrated: list[str] = []
        isolated = sorted(h for h in self.servers if h not in maint and not net_ok[h])
        for v in self.vms.values():
            h = v["host"]
            if h in maint:
                continue
            if not net_ok[h]:
                impacted[v["name"]] = f"host {h} loses all network paths"
            elif not ds_ok[v["datastore"]]:
                impacted[v["name"]] = f"datastore {v['datastore']} unreachable ({self.datastores[v['datastore']]['array']} cut off)"

        # Evacuation is simulated VM by VM, the way a placement engine does it: hosts are
        # emptied in wave order, largest VMs first, each onto the least-utilised healthy host
        # that stays under the cluster's memory ceiling. Aggregate free memory is not enough:
        # a 256 GB VM needs 256 GB free on one host.
        seq = maintenance_hosts if isinstance(maintenance_hosts, (list, tuple)) else sorted(maintenance_hosts)
        order = list(dict.fromkeys(h for h in seq if h in self.servers))
        used: dict[str, float] = defaultdict(float)
        for v in self.vms.values():
            used[v["host"]] += v["memoryGB"]
        capacity_shortfall = {}
        for cname, c in self.clusters.items():
            hosts_maint = [h for h in order if h in c["hosts"]]
            if not hosts_maint:
                continue
            healthy = [h for h in c["hosts"] if h not in maint and net_ok[h]]
            limit = c.get("maxMemoryUtilPct", 85) / 100.0
            short = 0
            for h in hosts_maint:
                for v in sorted(self.vms_on(h), key=lambda x: (-x["memoryGB"], x["name"])):
                    fits = [d for d in healthy if used[d] + v["memoryGB"] <= limit * self.servers[d]["memoryGB"]]
                    if not fits:
                        short += v["memoryGB"]
                        impacted[v["name"]] = (f"{cname} has no host with {v['memoryGB']} GB free under its "
                                               f"{round(limit * 100)}% ceiling to take {v['name']} from {h}")
                        continue
                    d = min(fits, key=lambda x: (used[x] / self.servers[x]["memoryGB"], x))
                    used[d] += v["memoryGB"]
                    used[h] -= v["memoryGB"]
                    if ds_ok[v["datastore"]]:
                        migrated.append(v["name"])
                    else:
                        impacted[v["name"]] = f"datastore {v['datastore']} unreachable"
            if short:
                capacity_shortfall[cname] = round(short)

        services: dict[str, dict] = defaultdict(lambda: {"impacted": 0, "total": 0, "tier": 3})
        for v in self.vms.values():
            s = services[v["service"]]
            s["total"] += 1
            s["tier"] = min(s["tier"], v["tier"])
            if v["name"] in impacted:
                s["impacted"] += 1
        svc_impact = {k: {**s, "state": ("down" if s["impacted"] == s["total"] else "degraded")}
                      for k, s in services.items() if s["impacted"]}

        weight = sum(tw.get(self.vms[n]["tier"], 1) for n in impacted)
        weight += migrated_weight * sum(tw.get(self.vms[n]["tier"], 1) for n in migrated)
        brs = 100 * (1 - math.exp(-weight / brs_scale))
        storage_lost = sorted(h for h in self.servers if net_ok[h] and h not in maint and
                              any(not ds_ok[v["datastore"]] for v in self.vms_on(h)))
        critical = sorted(n for n in impacted if self.vms[n]["tier"] == 0)
        return {
            "down_switches": sorted(down_switches),
            "maintenance_hosts": sorted(maint),
            "impacted_vms": sorted(impacted),
            "impact_reasons": impacted,
            "critical_vms": critical,
            "migrated_vms": len(migrated),
            "isolated_servers": isolated,
            "storage_lost_servers": storage_lost,
            "arrays_unreachable": sorted(set(self.arrays) - arrays_ok),
            "capacity_shortfall_gb": capacity_shortfall,
            "services": svc_impact,
            "brs": round(brs, 1),
        }

    # --------------------------------------------------------------- summary
    def summary(self) -> dict:
        kinds = defaultdict(int)
        for _, d in self.g.nodes(data=True):
            kinds[d["kind"]] += 1
        return {
            "nodes": self.g.number_of_nodes(),
            "edges": self.g.number_of_edges(),
            "by_kind": dict(kinds),
            "redundant_pairs": [list(p) for p in self.redundant_pairs()],
            "single_homed": self.single_homed(),
            "clusters": [self.cluster_capacity(c) for c in self.clusters],
            "storage_paths": {a: [p["switch"] for p in arr["ports"]] for a, arr in self.arrays.items()},
        }
