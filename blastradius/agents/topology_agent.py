"""Topology agent: builds the live cross-domain dependency graph from MCP tools."""

from __future__ import annotations

from ..greenlake import enrich_from_greenlake
from ..topology import Topology


class TopologyAgent:
    name = "topology"

    def __init__(self, sv):
        self.sv = sv

    def run(self) -> tuple[Topology, dict]:
        bus = self.sv.bus
        calls = {
            "servers": ("compute.list_servers", {}),
            "switches": ("network.list_switches", {}),
            "lldp": ("network.get_lldp_neighbors", {}),
            "clusters": ("virt.list_clusters", {}),
            "vms": ("virt.list_vms", {}),
            "datastores": ("virt.list_datastores", {}),
            "arrays": ("virt.list_storage_arrays", {}),
        }
        data, evidence = {}, {}
        for key, (tool, args) in calls.items():
            data[key], evidence[key] = bus.call(self.name, tool, **args)
        topo = Topology(**data)
        summary = topo.summary()
        summary["evidence"] = evidence
        summary["greenlake"] = enrich_from_greenlake(self.sv.settings, data["servers"])
        return topo, summary
