"""Intake agent: natural-language change intent -> validated change request."""

from __future__ import annotations

import json

from ..llm import load_prompt
from ..models import ChangeRequest


class IntakeAgent:
    name = "intake"

    def __init__(self, sv):
        self.sv = sv

    def inventory(self) -> tuple[dict, list[str]]:
        bus = self.sv.bus
        servers, e1 = bus.call(self.name, "compute.list_servers")
        switches, e2 = bus.call(self.name, "network.list_switches")
        clusters, e3 = bus.call(self.name, "virt.list_clusters")
        racks: dict[str, set[str]] = {}
        for s in servers:
            racks.setdefault(s["cluster"], set()).add(s["rack"])
        tor_pairs = {
            c: sorted(sw["name"] for sw in switches if sw["role"] == "tor" and sw["rack"] in rs)
            for c, rs in racks.items()
        }
        inv = {
            "clusters": [c["name"] for c in clusters],
            "cluster_hosts": {c["name"]: c["hosts"] for c in clusters},
            "servers": [s["name"] for s in servers],
            "switches": [s["name"] for s in switches],
            "cluster_tor_pairs": tor_pairs,
        }
        return inv, [e1, e2, e3]

    def run(self, intent: str) -> dict:
        inv, evidence = self.inventory()
        user = json.dumps({"intent": intent, "inventory": {k: inv[k] for k in ("clusters", "servers", "switches", "cluster_tor_pairs")}})
        cr: ChangeRequest = self.sv.llm.complete_json(
            "intake", load_prompt("intake"), user, ChangeRequest, context={"intent": intent, "inventory": inv}, temperature=0.0)

        # Never trust names from the model: keep only inventory assets.
        notes = list(cr.notes)
        for field, known in (("target_clusters", inv["clusters"]), ("target_servers", inv["servers"]), ("target_switches", inv["switches"])):
            vals = getattr(cr, field)
            bad = [v for v in vals if v not in known]
            if bad:
                notes.append(f"Dropped unknown {field.replace('target_', '')}: {bad}")
                setattr(cr, field, [v for v in vals if v in known])
        if cr.target_switches and "Switch OS" not in cr.components:
            cr.components.append("Switch OS")
        cr.notes = notes

        servers = list(cr.target_servers)
        for c in cr.target_clusters:
            servers += [h for h in inv["cluster_hosts"][c] if h not in servers]
        return {
            "change_request": cr.model_dump(),
            "targets": {"servers": sorted(servers), "switches": sorted(cr.target_switches)},
            "evidence": evidence,
            "llm": self.sv.llm.last(),
        }
