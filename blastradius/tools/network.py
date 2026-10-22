"""Network tools, shaped after Aruba Central / Mist (switches, ports, LLDP)."""

from __future__ import annotations

from . import ToolContext, ToolSpec


def tools(ctx: ToolContext) -> list[ToolSpec]:
    twin = ctx.twin

    def list_switches() -> list[dict]:
        """List switches with model, OS version, role, rack and redundancy peer."""
        return [twin.get_switch(n) for n in twin.switches]

    def get_switch(name: str) -> dict:
        """One switch record."""
        return twin.get_switch(name)

    def get_lldp_neighbors(switch: str = "") -> list[dict]:
        """Port status and LLDP neighbour for every port (optionally one switch)."""
        out = []
        for p in twin.ports_of(switch or None):
            lldp = p.get("lldp") or {}
            row = {
                "switch": p["switch"],
                "port": p["port"],
                "description": p.get("description", ""),
                "status": p["status"],
                "speed": p["speed"],
                "vlans": p["vlans"],
                "neighbor": lldp.get("neighbor"),
                "neighborPort": lldp.get("neighborPort"),
            }
            if p.get("note"):
                row["note"] = p["note"]
            out.append(row)
        return out

    def list_network_baselines() -> list[dict]:
        """Switch OS baselines."""
        return twin.network_baselines

    def upgrade_switch_os(switch: str, version: str, run_id: str, approval_token: str, hold_down: bool = True) -> dict:
        """WRITE. Upgrade the switch OS and reboot. With hold_down the call returns while the switch is still rebooting."""
        ctx.require(approval_token, run_id, switch, "network.upgrade_switch_os", version)
        return twin.upgrade_switch_os(switch, version, hold_down=hold_down)

    def wait_upgrade_complete(switch: str) -> dict:
        """Block until a switch finishes rebooting and return its record."""
        twin.finish_switch_reboot(switch)
        return twin.get_switch(switch)

    return [
        ToolSpec("network", "list_switches", list_switches, description=list_switches.__doc__),
        ToolSpec("network", "get_switch", get_switch, description=get_switch.__doc__),
        ToolSpec("network", "get_lldp_neighbors", get_lldp_neighbors, description=get_lldp_neighbors.__doc__),
        ToolSpec("network", "list_network_baselines", list_network_baselines, description=list_network_baselines.__doc__),
        ToolSpec("network", "upgrade_switch_os", upgrade_switch_os, write=True, description=upgrade_switch_os.__doc__),
        ToolSpec("network", "wait_upgrade_complete", wait_upgrade_complete, description=wait_upgrade_complete.__doc__),
    ]
