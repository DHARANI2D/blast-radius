"""Compute tools, shaped after HPE Compute Ops Management (servers, firmware baselines)."""

from __future__ import annotations

from . import ToolContext, ToolSpec


def tools(ctx: ToolContext) -> list[ToolSpec]:
    twin = ctx.twin

    def list_servers(cluster: str = "") -> list[dict]:
        """List servers with model, rack, cluster, health and installed firmware."""
        out = []
        for s in twin.servers.values():
            if cluster and s["cluster"] != cluster:
                continue
            srv = twin.get_server(s["name"])
            out.append({k: srv[k] for k in ("name", "serialNumber", "model", "rack", "cluster", "memoryGB", "state", "firmware")})
        return out

    def get_server(name: str) -> dict:
        """Full server record, including NICs and change history."""
        return twin.get_server(name)

    def list_firmware_baselines() -> list[dict]:
        """Firmware baselines (SPP bundles) available to apply."""
        return twin.compute_baselines

    def get_firmware_baseline(name: str = "latest") -> dict:
        """One baseline by name; 'latest' returns the newest released baseline."""
        for b in twin.compute_baselines:
            if (name == "latest" and b.get("latest")) or b["name"] == name:
                return b
        raise ValueError(f"no baseline {name!r}")

    def apply_firmware(server: str, component: str, version: str, run_id: str, approval_token: str) -> dict:
        """WRITE. Flash one firmware component. Requires an approval token for this run, server and version."""
        ctx.require(approval_token, run_id, server, "compute.apply_firmware", version)
        return twin.apply_firmware(server, component, version)

    return [
        ToolSpec("compute", "list_servers", list_servers, description=list_servers.__doc__),
        ToolSpec("compute", "get_server", get_server, description=get_server.__doc__),
        ToolSpec("compute", "list_firmware_baselines", list_firmware_baselines, description=list_firmware_baselines.__doc__),
        ToolSpec("compute", "get_firmware_baseline", get_firmware_baseline, description=get_firmware_baseline.__doc__),
        ToolSpec("compute", "apply_firmware", apply_firmware, write=True, description=apply_firmware.__doc__),
    ]
