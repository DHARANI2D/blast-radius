"""Virtualization and storage tools, shaped after HPE Morpheus (clusters, VMs, datastores)."""

from __future__ import annotations

from . import ToolContext, ToolSpec


def tools(ctx: ToolContext) -> list[ToolSpec]:
    twin = ctx.twin

    def list_clusters() -> list[dict]:
        """VM clusters with member hosts, HA settings and the memory utilisation ceiling."""
        return list(twin.clusters.values())

    def list_vms(cluster: str = "", host: str = "") -> list[dict]:
        """VMs with host placement, service, tier, size and datastore."""
        return [
            dict(v) for v in twin.vms.values()
            if (not cluster or v["cluster"] == cluster) and (not host or v["host"] == host)
        ]

    def list_datastores() -> list[dict]:
        """Datastores and the storage array behind each one."""
        return list(twin.datastores.values())

    def list_storage_arrays() -> list[dict]:
        """Storage arrays and the switch ports their controllers attach to."""
        return list(twin.arrays.values())

    def enter_maintenance(host: str, run_id: str, approval_token: str) -> dict:
        """WRITE. Live-migrate every VM off the host and place it in maintenance mode."""
        ctx.require(approval_token, run_id, host, "virt.enter_maintenance")
        return twin.enter_maintenance(host)

    def exit_maintenance(host: str, run_id: str, approval_token: str) -> dict:
        """WRITE. Take the host out of maintenance mode."""
        ctx.require(approval_token, run_id, host, "virt.exit_maintenance")
        return twin.exit_maintenance(host)

    return [
        ToolSpec("virt", "list_clusters", list_clusters, description=list_clusters.__doc__),
        ToolSpec("virt", "list_vms", list_vms, description=list_vms.__doc__),
        ToolSpec("virt", "list_datastores", list_datastores, description=list_datastores.__doc__),
        ToolSpec("virt", "list_storage_arrays", list_storage_arrays, description=list_storage_arrays.__doc__),
        ToolSpec("virt", "enter_maintenance", enter_maintenance, write=True, description=enter_maintenance.__doc__),
        ToolSpec("virt", "exit_maintenance", exit_maintenance, write=True, description=exit_maintenance.__doc__),
    ]
