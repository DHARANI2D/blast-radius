"""Rollback agent: reverts a failed wave (or, with rollback_scope: asset, its regressed assets) to the versions captured before it ran."""

from __future__ import annotations

from ..topology import Topology


class RollbackAgent:
    name = "rollback"

    def __init__(self, sv):
        self.sv = sv

    def _write(self, run_id: str, tool: str, asset: str, **args):
        token = self.sv.authority.token(run_id, asset, tool)
        return self.sv.bus.call(self.name, tool, run_id=run_id, approval_token=token, **args)

    def run(self, run_id: str, wave_exec: dict, topo: Topology) -> dict:
        bus = self.sv.bus
        actions = []
        t0 = bus.call(self.name, "telemetry.get_clock")[0]["t_min"]
        changes = list(reversed(wave_exec["firmware_changes"]))
        if self.sv.policy.get("execution.rollback_scope", "wave") == "asset":
            # Only the assets whose golden signals regressed; the rest of the wave keeps its upgrade.
            bad = {r["asset"] for r in wave_exec.get("regressions", [])}
            changes = [c for c in changes if c["asset"] in bad] or changes
        servers = sorted({c["asset"] for c in changes if c["asset"] in topo.servers})
        switches = sorted({c["asset"] for c in changes if c["asset"] in topo.switches})
        for h in servers:
            res, ev = self._write(run_id, "virt.enter_maintenance", h, host=h)
            actions.append({"tool": "virt.enter_maintenance", "asset": h, "evidence": ev})
        for c in changes:
            if c["asset"] in topo.servers:
                res, ev = self._write(run_id, "compute.apply_firmware", c["asset"], server=c["asset"], component=c["component"], version=c["from"])
            else:
                res, ev = self._write(run_id, "network.upgrade_switch_os", c["asset"], switch=c["asset"], version=c["from"], hold_down=False)
            actions.append({"tool": "revert", "asset": c["asset"], "component": c["component"], "to": c["from"], "evidence": ev})
        for h in servers:
            res, ev = self._write(run_id, "virt.exit_maintenance", h, host=h)
            actions.append({"tool": "virt.exit_maintenance", "asset": h, "evidence": ev})
        soak = int(self.sv.policy.get("execution.durations_min.soak", 10))
        bus.call(self.name, "telemetry.advance_clock", minutes=soak)
        after, after_ev = bus.call(self.name, "telemetry.get_golden_signals", assets=servers + switches)
        span = bus.call(self.name, "telemetry.get_clock")[0]["t_min"] - t0
        series = {s: bus.call(self.name, "telemetry.get_metric_series", asset=s, metric="nic_latency_ms", minutes=span)[0]
                  for s in servers}
        return {"actions": actions, "reverted": [{"asset": c["asset"], "component": c["component"], "to": c["from"]} for c in changes],
                "after": after, "evidence": after_ev, "series": series}
