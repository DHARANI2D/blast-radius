"""Rollback agent: reverts a failed wave to the versions captured before it ran."""

from __future__ import annotations

from ..topology import Topology


def manual_steps(changes: list[dict], in_maintenance: list[str], rebooting: list[str] = ()) -> list[str]:
    """The clean-up a person must do when writes are blocked: the rollback the agent could not run."""
    steps = [f"{s}: confirm the switch finished rebooting before touching its hosts" for s in rebooting]
    for c in reversed(changes):
        how = "" if c["asset"] in in_maintenance or c["component"] == "Switch OS" else " (enter maintenance first)"
        steps.append(f"{c['asset']}: revert {c['component']} {c['to']} -> {c['from']}, the version captured before the wave{how}")
    steps += [f"{h}: exit maintenance once its firmware is confirmed" for h in in_maintenance]
    return steps


class RollbackAgent:
    name = "rollback"

    def __init__(self, sv):
        self.sv = sv

    def _write(self, run_id: str, tool: str, asset: str, **args):
        token = self.sv.authority.token(run_id, asset, tool, args.get("version", ""))
        return self.sv.bus.call(self.name, tool, run_id=run_id, approval_token=token, **args)

    @staticmethod
    def hosts(wave_exec: dict, topo: Topology) -> list[str]:
        """Hosts the rollback puts in maintenance: the reverted servers, any the wave left there, and when a switch
        reverts (a reboot), every host the forward wave evacuated and its own hosts, as the plan required."""
        changed = {c["asset"] for c in wave_exec["firmware_changes"]}
        hosts = {a for a in changed if a in topo.servers} | set(wave_exec.get("in_maintenance", []))
        if any(a in topo.switches for a in changed):
            hosts |= {a for a in wave_exec["assets"] + wave_exec.get("evacuate", []) if a in topo.servers}
        return sorted(hosts)

    def run(self, run_id: str, wave_exec: dict, topo: Topology) -> dict:
        bus = self.sv.bus
        actions = []
        t0 = bus.call(self.name, "telemetry.get_clock")[0]["t_min"]
        changes = list(reversed(wave_exec["firmware_changes"]))
        servers = self.hosts(wave_exec, topo)
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
