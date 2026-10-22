"""Rollback agent: reverts a failed wave (or, with rollback_scope: asset, its regressed assets) to the versions captured before it ran."""

from __future__ import annotations

from ..mcp_layer import ToolCallError
from ..policy import PolicyViolation
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

    def _write(self, run_id: str, tool: str, asset: str, scope: set[str], **args):
        # Rollback writes pass the same PolicyGuard as forward ones: kill switch, allow-list, scope, rate limit.
        self.sv.guard.check(tool, asset, scope)
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
        self.sv.guard.new_wave()
        actions = []
        t0 = bus.call(self.name, "telemetry.get_clock")[0]["t_min"]
        changes = list(reversed(wave_exec["firmware_changes"]))
        if self.sv.policy.get("execution.rollback_scope", "wave") == "asset":
            # Only the assets whose golden signals regressed; the rest of the wave keeps its upgrade.
            bad = {r["asset"] for r in wave_exec.get("regressions", [])}
            changes = [c for c in changes if c["asset"] in bad] or changes
        servers = self.hosts({**wave_exec, "firmware_changes": changes}, topo)
        switches = sorted({c["asset"] for c in changes if c["asset"] in topo.switches})
        # Scope: maintenance only on the wave's own hosts, reverts only on what the wave changed.
        wave_scope, changed = set(wave_exec["assets"]) | set(wave_exec.get("evacuate", [])), {c["asset"] for c in changes}
        reverted: list[dict] = []
        held = set(wave_exec.get("in_maintenance", []))
        try:
            # A host already in maintenance before the change (a repair) is not ours to exit; one the halted wave left there is.
            ours = []
            for h in servers:
                res, ev = self._write(run_id, "virt.enter_maintenance", h, wave_scope, host=h)
                if not res.get("already") or h in held:
                    ours.append(h)
                    held.add(h)
                actions.append({"tool": "virt.enter_maintenance", "asset": h, "evidence": ev})
            for c in changes:
                if c["asset"] in topo.servers:
                    res, ev = self._write(run_id, "compute.apply_firmware", c["asset"], changed, server=c["asset"], component=c["component"], version=c["from"])
                else:
                    res, ev = self._write(run_id, "network.upgrade_switch_os", c["asset"], changed, switch=c["asset"], version=c["from"], hold_down=False)
                reverted.append(c)
                actions.append({"tool": "revert", "asset": c["asset"], "component": c["component"], "to": c["from"], "evidence": ev})
            for h in ours:
                res, ev = self._write(run_id, "virt.exit_maintenance", h, wave_scope, host=h)
                held.discard(h)
                actions.append({"tool": "virt.exit_maintenance", "asset": h, "evidence": ev})
        except (PolicyViolation, ToolCallError) as exc:
            # Stop at once (the kill switch means no more writes); a person finishes the rollback.
            done = {c["asset"] for c in reverted}
            return {"actions": actions, "blocked": str(exc), "recovered": False,
                    "reverted": [{"asset": c["asset"], "component": c["component"], "to": c["from"]} for c in reverted],
                    "pending": [c for c in wave_exec["firmware_changes"] if c not in reverted],
                    "in_maintenance": sorted(held), "rebooting": [s for s in wave_exec.get("switches_rebooting", []) if s not in done],
                    "after": [], "evidence": None, "series": {}}
        soak = int(self.sv.policy.get("execution.durations_min.soak", 10))
        bus.call(self.name, "telemetry.advance_clock", minutes=soak)
        after, after_ev = bus.call(self.name, "telemetry.get_golden_signals", assets=servers + switches)
        span = bus.call(self.name, "telemetry.get_clock")[0]["t_min"] - t0
        series = {s: bus.call(self.name, "telemetry.get_metric_series", asset=s, metric="nic_latency_ms", minutes=span)[0]
                  for s in servers}
        return {"actions": actions, "reverted": [{"asset": c["asset"], "component": c["component"], "to": c["from"]} for c in changes],
                "after": after, "evidence": after_ev, "series": series}
