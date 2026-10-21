"""Executor agent: runs one approved wave through policy-guarded MCP write tools.

Order inside a wave: snapshot golden signals -> evacuate hosts -> start switch
upgrades -> *during* check on dependents while switches are down -> flash host
firmware in vendor order -> wait for switches -> exit maintenance -> soak ->
post snapshot. Every write passes the PolicyGuard and carries an approval token
that the MCP server verifies.
"""

from __future__ import annotations

from ..policy import PolicyViolation
from ..topology import Topology


class ExecutionHalted(RuntimeError):
    pass


class ExecutorAgent:
    name = "executor"

    def __init__(self, sv):
        self.sv = sv

    def _write(self, run_id: str, tool: str, asset: str, approved: set[str], **args):
        try:
            self.sv.guard.check(tool, asset, approved)
        except PolicyViolation as exc:
            raise ExecutionHalted(str(exc)) from exc
        token = self.sv.authority.token(run_id, asset, tool)
        return self.sv.bus.call(self.name, tool, run_id=run_id, approval_token=token, **args)

    def focus_assets(self, wave: dict, topo: Topology) -> tuple[list[str], list[str]]:
        """Assets whose signals we compare: the wave itself plus hosts that depend on its switches."""
        own = [a for a in wave["assets"] + wave.get("evacuate", [])]
        deps: list[str] = []
        for sw in (a for a in wave["assets"] if a in topo.switches):
            for h in topo.servers_depending_on(sw):
                if h not in own and h not in deps:
                    deps.append(h)
        return own, deps

    def run_wave(self, run_id: str, index: int, wave: dict, components: list[str], target_versions: dict,
                 topo: Topology) -> dict:
        sv, bus = self.sv, self.sv.bus
        sv.guard.new_wave()
        if sv.guard.kill_switch_on():
            raise ExecutionHalted("kill switch engaged before the wave started")
        approved = set(wave["assets"]) | set(wave.get("evacuate", []))
        servers = [a for a in wave["assets"] if a in topo.servers]
        switches = [a for a in wave["assets"] if a in topo.switches]
        hosts_in_maint = servers + [e for e in wave.get("evacuate", []) if e in topo.servers]
        own, deps = self.focus_assets(wave, topo)
        order = sv.policy.get("execution.component_order", ["iLO 6", "System ROM"])
        actions: list[dict] = []

        clock, _ = bus.call(self.name, "telemetry.get_clock")
        t0 = clock["t_min"]
        pre, pre_ev = bus.call(self.name, "telemetry.get_golden_signals", assets=own + deps)

        def act(tool, asset, **args):
            res, ev = self._write(run_id, tool, asset, approved, **args)
            actions.append({"tool": tool, "asset": asset, "args": {k: v for k, v in args.items()}, "result": res, "evidence": ev})
            return res

        for h in hosts_in_maint:
            act("virt.enter_maintenance", h, host=h)
        for sw in switches:
            act("network.upgrade_switch_os", sw, switch=sw, version=target_versions[sw]["Switch OS"], hold_down=True)
        during, during_ev = (bus.call(self.name, "telemetry.get_golden_signals", assets=deps) if (switches and deps) else ([], None))
        for h in servers:
            for comp in order:
                if comp in components and comp in target_versions.get(h, {}):
                    act("compute.apply_firmware", h, server=h, component=comp, version=target_versions[h][comp])
        for sw in switches:
            res, ev = bus.call(self.name, "network.wait_upgrade_complete", switch=sw)
            actions.append({"tool": "network.wait_upgrade_complete", "asset": sw, "args": {}, "result": {"status": res["status"]}, "evidence": ev})
        for h in hosts_in_maint:
            act("virt.exit_maintenance", h, host=h)

        soak = int(sv.policy.get("execution.durations_min.soak", 10))
        bus.call(self.name, "telemetry.advance_clock", minutes=soak)
        post, post_ev = bus.call(self.name, "telemetry.get_golden_signals", assets=own + deps)
        clock, _ = bus.call(self.name, "telemetry.get_clock")
        window = clock["t_min"] - t0 + 10
        series = {s: bus.call(self.name, "telemetry.get_metric_series", asset=s, metric="nic_latency_ms", minutes=window)[0]
                  for s in servers}
        firmware_changes = [
            {"asset": a["asset"], "component": a["result"].get("component", "Switch OS"), "from": a["result"]["previous"], "to": a["result"]["current"]}
            for a in actions if a["tool"] in ("compute.apply_firmware", "network.upgrade_switch_os")
        ]
        return {
            "index": index,
            "name": wave.get("name", f"Wave {index}"),
            "assets": wave["assets"],
            "evacuate": wave.get("evacuate", []),
            "t_start_min": t0,
            "t_end_min": clock["t_min"],
            "actions": [{k: v for k, v in a.items() if k != "result"} | {"status": "ok"} for a in actions],
            "firmware_changes": firmware_changes,
            "migrated_vms": sum(len(a["result"].get("migrated", [])) for a in actions if a["tool"] == "virt.enter_maintenance"),
            "pre": pre, "during": during, "post": post,
            "evidence": {"pre": pre_ev, "during": during_ev, "post": post_ev},
            "series": series,
            "dependents": deps,
        }
