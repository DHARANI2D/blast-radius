"""Post-Validation agent: compares golden signals before, during and after a wave."""

from __future__ import annotations


class PostValidationAgent:
    name = "postcheck"

    def __init__(self, sv):
        self.sv = sv

    def compare(self, pre: list[dict], post: list[dict], during: list[dict] | None = None) -> dict:
        g = self.sv.policy.get("golden_signals", {})
        before = {s["asset"]: s for s in pre}
        regressions: list[dict] = []

        def reg(asset, metric, a, b, msg):
            regressions.append({"asset": asset, "metric": metric, "pre": a, "post": b, "message": msg})

        for s in post:
            a = s["asset"]
            p = before.get(a)
            if p is None:
                continue
            if s["kind"] == "server":
                ratio = s["nic_latency_ms"] / max(1e-6, p["nic_latency_ms"])
                if ratio > float(g.get("nic_latency_ratio_max", 2.0)):
                    reg(a, "nic_latency_ms", p["nic_latency_ms"], s["nic_latency_ms"],
                        f"NIC latency {p['nic_latency_ms']:.2f} -> {s['nic_latency_ms']:.2f} ms ({ratio:.1f}x)")
                if s["rx_drop_rate"] > float(g.get("rx_drop_rate_max", 0.001)):
                    reg(a, "rx_drop_rate", p["rx_drop_rate"], s["rx_drop_rate"], f"rx drop rate {s['rx_drop_rate']:.3%}")
                if s["crc_errors_per_min"] > float(g.get("crc_errors_per_min_max", 5)):
                    reg(a, "crc_errors_per_min", p["crc_errors_per_min"], s["crc_errors_per_min"],
                        f"{s['crc_errors_per_min']} CRC errors/min ({s['crc_errors_total'] - p['crc_errors_total']} since the wave started)")
                if s["health"] != g.get("require_health", "OK"):
                    reg(a, "health", p["health"], s["health"], f"health {s['health']}")
                if not s["network_reachable"] or not s["storage_paths_ok"]:
                    reg(a, "reachability", True, False, "host lost network or storage paths")
                hb = s["vm_heartbeats"]
                if hb["expected"] - hb["ok"] > int(g.get("vm_heartbeat_loss_max", 0)):
                    reg(a, "vm_heartbeats", hb["expected"], hb["ok"], f"{hb['expected'] - hb['ok']} VM heartbeats missing")
            else:
                if s["status"] != "UP":
                    reg(a, "status", p["status"], s["status"], f"switch status {s['status']}")
                if p["ports_up"] - s["ports_up"] > int(g.get("switch_ports_down_delta_max", 0)):
                    reg(a, "ports_up", p["ports_up"], s["ports_up"], f"{p['ports_up'] - s['ports_up']} ports down")

        for s in during or []:
            if s["kind"] == "server" and not s["maintenanceMode"]:
                hb = s["vm_heartbeats"]
                if not s["network_reachable"] or hb["ok"] < hb["expected"]:
                    reg(s["asset"], "during:reachability", True, False,
                        f"lost connectivity while its switch rebooted ({hb['expected'] - hb['ok']} VM heartbeats missing)")
        return {"passed": not regressions, "regressions": regressions, "checked": len(post) + len(during or [])}
