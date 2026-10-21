"""In-memory digital twin of the lab pod.

The twin plays the part of the real estate: Compute Ops Management, Aruba
Central / Mist, Morpheus and OpsRamp-style telemetry all read from and write to
it through the MCP tool layer. Agents never touch it directly.

It also holds the fault-injection rules used in the demo. Agents cannot see
these rules; they only observe their effect through telemetry, exactly as they
would observe a real firmware regression.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

# A firmware combination that regresses NIC latency. It is the "unknown
# unknown" the canary wave exists to catch: nothing in the knowledge base
# mentions it until BlastRadius learns it from a rollback.
FAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "FAULT-NIC-LAT-01",
        "description": (
            "System ROM U54 v2.32 changes PCIe link-training defaults; BCM57414 adapters still on "
            "NIC firmware 229.x renegotiate badly, raising NIC latency ~4x and dropping packets."
        ),
        "model": "HPE ProLiant DL380 Gen11",
        "firmware_equals": {"System ROM": "U54 v2.32"},
        "firmware_prefix": {"NIC BCM57414": "229."},
        "effect": {"nic_latency_multiplier": 4.1, "rx_drop_rate": 0.012, "crc_errors_per_min": 35},
    }
]


class TwinError(RuntimeError):
    pass


class Twin:
    def __init__(self, twin_file: Path, faults_enabled: bool = True):
        self._file = twin_file
        self._lock = threading.RLock()
        self.faults_enabled = faults_enabled
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self) -> None:
        with self._lock:
            raw = json.loads(self._file.read_text())
            self.meta = raw.get("_meta", {})
            self.servers: dict[str, dict] = {s["name"]: s for s in raw["compute"]["servers"]}
            self.compute_baselines: list[dict] = raw["compute"]["baselines"]
            self.switches: dict[str, dict] = {s["name"]: s for s in raw["network"]["switches"]}
            self.ports: list[dict] = raw["network"]["ports"]
            self.network_baselines: list[dict] = raw["network"]["baselines"]
            self.clusters: dict[str, dict] = {c["name"]: c for c in raw["virtualization"]["clusters"]}
            self.datastores: dict[str, dict] = {d["name"]: d for d in raw["virtualization"]["datastores"]}
            self.vms: dict[str, dict] = {v["name"]: v for v in raw["virtualization"]["vms"]}
            self.arrays: dict[str, dict] = {a["name"]: a for a in raw["storage"]["arrays"]}
            self.maintenance: set[str] = set()
            self.rebooting_switches: set[str] = set()
            self.clock_min = 0
            self.firmware_history: list[dict] = []
            self.crc_counters: dict[str, int] = {n: 100 + (i * 7) % 40 for i, n in enumerate(self.servers)}
            # Per-minute NIC latency history (None while a host is in maintenance),
            # seeded with 15 minutes of pre-window baseline.
            self.history: dict[str, list[tuple[int, float | None]]] = {n: [] for n in self.servers}
            for t in range(-15, 1):
                self._record(t)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "firmware": {n: dict(s["firmware"]) for n, s in self.servers.items()},
                "switch_firmware": {n: s["firmware"] for n, s in self.switches.items()},
                "placement": {n: v["host"] for n, v in self.vms.items()},
            }

    def advance(self, minutes: int) -> None:
        with self._lock:
            for _ in range(int(minutes)):
                self.clock_min += 1
                self._record(self.clock_min)
            for name in self.servers:
                eff = self._fault_effect(name)
                if eff:
                    self.crc_counters[name] += int(eff.get("crc_errors_per_min", 0) * minutes)

    def _record(self, t: int) -> None:
        for name in self.servers:
            self.history[name].append((t, None if name in self.maintenance else round(self._latency(name, t), 4)))

    # ----------------------------------------------------------- read helpers
    def get_server(self, name: str) -> dict:
        if name not in self.servers:
            raise TwinError(f"unknown server {name!r}")
        s = copy.deepcopy(self.servers[name])
        s["state"]["maintenanceMode"] = name in self.maintenance
        return s

    def get_switch(self, name: str) -> dict:
        if name not in self.switches:
            raise TwinError(f"unknown switch {name!r}")
        s = copy.deepcopy(self.switches[name])
        if name in self.rebooting_switches:
            s["status"] = "REBOOTING"
        return s

    def ports_of(self, switch: str | None = None) -> list[dict]:
        out = []
        for p in self.ports:
            if switch and p["switch"] != switch:
                continue
            q = copy.deepcopy(p)
            if p["switch"] in self.rebooting_switches:
                q["status"] = "down"
                q["lldp"] = None
            out.append(q)
        return out

    def vms_on(self, host: str) -> list[dict]:
        return [v for v in self.vms.values() if v["host"] == host]

    def host_mem_used(self, host: str) -> int:
        return sum(v["memoryGB"] for v in self.vms_on(host))

    # --------------------------------------------------------------- mutation
    def enter_maintenance(self, host: str) -> dict:
        with self._lock:
            srv = self.servers.get(host)
            if not srv:
                raise TwinError(f"unknown host {host!r}")
            if host in self.maintenance:
                return {"host": host, "migrated": [], "already": True}
            cluster = self.clusters[srv["cluster"]]
            limit = cluster["maxMemoryUtilPct"] / 100.0
            targets = [h for h in cluster["hosts"] if h != host and h not in self.maintenance and self._host_network_ok(h)]
            moved = []
            for vm in sorted(self.vms_on(host), key=lambda v: -v["memoryGB"]):
                cands = [
                    h for h in targets
                    if self.host_mem_used(h) + vm["memoryGB"] <= limit * self.servers[h]["memoryGB"]
                ]
                if not cands:
                    raise TwinError(f"insufficient capacity in {cluster['name']} to evacuate {vm['name']} from {host}")
                dest = min(cands, key=lambda h: self.host_mem_used(h) / self.servers[h]["memoryGB"])
                vm["host"] = dest
                moved.append({"vm": vm["name"], "to": dest})
            self.maintenance.add(host)
            self.advance(5)
            return {"host": host, "migrated": moved}

    def exit_maintenance(self, host: str) -> dict:
        with self._lock:
            self.maintenance.discard(host)
            return {"host": host, "maintenanceMode": False}

    def apply_firmware(self, server: str, component: str, version: str) -> dict:
        with self._lock:
            srv = self.servers.get(server)
            if not srv:
                raise TwinError(f"unknown server {server!r}")
            if component not in srv["firmware"]:
                raise TwinError(f"{server} has no component {component!r}")
            if component != "iLO 6" and server not in self.maintenance:
                raise TwinError(f"{server} must be in maintenance mode before updating {component}")
            prev = srv["firmware"][component]
            srv["firmware"][component] = version
            self.firmware_history.append({"asset": server, "component": component, "from": prev, "to": version, "t": self.clock_min})
            self.advance(4 if component == "iLO 6" else 14)
            return {"server": server, "component": component, "previous": prev, "current": version, "status": "COMPLETED"}

    def upgrade_switch_os(self, switch: str, version: str, hold_down: bool = False) -> dict:
        """Upgrade a switch. With ``hold_down`` the switch stays in REBOOTING
        until :meth:`finish_switch_reboot` (used to model a wave in flight)."""
        with self._lock:
            sw = self.switches.get(switch)
            if not sw:
                raise TwinError(f"unknown switch {switch!r}")
            prev = sw["firmware"]
            sw["firmware"] = version
            self.firmware_history.append({"asset": switch, "component": "Switch OS", "from": prev, "to": version, "t": self.clock_min})
            self.rebooting_switches.add(switch)
            self.advance(20)
            if not hold_down:
                self.rebooting_switches.discard(switch)
            return {"switch": switch, "previous": prev, "current": version, "status": "COMPLETED"}

    def finish_switch_reboot(self, switch: str) -> None:
        with self._lock:
            self.rebooting_switches.discard(switch)

    # -------------------------------------------------------------- telemetry
    def _fault_effect(self, server: str) -> dict | None:
        if not self.faults_enabled:
            return None
        srv = self.servers[server]
        for rule in FAULT_RULES:
            if srv["model"] != rule["model"]:
                continue
            if any(srv["firmware"].get(c) != v for c, v in rule["firmware_equals"].items()):
                continue
            if any(not srv["firmware"].get(c, "").startswith(p) for c, p in rule["firmware_prefix"].items()):
                continue
            return rule["effect"]
        return None

    def _host_network_ok(self, host: str) -> bool:
        for p in self.ports:
            lldp = p.get("lldp") or {}
            if lldp.get("neighbor") == host and p["status"] == "up" and p["switch"] not in self.rebooting_switches:
                return True
        return False

    def _storage_ok(self, host: str) -> bool:
        # Storage reachability: host -> an up ToR -> spine -> an up ToR carrying an array port.
        array_switches = {pt["switch"] for a in self.arrays.values() for pt in a["ports"]}
        live_array_sw = array_switches - self.rebooting_switches
        if not live_array_sw:
            return False
        return self._host_network_ok(host)

    def _latency(self, name: str, t: int) -> float:
        base = 0.17 + (int(hashlib.sha256(name.encode()).hexdigest(), 16) % 30) / 1000.0
        eff = self._fault_effect(name) or {}
        return base * eff.get("nic_latency_multiplier", 1.0) * (1 + self._jitter(name, t, 0.06))

    @staticmethod
    def _jitter(key: str, t: int, scale: float) -> float:
        h = hashlib.sha256(f"{key}:{t}".encode()).digest()
        return (h[0] / 255.0 - 0.5) * 2 * scale

    def server_signals(self, name: str, t: int | None = None) -> dict:
        with self._lock:
            t = self.clock_min if t is None else t
            srv = self.servers[name]
            eff = self._fault_effect(name) or {}
            lat = self._latency(name, t)
            net_ok = self._host_network_ok(name)
            storage_ok = self._storage_ok(name)
            vms = self.vms_on(name)
            hb_ok = len(vms) if (net_ok and storage_ok) else 0
            return {
                "asset": name,
                "kind": "server",
                "t_min": t,
                "health": srv["state"]["health"],
                "maintenanceMode": name in self.maintenance,
                "nic_latency_ms": round(lat, 4),
                "rx_drop_rate": eff.get("rx_drop_rate", 0.0001),
                "crc_errors_total": self.crc_counters[name],
                "crc_errors_per_min": eff.get("crc_errors_per_min", 0),
                "network_reachable": net_ok,
                "storage_paths_ok": storage_ok,
                "vm_heartbeats": {"expected": len(vms), "ok": hb_ok},
            }

    def switch_signals(self, name: str, t: int | None = None) -> dict:
        with self._lock:
            t = self.clock_min if t is None else t
            sw = self.switches[name]
            ports = [p for p in self.ports if p["switch"] == name]
            up = 0 if name in self.rebooting_switches else sum(1 for p in ports if p["status"] == "up")
            return {
                "asset": name,
                "kind": "switch",
                "t_min": t,
                "status": "REBOOTING" if name in self.rebooting_switches else sw["status"],
                "health": "OK" if name not in self.rebooting_switches else "DEGRADED",
                "ports_up": up,
                "ports_total": len(ports),
                "cpu_pct": max(1, sw["cpuPct"] + int(self._jitter(name, t, 3))),
            }

    def signals(self, asset: str, t: int | None = None) -> dict:
        if asset in self.servers:
            return self.server_signals(asset, t)
        if asset in self.switches:
            return self.switch_signals(asset, t)
        raise TwinError(f"unknown asset {asset!r}")

    def series(self, asset: str, metric: str, minutes: int = 10) -> list[dict]:
        """Samples of one metric over the last ``minutes`` of simulated time."""
        end = self.clock_min
        if metric == "nic_latency_ms" and asset in self.history:
            return [{"t_min": t, "value": v} for t, v in self.history[asset] if t > end - minutes]
        out = []
        for t in range(max(0, end - minutes + 1), end + 1):
            s = self.signals(asset, t)
            out.append({"t_min": t, "value": s.get(metric)})
        return out

