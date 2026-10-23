"""In-memory digital twin of the lab pod.

The twin plays the part of the real estate: Compute Ops Management, Aruba
Central / Mist, Morpheus and OpsRamp-style telemetry all read from and write to
it through the MCP tool layer. Agents never touch it directly.

It also holds the fault-injection rules used in the demo. Agents cannot see
these rules; they only observe their effect through telemetry, exactly as they
would observe a real firmware regression.

Which faults are live is a *scenario* (``BR_FAULTS``-style string, see
:func:`parse_scenario`): ``on`` is the demo regression and the default,
``off`` is a clean lab, and two opt-in scenarios exercise statistical canary
analysis (``blastradius.canary_stats``): ``subtle`` is a ~1.3x regression a 2x
threshold misses, and ``backup`` is a common-mode backup job that slows every
host at once. They combine with ``+``, e.g. ``on+backup``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Iterable

# Firmware combinations that regress NIC latency. FAULT-NIC-LAT-01 is the
# "unknown unknown" the canary wave exists to catch: nothing in the knowledge
# base mentions it until BlastRadius learns it from a rollback. Each rule is
# live only while its scenario is selected.
FAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "FAULT-NIC-LAT-01",
        "scenario": "regression",
        "description": (
            "System ROM U54 v2.32 changes PCIe link-training defaults; BCM57414 adapters still on "
            "NIC firmware 229.x renegotiate badly, raising NIC latency ~4x and dropping packets."
        ),
        "model": "HPE ProLiant DL380 Gen11",
        "firmware_equals": {"System ROM": "U54 v2.32"},
        "firmware_prefix": {"NIC BCM57414": "229."},
        "effect": {"nic_latency_multiplier": 4.1, "rx_drop_rate": 0.012, "crc_errors_per_min": 35},
    },
    {
        # Opt-in (scenario "subtle"): small enough that post > 2x pre never fires.
        "id": "FAULT-NIC-LAT-02",
        "scenario": "subtle",
        "description": (
            "System ROM U63 v2.32 enables PCIe ASPM L1 on the OCP slot by default; BCM57414 adapters on "
            "NIC firmware 230.x pay a link-state exit penalty: NIC latency ~1.3x and slightly more drops."
        ),
        "model": "HPE ProLiant DL360 Gen11",
        "firmware_equals": {"System ROM": "U63 v2.32"},
        "firmware_prefix": {"NIC BCM57414": "230."},
        "effect": {"nic_latency_multiplier": 1.3, "rx_drop_rate": 0.0003},
    },
]

# Common-mode events hit every host in the pod for a period of simulated time,
# whatever its firmware. They are not caused by the change, so a canary judged
# only against its own past (post vs. pre) blames the change for them.
COMMON_MODE_EVENTS: list[dict[str, Any]] = [
    {
        "id": "EVT-BACKUP-01",
        "scenario": "backup",
        "description": "Nightly backup job (proxy-based VM snapshots) loads every host uplink: NIC latency +40%.",
        "start_min": 72,   # minutes since the change window opened (inclusive)
        "end_min": 162,    # exclusive
        "effect": {"nic_latency_multiplier": 1.4},
    },
]

SCENARIOS = {"regression": "FAULT-NIC-LAT-01 (demo, default)", "subtle": "FAULT-NIC-LAT-02 (~1.3x, opt-in)",
             "backup": "EVT-BACKUP-01 (common-mode, opt-in)"}
_ON, _OFF = {"on", "1", "true", "yes", "regression"}, {"off", "0", "false", "no", "none", ""}

# Metrics whose per-minute history the twin records (None while a host is in maintenance).
HISTORY_METRICS = ("nic_latency_ms", "rx_drop_rate")
BASE_RX_DROP_RATE = 0.0001


def parse_scenario(value: str | bool | Iterable[str] | None) -> frozenset[str]:
    """``"on"`` -> {regression}, ``"off"`` -> {}, ``"subtle+backup"`` -> {subtle, backup}."""
    if value is None or isinstance(value, bool):
        return frozenset({"regression"} if value in (None, True) else set())
    tokens = value.replace(",", "+").split("+") if isinstance(value, str) else list(value)
    out: set[str] = set()
    for tok in (t.strip().lower() for t in tokens):
        if tok in _ON:
            out.add("regression")
        elif tok in SCENARIOS:
            out.add(tok)
        elif tok not in _OFF:
            raise ValueError(f"unknown fault scenario {tok!r}; use on, off, subtle, backup or a '+' combination")
    return frozenset(out)


class TwinError(RuntimeError):
    pass


class Twin:
    def __init__(self, twin_file: Path, faults_enabled: bool = True, scenario: str | Iterable[str] | None = None):
        """``scenario`` (e.g. ``"subtle"``, ``"on+backup"``) overrides ``faults_enabled`` when given."""
        self._file = twin_file
        self._lock = threading.RLock()
        self.scenarios = parse_scenario(faults_enabled if scenario is None else scenario)
        self.reset()

    @property
    def faults_enabled(self) -> bool:
        """The demo regression (FAULT-NIC-LAT-01) is live."""
        return "regression" in self.scenarios

    @faults_enabled.setter
    def faults_enabled(self, on: bool) -> None:
        self.scenarios = (self.scenarios | {"regression"}) if on else (self.scenarios - {"regression"})

    def set_scenario(self, scenario: str | Iterable[str] | None) -> frozenset[str]:
        """Select live faults/events. Takes effect for samples recorded from now on (reset() keeps it)."""
        with self._lock:
            self.scenarios = parse_scenario(scenario)
            return self.scenarios

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
            # Per-minute history of HISTORY_METRICS (None while a host is in maintenance),
            # seeded with 15 minutes of pre-window baseline. ``history`` is the NIC latency one.
            self.metric_history: dict[str, dict[str, list[tuple[int, float | None]]]] = {
                m: {n: [] for n in self.servers} for m in HISTORY_METRICS}
            self.history = self.metric_history["nic_latency_ms"]
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
        drops = self.metric_history["rx_drop_rate"]
        for name in self.servers:
            down = name in self.maintenance
            self.history[name].append((t, None if down else round(self._latency(name, t), 4)))
            drops[name].append((t, None if down else self._drop_rate(name)))

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
        if not self.scenarios:
            return None
        srv = self.servers[server]
        for rule in FAULT_RULES:
            if rule["scenario"] not in self.scenarios or srv["model"] != rule["model"]:
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

    def _common_mode_latency(self, t: int) -> float:
        """NIC latency multiplier of the common-mode events running at minute ``t`` (1.0 if none)."""
        mult = 1.0
        for ev in COMMON_MODE_EVENTS:
            if ev["scenario"] in self.scenarios and ev["start_min"] <= t < ev["end_min"]:
                mult *= ev["effect"].get("nic_latency_multiplier", 1.0)
        return mult

    def _latency(self, name: str, t: int) -> float:
        base = 0.17 + (int(hashlib.sha256(name.encode()).hexdigest(), 16) % 30) / 1000.0
        eff = self._fault_effect(name) or {}
        mult = eff.get("nic_latency_multiplier", 1.0) * self._common_mode_latency(t)
        return base * mult * (1 + self._jitter(name, t, 0.06))

    def _drop_rate(self, name: str) -> float:
        return (self._fault_effect(name) or {}).get("rx_drop_rate", BASE_RX_DROP_RATE)

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
                "rx_drop_rate": eff.get("rx_drop_rate", BASE_RX_DROP_RATE),
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

    def series(self, asset: str, metric: str, minutes: int = 10, start_t: int | None = None,
               end_t: int | None = None) -> list[dict]:
        """Samples of one metric over the last ``minutes`` of simulated time, or over the explicit
        window ``start_t..end_t`` (inclusive; ``end_t`` defaults to now and is capped at now).

        Recorded metrics (HISTORY_METRICS on servers) come from history, so a past window shows what
        the host reported then. Other metrics are recomputed from the current state at each minute.
        """
        with self._lock:
            end = self.clock_min if end_t is None else min(int(end_t), self.clock_min)
            start = end - int(minutes) + 1 if start_t is None else int(start_t)
            hist = self.metric_history.get(metric, {}).get(asset)
            if hist is not None:
                return [{"t_min": t, "value": v} for t, v in hist if start <= t <= end]
            lo = max(0, start) if start_t is None else start
            return [{"t_min": t, "value": self.signals(asset, t).get(metric)} for t in range(lo, end + 1)]

