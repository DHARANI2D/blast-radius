"""Generate the synthetic "digital twin" of one Bangalore data-centre pod.

The JSON shapes loosely mirror the APIs BlastRadius would read in production
(Compute Ops Management servers/baselines, Aruba Central / Mist switches and
LLDP, Morpheus clusters/VMs/datastores). Every value is synthetic: no customer
or HPE production data is used.

    python scripts/generate_twin.py            # writes data/twin/pod_blr1.json

The generator is seeded, so the output is reproducible.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "twin" / "pod_blr1.json"
rng = random.Random(20261021)

HOST_MEM_GB = 1024
HOST_CORES = 64
NIC_REFRESHED = (3, 11, 16, 20)  # R1 hosts already on NIC BCM57414 230.x

# Hand-placed "anchor" workloads. Everything else is filler that brings each
# host to a realistic 48-60% memory utilisation.
ANCHORS = {
    "blr-esx-07": [("payments-db-01", "payments", 0, 16, 256)],
    "blr-esx-27": [("payments-db-02", "payments", 0, 16, 256)],
    "blr-esx-04": [("payments-api-01", "payments", 0, 8, 32)],
    "blr-esx-09": [("payments-api-02", "payments", 0, 8, 32)],
    "blr-esx-24": [("payments-api-03", "payments", 0, 8, 32)],
    "blr-esx-33": [("payments-api-04", "payments", 0, 8, 32)],
    "blr-esx-05": [("orders-db-01", "orders", 1, 16, 192)],
    "blr-esx-25": [("orders-db-02", "orders", 1, 16, 192)],
    "blr-esx-12": [("orders-app-01", "orders", 1, 8, 64), ("orders-app-02", "orders", 1, 8, 64)],
    "blr-esx-30": [("orders-app-03", "orders", 1, 8, 64), ("orders-app-04", "orders", 1, 8, 64)],
    "blr-esx-14": [("portal-web-01", "customer-portal", 1, 4, 32), ("portal-web-02", "customer-portal", 1, 4, 32)],
    "blr-esx-18": [("portal-web-03", "customer-portal", 1, 4, 32)],
    "blr-esx-36": [("portal-web-04", "customer-portal", 1, 4, 32), ("portal-web-05", "customer-portal", 1, 4, 32)],
    "blr-esx-02": [("observability-01", "observability", 2, 8, 128)],
    "blr-esx-22": [("observability-02", "observability", 2, 8, 128)],
}

# Filler pools: (prefix, service, tier, vcpu, sizes)
FILLER = [
    ("analytics", "analytics", 2, 16, [64, 128]),
    ("inventory", "inventory", 2, 8, [32, 64]),
    ("ci-runner", "ci-runners", 3, 8, [16, 32]),
    ("dev-sandbox", "dev-sandbox", 3, 4, [16, 32]),
]

# Hosts that only carry tier-3 work: natural canary candidates.
LOW_TIER_HOSTS = {"blr-esx-03", "blr-esx-11", "blr-esx-21", "blr-esx-38"}


def servers() -> list[dict]:
    out = []
    for i in range(1, 41):
        name = f"blr-esx-{i:02d}"
        r1 = i <= 20
        model = "HPE ProLiant DL380 Gen11" if r1 else "HPE ProLiant DL360 Gen11"
        rom_family = "U54" if r1 else "U63"
        ilo = "1.58"
        if not r1 and i in (29, 35, 39):
            ilo = "1.62"  # firmware drift on a few hosts
        history = [
            {"date": "2026-07-12", "change": f"System ROM {rom_family} v2.10 -> v2.16", "result": "success"},
        ]
        if name == "blr-esx-12":
            history.append({
                "date": "2026-08-23",
                "change": f"System ROM {rom_family} v2.16 -> v2.20",
                "result": "rolled_back",
                "note": "POST hang after update; reverted via iLO recovery set",
            })
        out.append({
            "id": f"srv-{i:04d}",
            "name": name,
            "serialNumber": f"SYN{'1' if r1 else '2'}R{i:03d}",
            "model": model,
            "rack": "R1" if r1 else "R2",
            "rackUnit": 2 + ((i - 1) % 20) * 2,
            "cluster": "PROD-BLR-07" if r1 else "PROD-BLR-08",
            "memoryGB": HOST_MEM_GB,
            "cpuCores": HOST_CORES,
            "state": {"health": "OK", "power": "ON"},
            "firmware": {
                "iLO 6": ilo,
                "System ROM": f"{rom_family} v2.16",
                # Dev/CI hosts get firmware first: four R1 hosts already run the newer NIC
                # firmware. They are also the lowest-risk hosts, so a risk-ranked canary
                # picks them and never tests the NIC 229.x configuration.
                "NIC BCM57414": "230.0.156.0" if (not r1 or i in NIC_REFRESHED) else "229.1.123.0",
            },
            "nics": [
                {"name": "ens1f0", "speedGbps": 25, "mac": f"94:40:c9:{i:02x}:00:00"},
                {"name": "ens1f1", "speedGbps": 25, "mac": f"94:40:c9:{i:02x}:00:01"},
            ],
            "changeHistory": history,
        })
    return out


def switches() -> list[dict]:
    def sw(name, model, os_name, fw, role, rack, peer, ptype):
        return {
            "name": name,
            "serial": "SYN" + name.upper().replace("-", ""),
            "model": model,
            "os": os_name,
            "firmware": fw,
            "role": role,
            "rack": rack,
            "status": "UP",
            "redundancy": {"type": ptype, "peer": peer} if peer else None,
            "cpuPct": rng.randint(9, 18),
        }

    cx = "HPE Aruba Networking CX 8325-48Y8C"
    qfx = "HPE Juniper Networking QFX5120-48Y"
    spine = "HPE Aruba Networking CX 9300-32D"
    return [
        sw("spine-1", spine, "AOS-CX", "10.13.1010", "spine", "R0", "spine-2", "VSX"),
        sw("spine-2", spine, "AOS-CX", "10.13.1010", "spine", "R0", "spine-1", "VSX"),
        sw("tor-r1-a", cx, "AOS-CX", "10.13.1010", "tor", "R1", "tor-r1-b", "VSX"),
        sw("tor-r1-b", cx, "AOS-CX", "10.13.1010", "tor", "R1", "tor-r1-a", "VSX"),
        sw("tor-r2-a", qfx, "Junos", "23.4R2-S3", "tor", "R2", "tor-r2-b", "MC-LAG"),
        sw("tor-r2-b", qfx, "Junos", "23.4R2-S3", "tor", "R2", "tor-r2-a", "MC-LAG"),
    ]


def ports() -> list[dict]:
    """Switch ports with LLDP neighbours (Central/Mist style)."""
    out = []

    def port(switch, pid, neighbor, nport, status="up", vlans=(110, 120, 300), note=None, descr=None):
        p = {
            "switch": switch,
            "port": pid,
            "description": descr or (f"{neighbor} {nport}" if neighbor else ""),
            "status": status,
            "speed": "25G" if not pid.endswith(("/49", "/50", "/51", "/52")) else "100G",
            "vlans": list(vlans),
            "lldp": {"neighbor": neighbor, "neighborPort": nport} if status == "up" else None,
        }
        if note:
            p["note"] = note
        out.append(p)

    for i in range(1, 41):
        host = f"blr-esx-{i:02d}"
        rack = "r1" if i <= 20 else "r2"
        idx = (i - 1) % 20 + 1
        a, b = f"tor-{rack}-a", f"tor-{rack}-b"
        pid = f"1/1/{idx}" if rack == "r1" else f"xe-0/0/{idx}"
        port(a, pid, host, "ens1f0")
        if host == "blr-esx-07":
            # The hidden dependency: second uplink err-disabled for weeks.
            port(b, pid, None, None, status="down", descr=f"{host} ens1f1",
                 note="err-disabled (link-flap) since 2026-09-28; ticket never raised")
        else:
            port(b, pid, host, "ens1f1")

    # Storage array iSCSI ports hang off the R1 ToR pair only.
    port("tor-r1-a", "1/1/45", "alletra-mp-blr-01", "ctrl-a:p1", vlans=(300,))
    port("tor-r1-b", "1/1/45", "alletra-mp-blr-01", "ctrl-b:p1", vlans=(300,))

    # ToR -> spine uplinks and VSX/MC-LAG inter-switch links.
    for tor, (u1, u2, isl) in {
        "tor-r1-a": ("1/1/49", "1/1/50", "1/1/51"),
        "tor-r1-b": ("1/1/49", "1/1/50", "1/1/51"),
        "tor-r2-a": ("et-0/0/49", "et-0/0/50", "et-0/0/51"),
        "tor-r2-b": ("et-0/0/49", "et-0/0/50", "et-0/0/51"),
    }.items():
        peer = tor[:-1] + ("b" if tor.endswith("a") else "a")
        port(tor, u1, "spine-1", f"1/1/{tor_index(tor)}", vlans=(110, 120, 300))
        port(tor, u2, "spine-2", f"1/1/{tor_index(tor)}", vlans=(110, 120, 300))
        port(tor, isl, peer, isl, vlans=(110, 120, 300))
    port("spine-1", "1/1/32", "spine-2", "1/1/32")
    port("spine-2", "1/1/32", "spine-1", "1/1/32")
    return out


def tor_index(tor: str) -> int:
    return {"tor-r1-a": 1, "tor-r1-b": 2, "tor-r2-a": 3, "tor-r2-b": 4}[tor]


def vms() -> list[dict]:
    out = []
    counters = {p[0]: 0 for p in FILLER}
    for i in range(1, 41):
        host = f"blr-esx-{i:02d}"
        cluster = "PROD-BLR-07" if i <= 20 else "PROD-BLR-08"
        ds = "ds-blr07-gold" if i <= 20 else "ds-blr08-gold"
        used = 0
        for name, svc, tier, vcpu, mem in ANCHORS.get(host, []):
            out.append(vm(name, host, cluster, ds, svc, tier, vcpu, mem))
            used += mem
        target = rng.uniform(0.48, 0.58) * HOST_MEM_GB
        pools = FILLER[2:] if host in LOW_TIER_HOSTS else FILLER
        while used < target:
            prefix, svc, tier, vcpu, sizes = rng.choice(pools)
            mem = rng.choice(sizes)
            if used + mem > 0.60 * HOST_MEM_GB:
                break
            counters[prefix] += 1
            out.append(vm(f"{prefix}-{counters[prefix]:02d}", host, cluster, ds, svc, tier, vcpu, mem))
            used += mem
    return out


def vm(name, host, cluster, ds, svc, tier, vcpu, mem):
    return {
        "name": name,
        "host": host,
        "cluster": cluster,
        "datastore": ds,
        "service": svc,
        "tier": tier,
        "vcpu": vcpu,
        "memoryGB": mem,
        "powerState": "on",
    }


def main() -> None:
    twin = {
        "_meta": {
            "site": "BLR-POD-1 (synthetic digital twin)",
            "generatedBy": "scripts/generate_twin.py",
            "disclaimer": "Synthetic lab data. Not customer data. Firmware versions, CVE and advisory IDs are fictitious.",
        },
        "compute": {
            "servers": servers(),
            "baselines": [
                {
                    "name": "BLR-Baseline-2026.10",
                    "spp": "SPP 2026.09.0 (synthetic)",
                    "released": "2026-09-30",
                    "latest": True,
                    "components": {
                        "HPE ProLiant DL380 Gen11": {"iLO 6": "1.64", "System ROM": "U54 v2.32", "NIC BCM57414": "230.0.156.0"},
                        "HPE ProLiant DL360 Gen11": {"iLO 6": "1.64", "System ROM": "U63 v2.32", "NIC BCM57414": "230.0.156.0"},
                    },
                },
                {
                    "name": "BLR-Baseline-2026.07",
                    "spp": "SPP 2026.06.0 (synthetic)",
                    "released": "2026-06-30",
                    "latest": False,
                    "components": {
                        "HPE ProLiant DL380 Gen11": {"iLO 6": "1.58", "System ROM": "U54 v2.16", "NIC BCM57414": "229.1.123.0"},
                        "HPE ProLiant DL360 Gen11": {"iLO 6": "1.58", "System ROM": "U63 v2.16", "NIC BCM57414": "230.0.156.0"},
                    },
                },
            ],
        },
        "network": {
            "switches": switches(),
            "ports": ports(),
            "baselines": [
                {"name": "NET-Baseline-2026.10", "latest": True,
                 "components": {"HPE Aruba Networking CX 8325-48Y8C": {"Switch OS": "10.14.1000"},
                                "HPE Aruba Networking CX 9300-32D": {"Switch OS": "10.14.1000"},
                                "HPE Juniper Networking QFX5120-48Y": {"Switch OS": "23.4R2-S4"}}},
            ],
        },
        "virtualization": {
            "clusters": [
                {"name": "PROD-BLR-07", "platform": "HPE Morpheus VM Essentials", "ha": {"enabled": True, "failoverHosts": 1},
                 "maxMemoryUtilPct": 85, "hosts": [f"blr-esx-{i:02d}" for i in range(1, 21)]},
                {"name": "PROD-BLR-08", "platform": "VMware vSphere (managed by HPE Morpheus)", "ha": {"enabled": True, "failoverHosts": 1},
                 "maxMemoryUtilPct": 85, "hosts": [f"blr-esx-{i:02d}" for i in range(21, 41)]},
            ],
            "datastores": [
                {"name": "ds-blr07-gold", "array": "alletra-mp-blr-01", "protocol": "iSCSI", "vlan": 300},
                {"name": "ds-blr08-gold", "array": "alletra-mp-blr-01", "protocol": "iSCSI", "vlan": 300},
            ],
            "vms": vms(),
        },
        "storage": {
            "arrays": [
                {"name": "alletra-mp-blr-01", "model": "HPE Alletra Storage MP B10000", "firmware": "10.4.2 (synthetic)",
                 "ports": [{"name": "ctrl-a:p1", "switch": "tor-r1-a"}, {"name": "ctrl-b:p1", "switch": "tor-r1-b"}]},
            ],
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(twin, indent=1) + "\n")
    n_vms = len(twin["virtualization"]["vms"])
    print(f"wrote {OUT} ({len(twin['compute']['servers'])} servers, {len(twin['network']['switches'])} switches, {n_vms} VMs)")


if __name__ == "__main__":
    main()
