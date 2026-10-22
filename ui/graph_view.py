"""Graphviz rendering of the cross-domain dependency graph for the Control Tower."""

from __future__ import annotations

WAVE_COLORS = ["#2563eb", "#7c3aed", "#0891b2", "#ca8a04", "#db2777", "#16a34a", "#ea580c", "#4f46e5"]


def _short(name: str) -> str:
    return name.replace("blr-esx-", "")


def build_dot(topo, overlay: str = "none", plan: dict | None = None, impact: dict | None = None,
              risk: dict | None = None, deferred: set[str] | None = None, high_risk: float = 70) -> str:
    """overlay: none | impact (one wave's simulated outage) | waves (plan colouring) | risk (heat).

    ``high_risk`` is policy planning.high_risk_threshold: risk scores at or above it are red."""
    deferred = deferred or set()
    wave_of: dict[str, int] = {}
    if plan:
        for i, w in enumerate(plan["waves"]):
            for a in w["assets"] + w.get("evacuate", []):
                wave_of[a] = i
    isolated = set((impact or {}).get("isolated_servers", []))
    storage_lost = set((impact or {}).get("storage_lost_servers", []))
    down = set((impact or {}).get("down_switches", [])) | set((impact or {}).get("maintenance_hosts", []))
    arrays_cut = set((impact or {}).get("arrays_unreachable", []))
    single = {s["server"] for s in topo.single_homed()}

    def risk_color(score: float) -> str:
        if score >= high_risk:
            return "#dc2626"
        if score >= 40:
            return "#f97316"
        if score >= 20:
            return "#facc15"
        return "#86efac"

    def node_style(n: str, kind: str) -> str:
        fill, font, pen, style = "#f1f5f9", "#0f172a", "#94a3b8", "filled"
        if overlay == "impact":
            if n in down:
                fill, font = "#334155", "#ffffff"
            elif n in isolated or n in arrays_cut:
                fill, font = "#dc2626", "#ffffff"
            elif n in storage_lost:
                fill = "#fb923c"
        elif overlay == "waves" and n in wave_of:
            fill, font = WAVE_COLORS[wave_of[n] % len(WAVE_COLORS)], "#ffffff"
        elif overlay == "risk" and risk and n in risk:
            fill = risk_color(risk[n]["score"])
        if n in deferred:
            style, fill, font = "filled,dashed", "#e2e8f0", "#64748b"
        if n in single:
            pen = "#dc2626"
        return f'style="{style}" fillcolor="{fill}" fontcolor="{font}" color="{pen}"'

    lines = [
        "graph G {",
        'graph [rankdir=TB, splines=true, nodesep=0.08, ranksep=0.55, bgcolor="transparent", fontname="Helvetica", newrank=true];',
        'node [fontname="Helvetica", fontsize=9, shape=box, height=0.25, width=0.3, margin="0.03,0.02"];',
        'edge [color="#cbd5e1", penwidth=0.6];',
    ]
    spines = [n for n, s in topo.switches.items() if s["role"] == "spine"]
    lines.append("subgraph cluster_core { label=\"Spine\"; fontsize=10; color=\"#e2e8f0\";")
    for n in spines:
        lines.append(f'"{n}" [shape=box3d, {node_style(n, "switch")}];')
    lines.append("}")
    racks = sorted({s["rack"] for s in topo.servers.values()})
    array_racks = {topo.switches[p["switch"]]["rack"] for arr in topo.arrays.values() for p in arr["ports"]}
    for rack in racks:
        hosts = sorted(h for h, s in topo.servers.items() if s["rack"] == rack)
        cluster = topo.servers[hosts[0]]["cluster"]
        tors = sorted(n for n, s in topo.switches.items() if s["rack"] == rack and s["role"] == "tor")
        lines.append(f'subgraph cluster_{rack} {{ label="Rack {rack} · {cluster}"; fontsize=10; color="#cbd5e1"; style=rounded;')
        for t in tors:
            lines.append(f'"{t}" [shape=box3d, {node_style(t, "switch")}];')
        lines.append("{rank=same; " + " ".join(f'"{t}"' for t in tors) + "}")
        half = (len(hosts) + 1) // 2
        rows = [hosts[:half], hosts[half:]]
        for row in rows:
            for h in row:
                lines.append(f'"{h}" [label="{_short(h)}", {node_style(h, "server")}];')
            lines.append("{rank=same; " + " ".join(f'"{h}"' for h in row) + "}")
        for a, b in zip(rows[0], rows[1]):
            lines.append(f'"{a}" -- "{b}" [style=invis];')
        if rack in array_racks:
            for arr in topo.arrays:
                lines.append(f'"{arr}" [shape=cylinder, label="{arr}", {node_style(arr, "array")}];')
        lines.append("}")
    def level(n: str) -> int:
        if n in topo.switches:
            return 0 if topo.switches[n]["role"] == "spine" else 1
        return 2

    # physical links, written top-down so Graphviz ranks spine > ToR > hosts
    for a, b, d in topo.g.edges(data=True):
        if d["kind"] != "link":
            continue
        if level(a) > level(b):
            a, b = b, a
        kinds = {topo.g.nodes[a]["kind"], topo.g.nodes[b]["kind"]}
        if kinds == {"server", "switch"}:
            srv = a if a in topo.servers else b
            if srv in single:
                lines.append(f'"{a}" -- "{b}" [color="#dc2626", penwidth=1.6];')
            else:
                lines.append(f'"{a}" -- "{b}";')
        elif "array" in kinds:
            lines.append(f'"{a}" -- "{b}" [color="#7c3aed", penwidth=1.6];')
        else:
            lines.append(f'"{a}" -- "{b}" [color="#64748b", penwidth=1.2];')
    for a, b, d in topo.g.edges(data=True):
        if d["kind"] == "peer":
            lines.append(f'"{a}" -- "{b}" [color="#0ea5e9", style=bold, penwidth=1.4, constraint=false];')
    for p in topo.down_ports:
        srv = (p.get("description") or "").split(" ")[0]
        if srv in topo.servers:
            lines.append(f'"{p["switch"]}" -- "{srv}" [color="#dc2626", style=dashed, penwidth=1.4, label=" down", fontsize=8, fontcolor="#dc2626"];')
    # tier-0 services
    for svc in sorted({v["service"] for v in topo.vms.values() if v["tier"] == 0}):
        sid = "svc:" + svc
        hosts = sorted({v["host"] for v in topo.vms.values() if v["service"] == svc})
        hit = overlay == "impact" and any(v["name"] in set((impact or {}).get("impacted_vms", [])) for v in topo.vms.values() if v["service"] == svc)
        fill = "#dc2626" if hit else "#fef3c7"
        lines.append(f'"{sid}" [label="{svc} (tier-0)", shape=ellipse, style=filled, fillcolor="{fill}", fontcolor="{"#ffffff" if hit else "#92400e"}", fontsize=10];')
        for h in hosts:
            lines.append(f'"{h}" -- "{sid}" [color="#f59e0b", style=dotted, penwidth=1.0];')
    lines.append("}")
    return "\n".join(lines)
