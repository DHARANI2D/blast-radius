"""Deterministic stand-ins for the LLM roles (``BR_LLM_MODE=offline``).

They let the full pipeline (and the demo) run reproducibly without a model
endpoint. They get the same structured context the real prompt is built from
and return the same JSON schema. Everything downstream (constraints, Verifier
checks, Trust Score, approvals, execution, rollback) is the real code path.

The planner stand-in deliberately behaves like an ungrounded model on its first
attempt (it batches a redundant switch pair, overloads clusters and repeats a
plausible but false CVE claim) and like a corrected model once it has
feedback. With a live endpoint, the planner is the real model and may or may
not make those mistakes.
"""

from __future__ import annotations

import re
from typing import Any

COMP = r"(?P<component>iLO 6|System ROM|Switch OS)"
VER = r"(?:version\s+|v)?(?P<version>(?:U\d+ v)?\d+(?:\.\d+)+)"


def respond(role: str, ctx: dict) -> dict:
    return {
        "intake": intake,
        "planner": planner,
        "verifier_extract": extract_claims,
        "verifier_judge": judge,
        "report": report,
    }[role](ctx)


# ---------------------------------------------------------------- intake
def intake(ctx: dict) -> dict:
    text = ctx["intent"]
    low = text.lower()
    inv = ctx["inventory"]
    clusters = [c for c in inv["clusters"] if c.lower() in low]
    servers = [s for s in inv["servers"] if re.search(rf"\b{re.escape(s)}\b", low)]
    switches = [s for s in inv["switches"] if re.search(rf"\b{re.escape(s)}\b", low)]
    notes = []
    if not switches and re.search(r"\b(tor|top[- ]of[- ]rack)\b", low):
        for c in clusters:
            pair = inv["cluster_tor_pairs"].get(c, [])
            if pair:
                switches = pair
                notes.append(f"'ToR switch pair' resolved to {', '.join(pair)} (rack of {c}).")
                break
    comps = []
    if "ilo" in low:
        comps.append("iLO 6")
    if re.search(r"\b(rom|bios|system rom)\b", low):
        comps.append("System ROM")
    if switches:
        comps.append("Switch OS")
    day = next((d for d in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday") if d.lower() in low), "Saturday")
    start = "22:00"
    m = re.search(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b", low)
    if m:
        h = int(m.group(1)) % 12 + (12 if m.group(3) == "pm" else 0)
        start = f"{h:02d}:{m.group(2) or '00'}"
    dur = 480
    m = re.search(r"(\d+)\s*[- ]?(?:hour|hr)", low)
    if m:
        dur = int(m.group(1)) * 60
    tgt = ", ".join(clusters + servers + switches) or "no recognised targets"
    return {
        "summary": f"Upgrade {' and '.join(comps) or 'firmware'} to the {('latest' if 'latest' in low else 'requested')} baseline on {tgt}",
        "target_clusters": clusters,
        "target_servers": servers,
        "target_switches": switches,
        "components": comps or ["iLO 6", "System ROM"],
        "baseline": "latest",
        "window": {"day": day, "start": start, "duration_minutes": dur},
        "notes": notes,
    }


# --------------------------------------------------------------- planner
def planner(ctx: dict) -> dict:
    if ctx["attempt"] == 1 and ctx.get("naive_first", True):
        return _naive_plan(ctx)
    return _grounded_plan(ctx)


def _naive_plan(ctx: dict) -> dict:
    servers = ctx["target_servers"]
    switches = ctx["target_switches"]
    by_cluster: dict[str, list[str]] = {}
    for s in servers:
        by_cluster.setdefault(ctx["server_cluster"][s], []).append(s)
    first = [v[0] for v in by_cluster.values()]
    rest = {c: [s for s in v if s not in first] for c, v in by_cluster.items()}
    waves = [
        {"name": "Wave 1 - network first + canary", "assets": switches + first, "evacuate": []},
        {"name": "Wave 2 - first half of each cluster", "assets": [s for v in rest.values() for s in v[: len(v) // 2]], "evacuate": []},
        {"name": "Wave 3 - second half of each cluster", "assets": [s for v in rest.values() for s in v[len(v) // 2:]], "evacuate": []},
    ]
    biggest = max((sum(1 for a in w["assets"] if ctx["server_cluster"].get(a) == c) for w in waves for c in by_cluster), default=0)
    big_cluster = next(iter(by_cluster), "the cluster")
    tv = ctx["target_versions"]
    sentences = []
    if len(switches) >= 2:
        sentences.append(f"{switches[0]} and {switches[1]} are a redundant pair, so upgrading them together in wave 1 is safe.")
    sentences.append(f"All hosts in {big_cluster} are dual-homed.")
    if tv.get("System ROM"):
        sentences.append(f"System ROM {tv['System ROM'][0]} remediates SYN-CVE-2026-1105, so this upgrade is urgent.")
    if tv.get("iLO 6"):
        sentences.append(f"iLO 6 v{tv['iLO 6'][0]} has no known issues.")
    sentences.append(f"{big_cluster} can tolerate {biggest} hosts in maintenance at once.")
    sentences.append("The plan takes about 120 minutes and fits the window.")
    return {"waves": waves, "rationale": " ".join(sentences), "self_confidence": 91}


def _grounded_plan(ctx: dict) -> dict:
    from .solver import grounded_rationale

    waves = [dict(w, rationale=w.get("rationale", "")) for w in ctx["solver_plan"]]
    text = grounded_rationale(waves, ctx["facts"], ctx["components"], ctx["solver_duration_min"])
    # Models add colour that no tool can confirm; the Verifier should mark it Unverifiable.
    text += " Saturday-night application traffic is expected to be low."
    return {"waves": waves, "rationale": text, "self_confidence": 88}


# -------------------------------------------------------------- verifier
def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]


def extract_claims(ctx: dict) -> dict:
    switches = ctx.get("switch_names", [])
    claims: list[dict[str, Any]] = []
    for s in _sentences(ctx["rationale"]):
        low = s.lower()
        named = [n for n in switches if re.search(rf"\b{re.escape(n)}\b", s)]
        m = re.search(COMP + r"\s+" + VER + r"\s+(?:fixes|remediates|resolves|addresses|patches)\s+(?P<cve>(?:SYN-)?CVE-\d{4}-\d+)", s, re.I)
        if m:
            claims.append({"text": s, "type": "fixes_cve", "args": {"component": m["component"], "version": m["version"], "cve": m["cve"]}})
            continue
        m = re.search(COMP + r"\s+" + VER + r"\s+has no known issues", s, re.I)
        if m:
            claims.append({"text": s, "type": "no_known_issues", "args": {"component": m["component"], "version": m["version"]}})
            continue
        if len(named) >= 2 and re.search(r"different waves|separate waves", low):
            claims.append({"text": s, "type": "pair_staggered", "args": {"a": named[0], "b": named[1]}})
            continue
        if len(named) >= 2 and re.search(r"together|same wave|simultaneous|in parallel", low):
            claims.append({"text": s, "type": "pair_safe_together", "args": {"a": named[0], "b": named[1]}})
            continue
        m = re.search(r"all hosts in (?P<cluster>[\w-]+) are dual-homed", s, re.I)
        if m:
            claims.append({"text": s, "type": "all_dual_homed", "args": {"cluster": m["cluster"]}})
            continue
        m = re.search(r"(?P<server>[a-z][\w-]*\d) is (?P<kind>single|dual)-homed", s, re.I)
        if m:
            claims.append({"text": s, "type": f"{m['kind'].lower()}_homed", "args": {"server": m["server"]}})
            continue
        m = re.search(r"(?P<cluster>[A-Z][\w-]+) can tolerate (?P<hosts>\d+) hosts", s)
        if m:
            claims.append({"text": s, "type": "cluster_capacity", "args": {"cluster": m["cluster"], "hosts": int(m["hosts"])}})
            continue
        m = re.search(r"no wave has more than (?P<hosts>\d+) hosts", s, re.I)
        if m:
            claims.append({"text": s, "type": "per_wave_cap", "args": {"hosts": int(m["hosts"])}})
            continue
        if "canary" in low and re.search(r"no tier-0|without tier-0|no critical", low):
            claims.append({"text": s, "type": "canary_safe", "args": {}})
            continue
        if re.search(r"no wave causes (?:a|any) (?:workload )?outage", low):
            claims.append({"text": s, "type": "no_planned_outage", "args": {}})
            continue
        m = re.search(r"(?:update|upgrade)\s+" + COMP.replace("component", "first") + r"\s+before\s+" + COMP.replace("component", "second"), s, re.I)
        if m:
            claims.append({"text": s, "type": "install_order", "args": {"first": m["first"], "second": m["second"]}})
            continue
        m = re.search(r"about (?P<minutes>\d+) minutes", low) or re.search(r"(?P<hours>\d+(?:\.\d+)?) hours", low)
        if m and "window" in low:
            minutes = int(m["minutes"]) if "minutes" in m.groupdict() and m.groupdict().get("minutes") else int(float(m["hours"]) * 60)
            claims.append({"text": s, "type": "in_window", "args": {"minutes": minutes}})
            continue
        claims.append({"text": s, "type": "freeform", "args": {}})
    return {"claims": claims}


def judge(ctx: dict) -> dict:
    return {
        "label": "Unverifiable",
        "explanation": "No tool output or document in the evidence addresses this statement.",
        "evidence": [],
    }


# ---------------------------------------------------------------- report
def report(ctx: dict) -> dict:
    outcome = ctx["outcome"]
    done = ctx["waves_completed"]
    total = ctx["waves_total"]
    if outcome == "rolled_back":
        executed = ctx["waves_executed"]
        s = (f"Change halted in wave {executed}: post-checks on {', '.join(ctx['regressed_assets'])} showed "
             f"{ctx['regression_summary']}. The wave was rolled back to the previous versions and signals "
             f"{'recovered' if ctx['recovered'] else 'did NOT recover (escalated to on-call)'}. "
             f"{total - executed} remaining wave(s) were not executed.")
        lessons = [ctx["lesson"]] if ctx.get("lesson") else []
    elif outcome == "completed":
        s = f"All {total} waves completed; every post-check passed and no workload lost service."
        lessons = []
    elif outcome == "rejected":
        s = "The operator rejected the plan; nothing was executed."
        lessons = []
    else:
        s = f"Run ended with status '{outcome}' after {done} of {total} waves."
        lessons = []
    return {"summary": s, "lessons": lessons}
