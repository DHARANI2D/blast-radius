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
        "planner_explain": planner_explain,
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
    from .agents.intake import resolve_tor_pair  # the same deterministic rule the Intake agent applies to a live model

    tor = resolve_tor_pair(text, clusters, inv)
    if tor is not None:
        switches, note = tor
        notes.append(note)
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
    if scripted_first_attempt(ctx):
        return _naive_plan(ctx)
    return _grounded_plan(ctx)


def naive_mistakes(ctx: dict) -> list[str]:
    """The mistakes the scripted first draft makes for this change (rule kinds in planner memory)."""
    return (["CLUSTER_CAPACITY", "CANARY_COVERAGE"] + (["REDUNDANT_PAIR"] if len(ctx["target_switches"]) >= 2 else [])
            + (["fixes_cve"] if ctx["target_versions"].get("System ROM") else []))


def scripted_first_attempt(ctx: dict) -> bool:
    """Attempt 1 is the scripted ungrounded draft unless planner memory already warns against its mistakes."""
    from .memory import covers

    return ctx["attempt"] == 1 and ctx.get("naive_first", True) and not covers(ctx.get("memory_rules", []), *naive_mistakes(ctx))


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
    waves = [w for w in waves if w["assets"]]  # a small change leaves the halves empty
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


def planner_explain(ctx: dict) -> dict:
    """Re-explain the optimiser's final waves (same wording a corrected model would use)."""
    from .solver import grounded_rationale

    text = grounded_rationale(ctx["waves"], ctx["facts"], ctx["components"], ctx["total_duration_min"])
    text += " Saturday-night application traffic is expected to be low."
    return {"rationale": text, "self_confidence": 88}


def _grounded_plan(ctx: dict) -> dict:
    from .solver import grounded_rationale

    waves = [dict(w, rationale=w.get("rationale", "")) for w in ctx["solver_plan"]]
    text = grounded_rationale(waves, ctx["facts"], ctx["components"], ctx["solver_duration_min"])
    # Models add colour that no tool can confirm; the Verifier should mark it Unverifiable.
    text += " Saturday-night application traffic is expected to be low."
    return {"waves": waves, "rationale": text, "self_confidence": 88}


# -------------------------------------------------------------- verifier
# A full stop after "incl.", "e.g.", "i.e." or "vs." does not end a sentence.
SENTENCE_END = re.compile(r"(?<!\bincl\.)(?<!\be\.g\.)(?<!\bi\.e\.)(?<!\bvs\.)(?<=[.!?])\s+", re.I)


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in SENTENCE_END.split(text.strip()) if s.strip()]


# Paraphrase support for extract_claims. Each pattern below was added for a phrasing in the
# red-team benchmark's "dev" templates (blastradius/redteam.py); its held-out templates were
# not used. A negated sentence is left untyped (freeform -> Unverifiable) rather than guessed,
# except "never in the same wave", which states that a pair is staggered.
NEGATION = re.compile(r"\b(?:not|never|no longer|cannot|can't|isn't|aren't|doesn't|don't|won't|shouldn't)\b", re.I)
CVE_ID = r"(?P<cve>(?:SYN-)?CVE-\d{4}-\d+)"
FIX_WORD = r"\b(?:fix|remediat|resolv|address|patch)\w*"
CLUSTER_NAME = r"(?P<cluster>[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)"
HOST_NAME = r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)*-\d+\b"  # blr-esx-07; switch names and tier-N are filtered out
DUAL_HOMED = r"dual-homed|(?<!fewer than )(?<!less than )two (?:live )?uplinks|connected to both"
SINGLE_HOMED = r"single-homed|only one (?:live )?uplink|a single (?:tor )?switch|(?:fewer|less) than two (?:live )?uplinks"
TOGETHER = r"together|same wave|same time|simultaneous|in parallel"
CANONICAL_COMPONENTS = {"ilo 6": "iLO 6", "system rom": "System ROM", "switch os": "Switch OS"}


def extract_claims(ctx: dict) -> dict:
    switches = ctx.get("switch_names", [])
    claims: list[dict[str, Any]] = []

    shapes = "|".join(sorted({re.sub(r"\d+", lambda _: r"\d+", re.escape(n)) for n in switches}))

    def comp(name: str) -> str:
        return CANONICAL_COMPONENTS.get(name.lower(), name)

    for s in _sentences(ctx["rationale"]):
        low = s.lower()
        neg = bool(NEGATION.search(s))
        named = [n for n in switches if re.search(rf"\b{re.escape(n)}\b", s)]
        if shapes:  # a name shaped like a known switch (tor-r3-a) is still a switch claim; the checker rejects unknown ones
            named += [x for x in re.findall(rf"\b(?:{shapes})\b", s) if x not in named]
        m = re.search(COMP + r"\s+" + VER + r"\s+(?:fixes|remediates|resolves|addresses|patches)\s+(?P<cve>(?:SYN-)?CVE-\d{4}-\d+)", s, re.I)
        if not m and not neg and re.search(FIX_WORD, low):
            # any order: "The X V update patches CVE", "CVE is fixed in X V"
            mv, mc = re.search(COMP + r"\s+" + VER, s, re.I), re.search(CVE_ID, s, re.I)
            m = {"component": mv["component"], "version": mv["version"], "cve": mc["cve"]} if mv and mc else None
        if m:
            claims.append({"text": s, "type": "fixes_cve", "args": {"component": comp(m["component"]), "version": m["version"], "cve": m["cve"]}})
            continue
        m = re.search(COMP + r"\s+" + VER + r"\s+has no known issues", s, re.I)
        if not m and not neg and re.search(r"\b(?:no|free of) known (?:issues|defects|bugs)\b", low):
            m = re.search(COMP + r"\s+" + VER, s, re.I)
        if m:
            claims.append({"text": s, "type": "no_known_issues", "args": {"component": comp(m["component"]), "version": m["version"]}})
            continue
        if len(named) >= 2 and (re.search(r"different waves?|separate waves?", low) or (neg and re.search(TOGETHER, low))):
            claims.append({"text": s, "type": "pair_staggered", "args": {"a": named[0], "b": named[1]}})
            continue
        if len(named) >= 2 and not neg and re.search(TOGETHER, low):
            claims.append({"text": s, "type": "pair_safe_together", "args": {"a": named[0], "b": named[1]}})
            continue
        m = re.search(r"all hosts in (?P<cluster>[\w-]+) are dual-homed", s, re.I)
        if not m and not neg and re.search(r"\b(?:all|every|each)\b", low) and re.search(r"\bhosts?\b", low) and re.search(DUAL_HOMED, low):
            # "Every host in C has two live uplinks", "C hosts are all dual-homed" (any case)
            m = (re.search(CLUSTER_NAME, s) or re.search(r"\b(?:in|of)\s+(?P<cluster>[a-z][\w-]*\d)\b", s, re.I)
                 or re.search(r"(?P<cluster>\b[a-z][\w-]*\d)\s+hosts\b", s, re.I))
        if m:
            claims.append({"text": s, "type": "all_dual_homed", "args": {"cluster": m["cluster"]}})
            continue
        m = re.search(r"(?P<server>[a-z][\w-]*\d) is (?P<kind>single|dual)-homed", s, re.I)
        if m:
            claims.append({"text": s, "type": f"{m['kind'].lower()}_homed", "args": {"server": m["server"]}})
            continue
        hosts = [h for h in re.findall(HOST_NAME, s, re.I) if h.lower() not in switches and not h.lower().startswith("tier-")]
        if hosts and not neg and not re.search(r"\b(?:all|every|each|hosts)\b", low):  # plural: a cluster-level claim
            kind = "dual" if re.search(DUAL_HOMED, low) else "single" if re.search(SINGLE_HOMED, low) else None
            if kind:  # "h has two live uplinks", "h depends on a single ToR switch"
                claims.append({"text": s, "type": f"{kind}_homed", "args": {"server": hosts[0]}})
                continue
        m = re.search(r"(?P<cluster>[A-Z][\w-]+) can tolerate (?P<hosts>\d+) hosts", s)
        if not m and not neg and "wave" not in low and re.search(r"tolerate|absorb|capacity|can be in maintenance", low):
            mc, mh = re.search(CLUSTER_NAME, s), re.search(r"(?<![\w-])(?P<hosts>\d+) hosts", low)  # not the 08 of "prod-blr-08 hosts"
            m = {"cluster": mc["cluster"], "hosts": mh["hosts"]} if mc and mh else None
        if m:
            claims.append({"text": s, "type": "cluster_capacity", "args": {"cluster": m["cluster"], "hosts": int(m["hosts"])}})
            continue
        m = re.search(r"no wave has more than (?P<hosts>\d+) hosts", s, re.I)
        if not m and not neg and "wave" in low and "cluster" in low:
            m = re.search(r"\b(?:at most|up to) (?P<hosts>\d+) hosts\b", low)  # "each wave puts at most N hosts per cluster ..."
        if m:
            claims.append({"text": s, "type": "per_wave_cap", "args": {"hosts": int(m["hosts"])}})
            continue
        m = re.search(r"canary covers (?:all|the) (?P<n>\d+)", low)
        if not m and not neg and "canary" in low:
            m = re.search(r"(?<![\w-])(?P<n>\d+)\s+(?:[\w-]+\s+){0,3}?cohorts", low)  # "one host from each of the N configuration cohorts"
        if m:
            claims.append({"text": s, "type": "canary_covers_cohorts", "args": {"cohorts": int(m["n"])}})
            continue
        if "canary" in low and not neg and re.search(r"no tier-0|without tier-0|no critical|avoids? (?:tier-[01]|critical)", low):
            claims.append({"text": s, "type": "canary_safe", "args": {}})
            continue
        if re.search(r"no wave causes (?:a|any) (?:workload )?outage", low) or (
                not neg and re.search(r"\bno (?:wave|workload|vm)s?\b|\bnone of the (?:waves|workloads|vms)\b", low)
                and re.search(r"outage|loses? service", low)):
            claims.append({"text": s, "type": "no_planned_outage", "args": {}})
            continue
        m = re.search(r"(?:update|upgrade)\s+" + COMP.replace("component", "first") + r"\s+before\s+" + COMP.replace("component", "second"), s, re.I)
        if not m and not neg:  # "A must be updated before B", "A is flashed first, then B"
            m = re.search(COMP.replace("component", "first") + r"\b.*?\b(?:before|first,? then)\b.*?" + COMP.replace("component", "second"), s, re.I)
        if m and comp(m["first"]) != comp(m["second"]):
            claims.append({"text": s, "type": "install_order", "args": {"first": comp(m["first"]), "second": comp(m["second"])}})
            continue
        m = re.search(r"(?:about|roughly) (?P<minutes>\d+) minutes", low) or re.search(r"(?P<hours>\d+(?:\.\d+)?) hours", low)
        if m and "window" in low:
            minutes = int(m["minutes"]) if "minutes" in m.groupdict() and m.groupdict().get("minutes") else int(float(m["hours"]) * 60)
            claims.append({"text": s, "type": "in_window", "args": {"minutes": minutes}})
            continue
        claims.append({"text": s, "type": "freeform", "args": {}})
    return {"claims": claims}


ENTITY = re.compile(r"[A-Za-z0-9]+(?:[-.][A-Za-z0-9]+)+|[A-Za-z]*\d[A-Za-z0-9]*")


def judge(ctx: dict) -> dict:
    """Offline stand-in for the LLM judge: a lexical grounding check against the evidence the
    sentence cites. Every identifier, version and number in the sentence must appear in a cited
    tool output; otherwise Unverifiable. It never answers Contradicted (that needs semantics)."""
    cited = ctx.get("cited") or []
    if not cited:
        return {"label": "Unverifiable",
                "explanation": "No tool output or document in the evidence addresses this statement.", "evidence": []}
    text = re.sub(r"\[EV-\d{4}(?:,\s*EV-\d{4})*\]", "", ctx["claim"])
    entities = {t for t in ENTITY.findall(text) if not re.fullmatch(r"EV-\d{4}|tier-\d", t, re.I) and len(t) > 1}
    blob = " ".join(c["result"] for c in cited)
    missing = sorted(t for t in entities if t.lower() not in blob.lower())
    ids = [c["id"] for c in cited]
    if entities and not missing:
        return {"label": "Supported", "evidence": ids,
                "explanation": f"lexical grounding (offline judge): every identifier and number ({', '.join(sorted(entities)[:6])}) "
                               f"appears in the cited tool output {', '.join(ids)}."}
    return {"label": "Unverifiable", "evidence": ids,
            "explanation": "lexical grounding (offline judge): the cited evidence does not mention "
                           + (", ".join(missing[:5]) if missing else "any checkable identifier in this sentence") + "."}


# ---------------------------------------------------------------- report
def report(ctx: dict) -> dict:
    outcome = ctx["outcome"]
    done = ctx["waves_completed"]
    total = ctx["waves_total"]
    if ctx.get("outcome_reason"):
        s = f"{ctx['outcome_reason'][:1].upper()}{ctx['outcome_reason'][1:]}. No change was planned or executed."
        lessons = []
    elif ctx.get("halt_reason"):
        executed = ctx["waves_executed"]
        s = (f"Change halted in wave {ctx['halted_wave']}: {ctx['halt_reason']}. "
             + ("The partial wave was rolled back to the previous versions and signals "
                f"{'recovered' if ctx['recovered'] else 'did NOT recover (escalated to on-call)'}. " if outcome == "rolled_back" else
                f"Writes were blocked, so {ctx['manual_steps']} manual clean-up step(s) are listed in the report. " if ctx.get("manual_steps") else "")
             + f"{total - executed} remaining wave(s) were not executed.")
        lessons = []
    elif outcome == "rolled_back":
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
