"""Intake agent: natural-language change intent -> validated change request."""

from __future__ import annotations

import json
import re

from ..llm import LLMError, load_prompt
from ..models import ChangeRequest

_TOR = r"(?:tor|top[- ]of[- ]rack)"
_TOR_ALL = re.compile(rf"\b(?:all|both|every|each)\s+(?:of\s+)?(?:the\s+)?{_TOR}\b|\b{_TOR}\s+(?:switch\s+)?pairs\b|\b{_TOR}\s+switches\b")


def resolve_tor_pair(intent: str, clusters: list[str], inventory: dict) -> tuple[list[str], str] | None:
    """Deterministic reading of a generic "ToR switch pair" in the intent (offline and live intake agree on it).

    Returns None when the intent does not mention ToR switches generically (or names a switch itself). Otherwise
    the ToR pair(s) serving the named clusters and a note. "pairs", "switches" or "all/both" mean every pair; a
    single "pair" with clusters behind different pairs takes the pair of the cluster named first, and the note
    says which pair was chosen, which was not, and why.
    """
    low = intent.lower()
    if any(re.search(rf"\b{re.escape(s.lower())}\b", low) for s in inventory["switches"]):
        return None
    if not re.search(rf"\b{_TOR}\b", low):
        return None
    order = sorted(clusters, key=lambda c: (low.find(c.lower()) if c.lower() in low else len(low), clusters.index(c)))
    pairs: list[tuple[str, list[str]]] = []
    for c in order:
        pair = inventory["cluster_tor_pairs"].get(c, [])
        if pair and pair not in [p for _, p in pairs]:
            pairs.append((c, pair))
    if not pairs:
        return [], "The intent mentions a ToR switch pair but names no cluster to locate it; no switch was added."
    if len(pairs) == 1:
        c, pair = pairs[0]
        return list(pair), f"'ToR switch pair' resolved to {', '.join(pair)} (rack of {c})."
    if _TOR_ALL.search(low):
        return (sorted(a for _, p in pairs for a in p),
                "ToR switches resolved to every pair serving the named clusters: "
                + "; ".join(f"{'/'.join(p)} ({c})" for c, p in pairs) + ".")
    (c, pair), rest = pairs[0], pairs[1:]
    return list(pair), (
        "Assumption: 'the ToR switch pair' is ambiguous, because the named clusters sit behind different pairs ("
        + "; ".join(f"{x} behind {'/'.join(p)}" for x, p in pairs) + f"). Chose {'/'.join(pair)}, the pair of {c}, "
        "the cluster named first; not included: " + ", ".join(f"{'/'.join(p)} ({x})" for x, p in rest)
        + ". Name the switches to change this.")


class IntakeAgent:
    name = "intake"

    def __init__(self, sv):
        self.sv = sv

    def inventory(self) -> tuple[dict, list[str]]:
        bus = self.sv.bus
        servers, e1 = bus.call(self.name, "compute.list_servers")
        switches, e2 = bus.call(self.name, "network.list_switches")
        clusters, e3 = bus.call(self.name, "virt.list_clusters")
        racks: dict[str, set[str]] = {}
        for s in servers:
            racks.setdefault(s["cluster"], set()).add(s["rack"])
        tor_pairs = {
            c: sorted(sw["name"] for sw in switches if sw["role"] == "tor" and sw["rack"] in rs)
            for c, rs in racks.items()
        }
        inv = {
            "clusters": [c["name"] for c in clusters],
            "cluster_hosts": {c["name"]: c["hosts"] for c in clusters},
            "servers": [s["name"] for s in servers],
            "switches": [s["name"] for s in switches],
            "cluster_tor_pairs": tor_pairs,
        }
        return inv, [e1, e2, e3]

    def run(self, intent: str) -> dict:
        inv, evidence = self.inventory()
        user = json.dumps({"intent": intent, "inventory": {k: inv[k] for k in ("clusters", "servers", "switches", "cluster_tor_pairs")}})
        ctx = {"intent": intent, "inventory": inv}
        fallback = None
        try:
            cr: ChangeRequest = self.sv.llm.complete_json("intake", load_prompt("intake"), user, ChangeRequest, context=ctx, temperature=0.0)
            llm_rec = self.sv.llm.last()
            provenance = "offline stand-in (rule-based parser)" if self.sv.settings.offline else f"llm:{self.sv.llm.model}"
        except LLMError as exc:
            # A model outage must not stop the run before it starts: the deterministic parser reads the
            # intent instead, and the inventory check below still applies to what it finds.
            from ..offline_llm import intake as parse_intent

            cr = ChangeRequest.model_validate(parse_intent(ctx))
            err = str(exc)[:300]
            cr.notes.append(f"Parsed by the deterministic intake parser: the model call failed ({err}).")
            llm_rec = {"role": "intake", "model": self.sv.llm.model, "ok": False, "note": err}
            fallback = {"role": "intake", "error": err, "fallback": "deterministic intake parser"}
            provenance = f"deterministic intake parser (LLM failed: {err})"

        # Never trust names from the model: keep only inventory assets, matched ignoring case and written as the
        # inventory spells them. Dropped names are warnings on the timeline and the go/no-go card.
        notes, warnings, changed = list(cr.notes), [], False
        for field, known in (("target_clusters", inv["clusters"]), ("target_servers", inv["servers"]), ("target_switches", inv["switches"])):
            canon = {k.lower(): k for k in known}
            keep, bad = [], []
            for v in getattr(cr, field):
                c = canon.get(str(v).strip().lower())
                if c is None:
                    bad.append(v)
                elif c not in keep:
                    keep.append(c)
            if bad:
                warnings.append(f"Dropped unknown {field.replace('target_', '')}: {bad}")
            changed |= keep != getattr(cr, field)
            setattr(cr, field, keep)
        tor = resolve_tor_pair(intent, cr.target_clusters, inv)
        if tor is not None:
            switches, note = tor
            changed |= sorted(switches) != sorted(cr.target_switches)
            cr.target_switches = switches
            if note.startswith("Assumption") or not switches:
                warnings.append(note)
            elif note not in notes:
                notes.append(note)
        if cr.target_switches and "Switch OS" not in cr.components:
            cr.components.append("Switch OS")
        cr.notes = notes + [w for w in warnings if w not in notes]
        if changed:
            # The model's summary described other targets; say what will actually be changed.
            named = cr.target_clusters + cr.target_servers + cr.target_switches
            cr.summary = (f"Upgrade {' and '.join(cr.components)} to the {cr.baseline} baseline on "
                          + (", ".join(named) or "no recognised targets"))

        servers = list(cr.target_servers)
        for c in cr.target_clusters:
            servers += [h for h in inv["cluster_hosts"][c] if h not in servers]
        return {
            "change_request": cr.model_dump(),
            "targets": {"servers": sorted(servers), "switches": sorted(cr.target_switches)},
            "warnings": warnings,
            "evidence": evidence,
            "llm": llm_rec,
            "provenance": provenance,
            "llm_fallback": fallback,
        }
