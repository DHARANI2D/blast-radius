"""Fill the official HPE hackathon abstract template with the BlastRadius abstract.

    python scripts/build_abstract.py      # writes docs/abstract/BlastRadius_Abstract.docx

Edit the CONTENT section below and re-run. The template's headings, styles, header,
footer and placeholder lines keep its exact format; only its instructions and empty
spacer paragraphs are removed (to stay within 4 pages).
"""

from __future__ import annotations

import copy
import re
from pathlib import Path

import docx
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.opc.constants import CONTENT_TYPE as CT
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.opc.packuri import PackURI
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.parts.numbering import NumberingPart
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs" / "abstract" / "template.docx"
OUT = ROOT / "docs" / "abstract" / "BlastRadius_Abstract.docx"
REPO = "https://github.com/DHARANI2D/blast-radius"

# ============================================================== CONTENT
TITLE = "BlastRadius: Agentic Change-Safety Mesh for HPE Hybrid Infrastructure"

ABSTRACT = (
    "Configuration and change-management failures cause 41% of major network-related outages and 51% of major IT "
    "system/software outages (Uptime Institute 2026), and over 90% of mid-size and large enterprises put one hour of "
    "downtime above $300,000 (ITIC 2024). BlastRadius is a LangGraph multi-agent system, connected through the Model "
    "Context Protocol (MCP), that turns any firmware or configuration upgrade into a verified, staged and reversible "
    "operation. Agents build a live dependency graph across HPE compute, network, virtualization and storage, score risk "
    "from release notes, advisories, incidents and simulated downstream exposure, and propose canary waves that a "
    "risk-aware optimiser re-orders. Deterministic constraints and an independent Verifier, measured on a red-team "
    "benchmark, check every wave and every factual claim against tool evidence, so plans built on hallucinations never "
    "execute. After human sign-off, waves roll out with pre/during/post checks against fixed thresholds and un-upgraded "
    "peers, automatic rollback and learning, all recorded in a hash-chained ledger, as a governed agent for HPE GreenLake Intelligence."
)

CONTEXT = [
    "A ProLiant host runs a Morpheus or VMware cluster, hangs off a pair of Aruba CX or Juniper QFX top-of-rack switches "
    "and reaches an Alletra array over the same fabric, yet firmware, iLO, BIOS, switch OS and hypervisor upgrades are "
    "planned per tool and per team. HPE tools validate their own domain well (Compute Ops Management, Marvis Actions, "
    "Apstra), while OpsRamp RCA and Zerto rewind act after the fact. No agent "
    "answers the operator's real question before the change: *\"If I push this firmware to 40 servers and two ToR switches "
    "tonight, what else breaks, and can I trust the AI's answer?\"* As agentic AI starts to execute changes, an ungrounded "
    "plan can push a correlated failure faster than a human can stop it.",
]

WHY = [
    "**Top outage cause:** change/configuration failure drives 41% of major network and 51% of major IT system/software "
    "outages (Uptime Institute 2026); 87% of operators say better process or configuration would have prevented theirs (Uptime 2025).",
    "**Expensive:** over 90% of mid-size and large enterprises put hourly downtime above $300K, 41% at $1M-$5M+ (ITIC 2024).",
    "**Agentic risk:** Gartner predicts that by 2029 at least 70% of organizations with production agentic AI in I&O will "
    "have a material incident linked partly to insufficient runtime controls. BlastRadius *is* that runtime control.",
]

OVERVIEW_INTRO = (
    "An operator, a change ticket or an upstream copilot (over A2A) states a change in plain language "
    "(*\"Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair to the latest "
    "baseline this Saturday 10pm\"*). BlastRadius **discovers** the cross-domain dependency graph, **assesses** per-asset "
    "risk and downstream exposure, **plans, optimises and verifies** canary waves (code rejects unsafe waves; the Verifier "
    "rejects unsupported claims), asks a human to **approve** a one-page go/no-go card, then **executes and validates** "
    "wave by wave, rolling back automatically on regression and learning from it."
)
OVERVIEW: list[str] = []

INNOVATION = [
    "**Cross-domain, before the change:** one graph joins compute, network, virtualization and storage. In the PoC the "
    "storage array hangs only off the rack-R1 ToR pair, so rebooting both R1 switches would also cut the *other* cluster's datastores.",
    "**Verifier-gated autonomy, measured:** each planner sentence becomes an atomic claim checked by code that fetches its "
    "own MCP evidence (release notes, LLDP, capacity, re-simulation); other claims go to an LLM judge (ideally a separate "
    "model) that may only cite retrieved evidence. A contradiction or an unverifiable *safety* claim blocks the plan. Red-team benchmark (166 "
    "labelled claims, 22 mutation operators): 93/97 false claims contradicted, the rest flagged, 0 dangerous misses, "
    "0 false blocks; 21/21 unsafe plan mutations rejected.",
    "**LLM proposes, code disposes:** redundancy, capacity, canary, window and deferral rules are code, with a deterministic "
    "solver as fallback. A simulated-annealing optimiser moves the riskiest assets (ToR switches, the single-homed host) "
    "to the last waves, the result is re-verified, and the human signs that exact plan hash. A Monte Carlo pre-mortem puts "
    "P(tier-0 outage) per wave on the go/no-go card.",
    "**Cohort canary, statistical judge, provable diagnosis:** the canary holds one host per configuration cohort (model + "
    "untouched firmware), not the lowest-risk hosts, which here would miss the fault. A Mann-Whitney test against "
    "un-upgraded peers catches a 1.3x regression the 2x rule misses and ignores a fleet-wide backup slowdown; "
    "per-component probes and same-model controls pin the culprit.",
    "**Learns from both kinds of failure:** rollback lessons defer exactly the affected hosts; rejected plans become "
    "planner-memory rules retrieved for the next similar change.",
]

BUSINESS = [
    "**Avoided cost, replayed on the twin:** a risk-ranked canary passes the fault and wave 2 degrades payments-db until "
    "minute 66: about **$64K** (13.2 degraded VM-hours, a tier-0 Sev-1) vs $458 with BlastRadius, at illustrative "
    "rates (policy.yaml). Cross-check: one avoided 4-hour Sev-1 at ITIC's $300K/hour floor is $1.2M.",
    "**Operator time:** hours of cross-team impact analysis become a verified 42-asset plan in about 3 s of compute "
    "offline (target under 5 minutes end to end with a hosted LLM).",
    "**HPE levers:** stickier GreenLake Intelligence, a reason to run compute, network and virtualization on HPE, a \"safe "
    "autonomy\" answer to Gartner, fewer support escalations.",
    "**Roadmap:** P1 twin -> P2 Q1 2027 HPE IT pilot (read-only COM/Central/Mist) -> P3 GreenLake Intelligence agent "
    "with ServiceNow CAB, Zerto, Apstra -> P4 AI factories.",
]

ARCH_TEXT = ("A checkpointed LangGraph state machine orchestrates ten agents. Agents see the estate only through five MCP "
             "servers shaped like Compute Ops Management, Aruba Central/Mist, Morpheus and OpsRamp; every tool call is stored "
             "as citable evidence. HPE's GreenLake devices MCP server (gl-mcp) attaches read-only; an A2A endpoint and "
             "\"Ask BlastRadius\" answer questions from read-only tools.")

HOW = [
    "**Intake:** the LLM turns the intent into a typed change request (unknown names dropped).",
    "**Discover:** 7 MCP calls build a 563-node, 1,652-edge graph; LLDP exposes a single-homed host.",
    "**Assess:** release notes, advisories, incidents and learned regressions plus simulated single-asset failure; the ToR "
    "the single-homed payments-DB host depends on scores 79/100.",
    "**Plan and optimise:** the Planner, given memory rules from past rejections, proposes waves and a cohort-covering "
    "canary; constraints, VM-by-VM evacuation and per-wave Blast-Radius Scores are computed in code; the optimiser re-orders "
    "within the same constraints.",
    "**Verify:** Trust = 100 x evidence-weighted support - 15 per contradiction; under 80 or any contradiction means re-plan "
    "with feedback, then solver fallback, then escalation.",
    "**Approve:** LangGraph interrupt; HMAC-signed approval (1 signer canary, 2 distinct signers fleet) grants scoped write tokens.",
    "**Execute:** evacuate hosts, start switch upgrades, check dependents *during* the reboot, flash iLO then ROM (canary: "
    "probe after each component), soak.",
    "**Post-validate, learn:** thresholds (latency, drops, CRC, health, reachability, VM heartbeats) plus the peer test; "
    "on regression halt, revoke, revert, confirm recovery, report and learn.",
]

STACK = [
    "**LLMs (HPE-approved only):** OpenAI-compatible endpoint (NVIDIA NIM on HPE Private Cloud AI or the ChatHPE/GenAI Hub "
    "gateway) or Azure OpenAI with function calling; Verifier at temperature 0, ideally on a "
    "separate model; offline stand-ins for a reproducible demo.",
    "**Frameworks:** LangGraph 1.x, MCP Python SDK 2.x (5 servers, 26 tools), A2A JSON-RPC, NetworkX, BM25 retrieval, "
    "pure-Python statistics, annealing and Monte Carlo, Pydantic, YAML policy, SQLite ledger, Streamlit, Docker; 203 pytest tests.",
]

RAI = (
    "**Responsible AI and governance:** one signer for the canary and two distinct signers for the fleet, nothing written "
    "unsigned; every claim links to evidence or defaults to Unverifiable, contradictions block; write allow-list, approved "
    "scope, rate limit and kill switch in code; tamper-evident hash-chained ledger; synthetic data, secrets redacted before "
    "prompts; the A2A endpoint and Ask BlastRadius are read-only."
)

DEMO = [
    f"**Code:** {REPO} · **Video:** [Brightidea link]",
    "**PoC (twin of one Bangalore pod: 40 ProLiant Gen11, 504 VMs, 2 ToR pairs, Alletra):** the naive plan puts both VSX "
    "members in wave 1 (504 VMs incl. payments-db lose service; Trust 0 vs. self-reported 91; a false CVE claim contradicted); "
    "the optimised re-plan scores Trust 98, covers all 3 configuration cohorts, pre-mortem tier-0 risk 0.75% (naive: 100%). "
    "A 3.9x NIC-latency regression on a NIC-229.x host (Mann-Whitney p = 4.4e-16 vs 15 peers) auto-halts and rolls back; the "
    "next run defers exactly the 16 affected hosts and its first draft passes. Execution is simulated; twin IDs are fictitious.",
]

REFERENCES = [
    "HPE press releases: unified agentic IT operations with GreenLake and Morpheus (June 17, 2026); self-driving networks (June 16, 2026).",
    "HPE Compute Ops Management; HewlettPackard/gl-mcp; MCP specification; Linux Foundation A2A (April 9, 2026).",
    "Uptime Institute outage analysis 2026 and survey 2025; ITIC 2024 hourly cost of downtime.",
    "Gartner, \"Agentic AI Fails Where Governance Stops\" (Sept 2026); AI in I&O Hype Cycle 2026.",
    "Open source (OSS_DISCLOSURE.md): LangGraph, MCP SDK, Pydantic, PyYAML (MIT); NetworkX, pandas, Altair (BSD-3); Streamlit (Apache-2.0).",
]


# ============================================================== BUILDING
def _numbering(document) -> dict[str, int]:
    """Add one bullet and two decimal list definitions; return their numIds."""
    try:
        numbering = document.part.numbering_part.element
    except NotImplementedError:  # template has no numbering part; python-docx cannot create one itself
        part = NumberingPart(PackURI("/word/numbering.xml"), CT.WML_NUMBERING,
                             parse_xml(f'<w:numbering {nsdecls("w")}/>'), document.part.package)
        document.part.relate_to(part, RT.NUMBERING)
        numbering = part.element
    defs = {"bullet": ("bullet", "•"), "steps1": ("decimal", "%1."), "steps2": ("decimal", "%1.")}
    ids = {}
    for i, (key, (fmt, text)) in enumerate(defs.items(), start=101):
        numbering.append(parse_xml(
            f'<w:abstractNum {nsdecls("w")} w:abstractNumId="{i}"><w:multiLevelType w:val="singleLevel"/>'
            f'<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="{fmt}"/><w:lvlText w:val="{text}"/>'
            f'<w:lvlJc w:val="left"/><w:pPr><w:ind w:left="360" w:hanging="270"/></w:pPr>'
            "</w:lvl></w:abstractNum>"))
    for i, key in enumerate(defs, start=101):
        numbering.append(parse_xml(f'<w:num {nsdecls("w")} w:numId="{i}"><w:abstractNumId w:val="{i}"/></w:num>'))
        ids[key] = i
    # abstractNum elements must precede num elements
    abstracts = [e for e in numbering if e.tag == qn("w:abstractNum")]
    for e in abstracts:
        numbering.remove(e)
    for k, e in enumerate(abstracts):
        numbering.insert(k, e)
    return ids


def _add_runs(p, text: str) -> None:
    for part in re.split(r"(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)", text):
        if not part:
            continue
        if part.startswith("**"):
            p.add_run(part[2:-2]).bold = True
        elif part.startswith("`"):
            r = p.add_run(part[1:-1])
            r.font.name = "Consolas"
            r.font.size = Pt(9.5)
        elif part.startswith("*"):
            p.add_run(part[1:-1]).italic = True
        else:
            p.add_run(part)


def _new_par_after(anchor, style: str):
    new = OxmlElement("w:p")
    anchor._p.addnext(new)
    par = docx.text.paragraph.Paragraph(new, anchor._parent)
    par.style = style
    return par


def _write(anchor, items: list[str], style="Normal", num_id: int | None = None, space_after: int | None = None):
    last = anchor
    for t in items:
        p = _new_par_after(last, style)
        if num_id:
            pPr = p._p.get_or_add_pPr()
            pPr.append(parse_xml(f'<w:numPr {nsdecls("w")}><w:ilvl w:val="0"/><w:numId w:val="{num_id}"/></w:numPr>'))
            p.paragraph_format.space_after = Pt(3)
        elif space_after is not None:
            p.paragraph_format.space_after = Pt(space_after)
        _add_runs(p, t)
        last = p
    return last


def _hyperlink_text(p, url: str) -> None:
    """Turn the first occurrence of url inside paragraph p into a hyperlink."""
    for r in p.runs:
        if url in r.text:
            before, after = r.text.split(url, 1)
            r.text = before
            rid = p.part.relate_to(url, RT.HYPERLINK, is_external=True)
            h = OxmlElement("w:hyperlink")
            h.set(qn("r:id"), rid)
            nr = copy.deepcopy(r._r)
            for t in nr.findall(qn("w:t")):
                nr.remove(t)
            t = OxmlElement("w:t")
            t.text = url
            t.set(qn("xml:space"), "preserve")
            nr.append(t)
            rpr = nr.get_or_add_rPr()
            rpr.append(parse_xml(f'<w:color {nsdecls("w")} w:val="0563C1"/>'))
            rpr.append(parse_xml(f'<w:u {nsdecls("w")} w:val="single"/>'))
            h.append(nr)
            r._r.addnext(h)
            if after:
                tail = copy.deepcopy(r._r)
                for t in tail.findall(qn("w:t")):
                    tail.remove(t)
                tt = OxmlElement("w:t")
                tt.text = after
                tt.set(qn("xml:space"), "preserve")
                tail.append(tt)
                h.addnext(tail)
            return


def _set_text(p, text: str) -> None:
    for r in list(p.runs):
        r._r.getparent().remove(r._r)
    _add_runs(p, text)


def _delete(p) -> None:
    p._p.getparent().remove(p._p)


def find(d, text: str, style: str | None = None):
    for p in d.paragraphs:
        if text in p.text and (style is None or p.style.name == style):
            return p
    raise KeyError(text)


def build() -> Path:
    d = docx.Document(str(TEMPLATE))
    nums = _numbering(d)

    # title (the Team Members line is left exactly as the template has it, for the team to fill in)
    _set_text(d.paragraphs[0], TITLE)

    # abstract
    hint = find(d, "Summarise the entire proposal")
    _write(hint, [ABSTRACT])
    _delete(hint)

    # 1. problem statement
    _delete(find(d, "Describe the real HPE business"))
    p = find(d, "Describe the current process")
    _write(p, CONTEXT)
    _delete(p)
    p = find(d, "Quantify the impact")
    _write(p, WHY, num_id=nums["bullet"])
    _delete(p)

    # 2. proposed solution
    _delete(find(d, "Present your AI concept"))
    p = find(d, "Describe your solution and how")
    last = _write(p, [OVERVIEW_INTRO])
    if OVERVIEW:
        _write(last, OVERVIEW, num_id=nums["steps1"])
    _delete(p)
    p = find(d, "Explain what makes this approach")
    _write(p, INNOVATION, num_id=nums["bullet"])
    _delete(p)
    p = find(d, "Estimate the value delivered")
    _write(p, BUSINESS, num_id=nums["bullet"])
    _delete(p)

    # 3. implementation
    _delete(find(d, "Detail the technical design"))
    # the template formats this sub-heading by hand (a Normal paragraph), so it keeps that formatting
    find(d, "Technical Architecture").paragraph_format.keep_with_next = True
    p = find(d, "Outline the data flow")
    pic = _new_par_after(p, "Normal")
    pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pic.paragraph_format.space_after = Pt(2)
    pic.add_run().add_picture(str(ROOT / "docs" / "img" / "architecture.png"), width=Inches(5.5))
    cap = _new_par_after(pic, "Normal")
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = cap.add_run("Figure 1. BlastRadius architecture: LangGraph supervisor, agents, MCP tool layer and governance controls.")
    r.italic = True
    r.font.size = Pt(8.5)
    r.font.color.rgb = RGBColor(0x59, 0x59, 0x59)
    _write(cap, [ARCH_TEXT])
    _delete(p)
    p = find(d, "Step-by-Step functional walkthrough")
    _write(p, HOW, num_id=nums["steps2"])
    _delete(p)
    p = find(d, "List your LLMs/models")
    # the template has no Responsible AI section, so it is the last Technology Stack bullet
    _write(p, STACK + [RAI], num_id=nums["bullet"])
    _delete(p)

    p = find(d, "Provide links to your GitHub")
    _write(p, DEMO, num_id=nums["bullet"])
    _delete(p)
    _hyperlink_text(find(d, REPO), REPO)

    # 4. references
    _delete(find(d, "List papers, tools, datasets"))
    # same paragraph format as the template's "• [Reference N]" lines
    refs = [p for p in d.paragraphs if p.text.startswith("\u2022 [Reference")]
    last = refs[-1]
    for t in REFERENCES:
        new = copy.deepcopy(refs[0]._p)
        last._p.addnext(new)
        last = docx.text.paragraph.Paragraph(new, last._parent)
        _set_text(last, "\u2022 " + t)
    for p in refs:
        _delete(p)

    # drop the template's empty spacer paragraphs (keeps the 4-page limit)
    for p in list(d.paragraphs):
        if not p.text.strip() and not p._p.findall(".//" + qn("w:drawing")):
            _delete(p)
    # never strand a heading at the bottom of a page
    for p in d.paragraphs:
        if p.style.name.startswith("Heading"):
            p.paragraph_format.keep_with_next = True

    d.core_properties.title = TITLE
    d.core_properties.subject = "HPE Agentic AI Hackathon India 2026 - Track 3"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    d.save(str(OUT))
    return OUT


if __name__ == "__main__":
    print(f"wrote {build()}")
