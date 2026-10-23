"""BlastRadius Control Tower (Streamlit).

    streamlit run ui/app.py        # or: python -m blastradius ui
"""

from __future__ import annotations

import html
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from blastradius.agents.investigator import InvestigatorAgent  # noqa: E402
from blastradius.cli import DEFAULT_INTENT  # noqa: E402
from blastradius.config import Settings  # noqa: E402
from blastradius.constraints import wave_impact  # noqa: E402
from blastradius.ledger import Ledger  # noqa: E402
from blastradius.llm import LLMError  # noqa: E402
from blastradius.services import Services  # noqa: E402
from blastradius.workflow import Engine  # noqa: E402
from graph_view import build_dot  # noqa: E402

st.set_page_config(page_title="BlastRadius Control Tower", page_icon="💥", layout="wide")

LABEL_ICON = {"Supported": "✅", "Contradicted": "❌", "Unverifiable": "❔"}
LEVEL_ICON = {"info": "🔹", "warn": "🟠", "error": "🔴", "success": "🟢"}
ANIMATION_FRAMES = 12  # live-signal chart frames, once per run

st.markdown(
    """
    <style>
      .block-container {padding-top: 2.6rem;}
      .br-tag {font-size: 0.8rem; color: #64748b;}
      .br-banner-red {background:#fee2e2;border-left:6px solid #dc2626;padding:0.6rem 0.9rem;border-radius:6px;color:#7f1d1d;}
      .br-banner-green {background:#dcfce7;border-left:6px solid #16a34a;padding:0.6rem 0.9rem;border-radius:6px;color:#14532d;}
      .br-banner-amber {background:#fef3c7;border-left:6px solid #d97706;padding:0.6rem 0.9rem;border-radius:6px;color:#78350f;}
      @media (prefers-color-scheme: dark) {
        .br-banner-red {background:#450a0a;color:#fecaca;}
        .br-banner-green {background:#052e16;color:#bbf7d0;}
        .br-banner-amber {background:#451a03;color:#fde68a;}
      }
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------------ session
def services(transport: str, scenario: str) -> tuple[Services, Engine]:
    key = (transport, scenario)
    if st.session_state.get("svc_key") != key:
        old = st.session_state.get("sv")
        if old is not None:
            old.bus.close()  # stop the old MCP event-loop thread
        sv = Services.create(tool_transport=transport, fault_scenario=scenario)
        st.session_state.update(svc_key=key, sv=sv, engine=Engine(sv), run=None, animated=set())
        clear_run_views()
    return st.session_state.sv, st.session_state.engine


def clear_run_views() -> None:
    """Forget per-run results (red-team injection, Ask history) when the run they belong to goes away."""
    for k in ("inj", "qa"):
        st.session_state.pop(k, None)


def verifier_label(sv: Services) -> str:
    """How independent the Verifier really is: a separate model only when BR_VERIFIER_MODEL names a different one."""
    p, v = sv.llm.model, sv.verifier_llm.model
    if sv.settings.offline:
        return f"independent agent, temperature 0 · offline stand-in `{v}`"
    if sv.settings.verifier_model and sv.settings.verifier_model != sv.settings.llm_model:
        return f"independent agent, temperature 0 · separate model `{v}` (planner `{p}`)"
    return f"independent agent, temperature 0 · same model as the planner (`{v}`), separate prompt"


SCENARIOS = {"on": "Canary regression (ROM + NIC 229.x, ~4x)", "subtle": "Subtle regression (~1.3x, below the 2x rule)",
             "backup": "Backup job slows every host (no fault)", "on+backup": "Regression during the backup job",
             "subtle+backup": "Subtle regression during the backup job", "off": "No faults"}
TRANSPORTS = ["mcp", "inproc"]
# Defaults follow BR_TOOL_TRANSPORT and BR_FAULTS, read once per session.
if "defaults" not in st.session_state:
    _s = Settings()
    st.session_state.defaults = (_s.tool_transport if _s.tool_transport in TRANSPORTS else "mcp",
                                 _s.fault_scenario if _s.fault_scenario in SCENARIOS else "on")

run = st.session_state.get("run")
# A run waiting at a gate (or executing) belongs to the current twin and transport: switching
# either would re-seed the twin and drop the run without a report, so the controls lock.
in_flight = bool(run and (run.get("interrupt") or run.get("state", {}).get("status") in ("executing", "rolling_back")))

with st.sidebar:
    st.markdown("## 💥 BlastRadius")
    st.caption("Know what breaks before you break it.")
    d_transport, d_scenario = st.session_state.defaults
    transport = st.radio("Tool transport", TRANSPORTS, index=TRANSPORTS.index(d_transport), horizontal=True, disabled=in_flight,
                         help="mcp: every agent tool call goes through an MCP client session to the domain MCP server.")
    scenario = st.selectbox("Fault scenario", list(SCENARIOS), index=list(SCENARIOS).index(d_scenario), format_func=SCENARIOS.get,
                            disabled=in_flight,
                            help="Injected into the twin. Agents cannot see these rules; they only observe telemetry.")
    if in_flight:
        st.caption("Locked while a change is in flight: finish it (approve, reject or Close change), or press New run, "
                   "before switching transport or fault scenario.")
    sv, engine = services(transport, scenario)
    desc = sv.bus.describe()
    st.markdown(f"**MCP servers:** {', '.join(desc['servers'])}  \n**Tools:** {len(desc['tools'])} ({len(desc['write_tools'])} write, token-gated)")
    st.markdown(f"**Planner:** `{sv.llm.model}`  \n**Verifier:** `{sv.verifier_llm.model}`")
    if sv.settings.offline:
        st.caption("Offline mode: deterministic LLM stand-ins. Set BR_LLM_MODE/BR_LLM_BASE_URL for an HPE-approved endpoint.")
    st.divider()
    lessons = len(sv.kb.learned)
    st.markdown(f"**Learned incidents:** {lessons}")
    c1, c2 = st.columns(2)
    if c1.button("Reset lab", help="Restore the twin and forget learned incidents", width="stretch"):
        sv.reset_lab(forget_lessons=True)
        st.session_state.run = None
        clear_run_views()
        st.rerun()
    if c2.button("New run", help="Keep lessons, restore twin state", width="stretch"):
        sv.reset_lab(forget_lessons=False)
        st.session_state.run = None
        clear_run_views()
        st.rerun()
    kill = st.toggle("Kill switch", value=os.environ.get("BR_KILL_SWITCH") == "on",
                     help="Blocks every write action immediately (checked by the policy guard before each write).")
    os.environ["BR_KILL_SWITCH"] = "on" if kill else "off"
    with st.expander("HPE GreenLake MCP (gl-mcp)"):
        from blastradius.greenlake import doctor

        rep = doctor(sv.settings)
        st.markdown(("🟢 ready" if rep.get("ready") else "⚪ not ready") + f" · transport: {rep.get('transport') or 'not configured'}")
        for k, v in (rep.get("env") or {}).items():
            st.caption(f"{k}: {v}")
        for prob in rep.get("problems", [])[:4]:
            st.caption(f"• {prob}")
        st.caption("Read-only device inventory from HPE's devices MCP server. See the README for setup.")
    st.divider()
    st.caption("Synthetic lab digital twin (BLR-POD-1). Firmware, CVE and advisory IDs are fictitious. No customer data.")

run = st.session_state.get("run")  # New run / Reset lab may have cleared it above
state = (run or {}).get("state", {})
intr = (run or {}).get("interrupt")

# ------------------------------------------------------------------ header
st.markdown("### Change-Safety Control Tower")
intent = st.text_area("Change intent", value=state.get("intent", DEFAULT_INTENT), height=68, label_visibility="collapsed")
b1, b2 = st.columns([1, 5])
if b1.button("Analyse change", type="primary", width="stretch"):
    sv.twin.reset()
    with st.status("Agents at work: intake, topology, risk, planner, verifier...", expanded=False) as s:
        t0 = time.time()
        clear_run_views()
        st.session_state.run = engine.start(intent)
        st.session_state.animated = set()
        s.update(label=f"Analysis complete in {time.time() - t0:.1f}s · {sv.bus.calls} tool calls", state="complete")
    st.rerun()
b2.caption("Example: *Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair to the latest baseline this Saturday 10pm*")

if not run:
    st.info("Enter a change intent and press **Analyse change**. BlastRadius builds a dependency graph from MCP tool calls "
            "across compute, network, virtualization and storage, plans canary waves, verifies every claim against tool evidence, and "
            "only executes after a human approves.")
    st.stop()

ver = state.get("verification") or (state.get("attempts") or [{}])[-1].get("verification", {})
cons = state.get("constraints") or (state.get("attempts") or [{}])[-1].get("constraints", {})
m = st.columns(5)
STATUS = {"awaiting_canary_approval": "go / no-go", "executing": "executing", "rolled_back": "rolled back",
          "completed": "completed", "rejected": "rejected", "halted": "halted", "escalated": "escalated",
          "stopped_after_canary": "stopped", "rolling_back": "rolling back", "analysing": "analysing"}
status_label = STATUS.get(state.get("status"), (state.get("status") or "-").replace("_", " "))
if intr and intr.get("scope") == "fleet":
    status_label = "canary passed"
elif intr and intr.get("scope") == "escalation":
    status_label = "escalated"
m[0].metric("Status", status_label)
if state.get("verification"):  # the accepted plan's score
    m[1].metric("Trust Score", f"{ver.get('trust_score', 0):.0f}/100",
                delta=f"self-reported {ver.get('self_confidence')}" if ver.get("self_confidence") is not None else None, delta_color="off")
else:  # no plan was accepted: the score belongs to a rejected attempt, not to anything that can run
    m[1].metric("Trust Score (last rejected attempt)", f"{ver['trust_score']:.0f}/100" if ver.get("trust_score") is not None else "-")
m[2].metric("Max Blast-Radius Score", f"{cons.get('max_brs', 0):.0f}")
m[3].metric("Plan attempts", len(state.get("attempts", [])))
avoided = state.get("avoided_cost_usd")
m[4].metric("Est. cost avoided (illustrative)", "-" if avoided is None else f"${avoided / 1e3:,.1f}K" if avoided >= 1000 else f"${avoided:,.0f}",
            help="Replayed on the twin: what the conventional risk-ranked canary would have cost minus what happened, "
                 "at illustrative rates (policy.yaml: business). '-' means no replay ran. See tab ④.")

main, side = st.columns([3.2, 1.3], gap="medium")

with side:
    st.markdown("#### Agent timeline")
    box = st.container(height=640)
    for e in state.get("timeline", []):
        box.markdown(f"{LEVEL_ICON.get(e['level'], '🔹')} **{e['agent']}** · {e['detail']}")

topo = sv.runs.get(run["run_id"], {}).get("topo")
risk = state.get("risk", {})
attempts = state.get("attempts", [])

with main:
    tabs = st.tabs(["① Blast radius", "② Plan & Verifier", "③ Go / No-Go", "④ Execution", "⑤ Audit & report", "⑥ Ask"])

    # --------------------------------------------------------- blast radius
    with tabs[0]:
        if topo is None:
            st.warning("Dependency graph not available for this run.")
        else:
            opts = ["Hidden dependencies"]
            if attempts:
                opts.append("Attempt 1 · wave 1 impact")
            if state.get("plan"):
                opts.append("Approved plan · waves")
            opts.append("Risk heat")
            # Open on attempt 1's outage when it was rejected; when it passed, on the plan that will run.
            default = "Attempt 1 · wave 1 impact" if attempts and not attempts[0].get("passed") else "Approved plan · waves"
            choice = st.radio("Overlay", opts, horizontal=True, index=opts.index(default) if default in opts else 0,
                              label_visibility="collapsed")
            impact, overlay, plan_for = None, "none", None
            first = (attempts[0]["plan"]["waves"] or [None])[0] if attempts else None
            if choice.startswith("Attempt 1") and first is None:
                st.info("Attempt 1 has no waves.")
            elif choice.startswith("Attempt 1"):
                impact = wave_impact(first, topo, sv.policy)
                overlay = "impact"
                lost, crit = impact["impacted_vms"], impact["critical_vms"]
                st.markdown(
                    f"<div class='{'br-banner-red' if lost or impact['arrays_unreachable'] else 'br-banner-green'}'>"
                    f"<b>{first['name']}</b> ({', '.join(first['assets'])}): "
                    + (f"{len(lost)} VMs lose service" if lost else "no VMs lose service")
                    + (f" incl. tier-0 {', '.join(crit[:4])}{'...' if len(crit) > 4 else ''}" if crit else "") + ". "
                    + (f"Storage array {', '.join(impact['arrays_unreachable'])} is reachable only through the R1 ToR pair, so "
                       f"{len(impact['storage_lost_servers'])} hosts in the other cluster lose their datastores. " if impact['arrays_unreachable'] else "")
                    + f"Blast-Radius Score <b>{impact['brs']:.0f}</b>.</div>", unsafe_allow_html=True)
            elif choice.startswith("Approved"):
                overlay, plan_for = "waves", state["plan"]
                st.markdown("<div class='br-banner-green'>Colour = wave. Redundant peers never share a wave; the single-homed host "
                            "rides with the switch it depends on.</div>", unsafe_allow_html=True)
            elif choice == "Risk heat":
                overlay = "risk"
            else:
                sh = topo.single_homed()
                if sh:
                    s0 = sh[0]
                    st.markdown(f"<div class='br-banner-amber'><b>Hidden dependency:</b> {s0['server']} is single-homed to "
                                f"{', '.join(s0['up_links'])}; {', '.join(s0['dead_ports'])} is {s0['note']}. It hosts "
                                f"{', '.join(v['name'] for v in topo.vms_on(s0['server']) if v['tier'] == 0) or 'no tier-0 VMs'}.</div>",
                                unsafe_allow_html=True)
            deferred = {d["asset"] for d in risk.get("deferred", [])}
            st.graphviz_chart(build_dot(topo, overlay, plan_for, impact, risk.get("assets"), deferred,
                                        high_risk=float(sv.policy.get("planning.high_risk_threshold", 70))), width="stretch")
            st.caption("Red outline/edge: single-homed host · dashed red: dead uplink · purple: storage array ports · blue: VSX/MC-LAG peer link · "
                       "dotted amber: tier-0 service placement · dashed grey node: deferred by learned regression")
            if risk.get("assets"):
                gl = (state.get("topology") or {}).get("greenlake") or {}
                if gl.get("enabled") and gl.get("ok"):
                    st.markdown(f"**GreenLake inventory:** {gl.get('devices_seen', 0)} devices seen, {gl.get('matched_twin_servers', 0)} matched to "
                                f"twin servers over {gl.get('pages', '?')} page(s)." + (f" {gl['note']}" if gl.get("note") else ""))
                elif gl.get("enabled"):
                    st.warning(f"GreenLake enrichment failed (discovery continued without it): {gl.get('error')}")
                st.markdown("##### Risk & Advisory agent")
                rows = [{"asset": a, "kind": r["kind"], "risk": r["score"], "deferred": "yes" if r["blocked"] else "",
                         "why": " · ".join(r["reasons"][:3]), "evidence": ", ".join(r["evidence"][:4])}
                        for a, r in sorted(risk["assets"].items(), key=lambda kv: -kv[1]["score"])]
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=260,
                             column_config={"risk": st.column_config.ProgressColumn("risk", min_value=0, max_value=100, format="%d")})

    # ------------------------------------------------------------ plans
    with tabs[1]:
        for a in attempts:
            v, c, p = a["verification"], a["constraints"], a["plan"]
            ok = a.get("passed")
            head = f"Attempt {a['attempt']} · {a['provenance']} · {'ACCEPTED' if ok else 'BLOCKED'}"
            with st.expander(head, expanded=True):
                l, r = st.columns([1.1, 1])
                with l:
                    st.markdown("**Constraint checker (deterministic code)**")
                    if c["ok"]:
                        st.markdown("<div class='br-banner-green'>All hard constraints satisfied.</div>", unsafe_allow_html=True)
                    for x in c["violations"][:8]:
                        st.markdown(f"🚫 `{x['code']}` {x['message']}")
                    if len(c["violations"]) > 8:
                        st.caption(f"... and {len(c['violations']) - 8} more")
                    wdf = pd.DataFrame([{"wave": i["name"], "assets": len(w["assets"]), "BRS": i["brs"], "VMs lost": len(i["impacted_vms"]),
                                         "VMs migrated": i["migrated_vms"], "min": i["duration_min"]}
                                        for w, i in zip(p["waves"], c["impacts"])])
                    st.dataframe(wdf, hide_index=True, width="stretch",
                                 column_config={"BRS": st.column_config.ProgressColumn("BRS", min_value=0, max_value=100, format="%.0f")})
                with r:
                    st.markdown(f"**Verifier** · {verifier_label(sv)}")
                    k1, k2 = st.columns(2)
                    k1.metric("Planner self-confidence", v["self_confidence"] if v["self_confidence"] is not None else "-")
                    k2.metric("Verified Trust Score", f"{v['trust_score']:.0f}",
                              delta=(f"{v['trust_score'] - v['self_confidence']:+.0f} vs self-report" if v["self_confidence"] is not None else None))
                    if v["blocked_by"]:
                        st.markdown(f"<div class='br-banner-red'>Blocked: {'; '.join(v['blocked_by'])}</div>", unsafe_allow_html=True)
                    vd = a.get("verification_draft")
                    if vd:  # the planner's own rationale for its draft waves, before the optimiser re-sequenced them
                        st.caption(f"Planner's draft rationale (before optimisation): Trust Score {vd['trust_score']:.0f}"
                                   + (f"; blocked: {'; '.join(vd['blocked_by'])}" if vd["blocked_by"] else ""))
                        for x in [x for x in vd["claims"] if x["label"] == "Contradicted"][:4]:
                            st.markdown(f"{LABEL_ICON[x['label']]} {x['text']} - {x['explanation']}")
                st.markdown("**Claims extracted from the planner's rationale**")
                cdf = pd.DataFrame([{"": LABEL_ICON[x["label"]], "claim": x["text"], "verdict": x["label"], "why": x["explanation"],
                                     "evidence": ", ".join(x["evidence"])} for x in v["claims"]])
                st.dataframe(cdf, hide_index=True, width="stretch")
                opt = a.get("optimization")
                if opt:
                    b, af = opt["before"], opt["after"]
                    st.markdown(f"**Risk-aware wave optimizer** · {opt['status'].replace('_', ' ')} · "
                               f"objective J {b['J']:.0f} → {af['J']:.0f}" + (f" ({(af['J'] - b['J']) / b['J'] * 100:+.0f}%)" if b["J"] else "") + ", "
                               f"{opt['stats']['iterations']} iterations in {opt['stats']['elapsed_s']:.1f}s"
                               + (" (stopped by the time cap: this plan depends on machine speed)" if opt["stats"].get("stopped_by") == "time_budget" else "")
                               + ". The Verifier above checked the optimised waves.")
                    st.dataframe(pd.DataFrame([{"": "before", **{k: b[k] for k in ("waves", "duration_min", "sum_brs", "max_brs", "exposure", "J")}},
                                               {"": "after", **{k: af[k] for k in ("waves", "duration_min", "sum_brs", "max_brs", "exposure", "J")}}]),
                                 hide_index=True, width="stretch")
                    moved = [c for c in opt["changes"] if c["weight"] >= 1]
                    if moved:
                        st.caption("Moved later so more of the plan is proven first: " + "; ".join(
                            f"{c['asset']} wave {c['from_wave']} → {c['to_wave']} ({c['validated_before_pct'][0]:.0f}% → "
                            f"{c['validated_before_pct'][1]:.0f}% validated before it)" for c in moved[:4]))
        ms = sv.memory.stats()
        with st.expander(f"Planning memory: {ms['rules']} rules learned from rejected plans · first-attempt pass rate "
                         f"{ms['first_attempt_pass_rate'] if ms['runs'] else '-'} over {ms['runs']} run(s)"):
            st.caption(f"With memory: {ms['with_memory']['first_attempt_pass_rate']} · without: {ms['without_memory']['first_attempt_pass_rate']}. "
                       "Reset lab forgets these rules; New run keeps them.")
            for r in sorted(sv.memory.rules(), key=lambda r: -r["hits"])[:15]:
                st.markdown(f"- `{r['hits']}x` **{r['key']}**: {r['guidance']}")
        with st.expander("Red-team benchmark: how do we know the Trust Score works?"):
            extractor = "offline"
            if not sv.settings.offline:  # live mode: the deployed extractor can be benchmarked too, at a price
                extractor = st.radio("Claim extractor", ["offline", "configured"], horizontal=True, key="rt-extractor",
                                     format_func={"offline": "offline extractor (about 5 s)",
                                                  "configured": f"configured `{sv.verifier_llm.model}` (about 2,000 model calls)"}.get)
            if st.button("Run benchmark (about 5 s)" if extractor == "offline" else "Run benchmark", key="rt-run"):
                from blastradius.redteam import run_benchmark

                with st.spinner("Generating labelled false claims and unsafe plan mutations..."):
                    st.session_state.redteam = (extractor, run_benchmark(sv, seed=7, extractor=extractor))
            used, rt = st.session_state.get("redteam") or (None, None)
            if rt:
                h = rt["headline"]
                st.caption(f"Measured with the {used} extractor `{rt['extractor']}`"
                           + (", not the deployed model." if used == "offline" and not sv.settings.offline else "."))
                k = st.columns(4)
                k[0].metric("False claims contradicted", f"{h['typed_caught']}/{h['typed_false']}",
                            help=f"95% CI {h['typed_catch_ci'][0]:.0%}-{h['typed_catch_ci'][1]:.0%}")
                k[1].metric("Dangerous misses", h["typed_dangerous_misses"])
                k[2].metric("False blocks on true claims", f"{h['typed_false_blocks']}/{h['typed_true']}")
                k[3].metric("Unsafe plan mutations rejected", f"{h['plan_mutations_detected']}/{h['plan_mutations']}")
                st.caption(f"Paraphrase robustness of the claim extractor `{rt['extractor']}`: canonical {h['extraction_canonical']:.0%}, "
                           f"dev {h['extraction_dev']:.0%}, held-out {h['extraction_held_out']:.0%}" + (" (a live model extractor is the fix). " if used == "offline" else ". ")
                           + 
                           f"Injected hallucinations caught: {h['injections_caught']}/{h['injections']}.")
                from blastradius.redteam import format_markdown

                st.download_button("Download full report (Markdown)", format_markdown(rt), file_name="blastradius-redteam.md")
            if state.get("plan") and topo is not None:
                from blastradius.redteam import HALLUCINATION_KINDS, verify_injected

                c1, c2 = st.columns([2, 1])
                kind = c1.selectbox("Inject a labelled hallucination into the accepted plan's rationale", HALLUCINATION_KINDS)
                if c2.button("Inject and verify", width="stretch"):
                    try:
                        st.session_state.inj = verify_injected(sv, state["plan"], state["change_request"], topo, state["risk"], kind)
                    except ValueError as exc:
                        st.session_state.inj = {"error": str(exc)}
                inj = st.session_state.get("inj")
                if inj and "error" in inj:
                    st.warning(inj["error"])
                elif inj:
                    st.markdown(f"🧪 **Injected (red-team test, not planner output):** \"{inj['sentence']}\"  \n"
                                f"Verifier: **{inj['label']}** · plan {'blocked' if inj['plan_blocked'] else 'NOT blocked'} · "
                                f"Trust {inj['trust']:.0f}")
        with st.expander("Evidence viewer (every tool call is citable)"):
            ids = [e["id"] for e in sv.evidence.all()]
            if ids:
                pick = st.selectbox("Evidence ID", ids[::-1])
                e = sv.evidence.get(pick)
                st.markdown(f"`{e['agent']}` called `{e['tool']}` with `{json.dumps(e['args'])}`")
                txt = json.dumps(e["result"], indent=1, default=str)
                st.code(txt[:6000] + ("\n...(truncated)" if len(txt) > 6000 else ""), language="json")

    # ------------------------------------------------------------ approval
    with tabs[2]:
        if intr and intr.get("scope") in ("canary", "fleet"):
            card = intr
            st.markdown(f"#### Go / No-Go: {'plan + canary wave' if card['scope'] == 'canary' else 'fleet waves'}")
            st.caption(f"Plan `{card['plan_hash'][:16]}` · {card['plan_provenance']} · requires **{card['required_approvers']}** approver(s)")
            k = st.columns(4)
            k[0].metric("Trust Score", f"{card['trust_score']:.0f}")
            k[1].metric("Max BRS", f"{card['max_brs']:.0f}")
            k[2].metric("Duration", f"{card['total_duration_min']} min")
            k[3].metric("Deferred", len(card["deferred"]))
            for w in card.get("warnings") or []:
                st.markdown(f"<div class='br-banner-amber'><b>Warning:</b> {w}</div>", unsafe_allow_html=True)
            cov, rr = card.get("canary_coverage"), card.get("risk_ranked_coverage")
            if cov and card["scope"] == "canary":
                canary = card["waves"][0]["assets"] if card["waves"] else []
                cmp = ""
                if rr:
                    cmp = (f" A risk-ranked canary ({', '.join(rr['canary'])}) would cover {rr['covered']}/{rr['total']} "
                           f"({rr['hosts_represented']}/{rr['hosts_total']} hosts)"
                           + (": untested " + "; ".join(m["label"] for m in rr["missing"]) if rr["missing"] else "") + ".")
                st.markdown(f"<div class='{'br-banner-green' if cov['ok'] else 'br-banner-red'}'><b>Canary coverage:</b> "
                            f"{', '.join(canary)} covers <b>{cov['covered']}/{cov['total']}</b> configuration cohorts "
                            f"({cov['hosts_represented']}/{cov['hosts_total']} hosts represented).{cmp}</div>", unsafe_allow_html=True)
                with st.expander("Configuration cohorts (model + firmware the change does not touch)"):
                    st.dataframe(pd.DataFrame([{"cohort": c["label"], "hosts": c["size"], "canary host": ", ".join(c["canary"]) or "-"}
                                               for c in cov["cohorts"]]), hide_index=True, width="stretch")
            if card.get("canary_result"):
                cr = card["canary_result"]
                st.markdown(f"<div class='br-banner-green'>Canary {', '.join(cr['assets'])}: <b>{cr['result']}</b>; "
                            f"{cr['checked']} signal sets within thresholds; {cr['migrated_vms']} VMs live-migrated.</div>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"wave": w["name"], "assets": ", ".join(w["assets"]), "evacuate": ", ".join(w["evacuate"]),
                                        "BRS": w["brs"], "min": w["duration_min"]} for w in card["waves"]]),
                         hide_index=True, width="stretch")
            if card["deferred"]:
                st.markdown(f"<div class='br-banner-amber'><b>{len(card['deferred'])} host(s) deferred</b> by a learned regression: "
                            f"{card['deferred'][0]['reason']}</div>", unsafe_allow_html=True)
            pm = card.get("premortem")
            if pm:
                st.markdown("**Pre-mortem** · Monte Carlo over failure assumptions (*assumption-driven, not measured*)")
                k = st.columns(4)
                k[0].metric("P(tier-0 outage)", f"{pm['p_tier0_loss']:.2%}")
                k[1].metric("Attributable to change", f"{pm['p_tier0_loss_attributable']:.2%}")
                k[2].metric("Expected VMs lost", f"{pm['expected_vms_lost']:.2f}")
                first = next((r for r in (card.get("premortem_compare") or []) if r["plan"] == "attempt 1"), None)
                k[3].metric("Attempt 1 draft", f"{first['p_tier0_loss']:.0%}" if first else "-")
                st.dataframe(pd.DataFrame([{"wave": w["name"], "P(tier-0 loss)": f"{w['p_tier0_loss']:.3%}",
                                            "most likely": w.get("top_scenario"), "most severe": w.get("worst_scenario")}
                                           for w in pm["waves"]]), hide_index=True, width="stretch")
                with st.expander("Pre-mortem assumptions"):
                    st.json(pm.get("assumptions", {}))
            st.markdown("**Top risks**")
            for r in card["top_risks"][:4]:
                st.markdown(f"- `{r['asset']}` risk {r['score']}: {'; '.join(r['reasons'])}")
            st.markdown(f"**Rollback plan:** {card['rollback_plan']}")
            with st.expander("Claims and evidence"):
                for c in card["claims"]:
                    st.markdown(f"{LABEL_ICON[c['label']]} {c['text']} <span class='br-tag'>({', '.join(c['evidence'])})</span>", unsafe_allow_html=True)
            if state.get("approval_error"):
                st.error(f"Not signed: {state['approval_error']}")
            with st.form(f"approve_{card['scope']}"):
                names = [st.text_input(f"Approver {i + 1}", value=["asha.ops", "ravi.net"][i] if i < 2 else "")
                         for i in range(card["required_approvers"])]
                comment = st.text_input("Comment", value="")
                ca, cb = st.columns(2)
                approve = ca.form_submit_button("Approve and sign", type="primary", width="stretch")
                reject = cb.form_submit_button("Reject", width="stretch")
            if approve or reject:
                payload = {"decision": "approve" if approve else "reject", "approver": names[0], "approvers": names, "comment": comment}
                with st.spinner("Executing approved wave(s) through policy-guarded MCP write tools..."):
                    st.session_state.run = engine.resume(run["run_id"], payload)
                st.rerun()
        elif intr and intr.get("scope") == "escalation":
            st.error("No plan passed constraints and verification. Escalated to a human.")
            st.json(intr["feedback"])
            if st.button("Close change"):
                st.session_state.run = engine.resume(run["run_id"], {"decision": "abort", "approver": "operator"})
                st.rerun()
        else:
            if state.get("approvals"):
                st.markdown("**Signed approvals**")
                st.dataframe(pd.DataFrame([{"scope": a["scope"], "approver": a["approver"], "decision": a["decision"],
                                            "plan": a["plan_hash"][:12], "signature (HMAC-SHA256)": a["signature"][:24] + "..."}
                                           for a in state["approvals"]]), hide_index=True, width="stretch")
            else:
                st.info("No approval pending.")

    # ----------------------------------------------------------- execution
    with tabs[3]:
        execs = state.get("executions", [])
        plan = state.get("plan")
        if not plan:
            st.info("Nothing executed yet.")
        else:
            status_rows = []
            rolled_back = bool(state.get("rollback")) and not state["rollback"].get("blocked")
            for i, w in enumerate(plan["waves"], 1):
                ex = next((e for e in execs if e["index"] == i), None)
                if ex is None:
                    s = "⏸ not run" if state.get("status") in ("rolled_back", "halted", "rejected", "stopped_after_canary") else "⏳ pending"
                elif ex.get("result") == "passed":
                    s = "✅ passed"
                elif ex.get("result") == "halted":
                    s = "↩️ halted, rolled back" if rolled_back else "⛔ halted part-way"
                else:
                    s = "↩️ rolled back" if rolled_back else "❌ regression"
                status_rows.append({"wave": w["name"], "assets": len(w["assets"]), "status": s,
                                    "actions": len(ex["actions"]) if ex else 0, "VMs migrated": ex["migrated_vms"] if ex else 0})
            st.dataframe(pd.DataFrame(status_rows), hide_index=True, width="stretch")
            if state.get("halt_reason"):
                st.markdown(f"<div class='br-banner-red'><b>Halted:</b> {html.escape(state['halt_reason'])}</div>", unsafe_allow_html=True)
                if state.get("manual_steps"):
                    st.markdown("**Manual clean-up (writes are blocked)**\n" + "\n".join(f"{i}. {x}" for i, x in enumerate(state["manual_steps"], 1)))
            if execs and any(e.get("series") for e in execs):
                ex = execs[0] if not state.get("rollback") else execs[-1]
                st.markdown(f"##### Live golden signals · {ex['name']} · NIC latency (ms)")
                st.caption("Gaps = host in maintenance (evacuated, flashing, rebooting). Threshold: 2x the pre-change baseline.")
                frames = []
                for asset, pts in (ex.get("series") or {}).items():
                    if state.get("rollback") and asset in state["rollback"].get("series", {}):
                        pts = pts + state["rollback"]["series"][asset]
                    for pt in pts:
                        frames.append({"t (min)": pt["t_min"], "asset": asset, "latency": pt["value"]})
                if not frames:  # e.g. a wave with no servers: nothing was sampled
                    st.caption("No server telemetry for this wave.")
                else:
                    df = pd.DataFrame(frames).drop_duplicates(["t (min)", "asset"]).pivot(index="t (min)", columns="asset", values="latency").sort_index()
                    ph = st.empty()
                    # Animate once per run, in at most ANIMATION_FRAMES frames, so approving never blocks for long.
                    if run["run_id"] not in st.session_state.animated:
                        st.session_state.animated.add(run["run_id"])
                        step = max(2, -(-len(df) // ANIMATION_FRAMES))
                        for n in range(3, len(df), step):
                            ph.line_chart(df.iloc[:n], height=240)
                            time.sleep(0.03)
                    ph.line_chart(df, height=240)
                regs = [r for e in execs for r in e.get("regressions", [])]
                if regs:
                    st.markdown("<div class='br-banner-red'><b>Auto-halt.</b> " + "; ".join(f"{r['asset']}: {r['message']}" for r in regs)
                                + ". Remaining waves cancelled; write access revoked.</div>", unsafe_allow_html=True)
                if state.get("rollback") and state["rollback"].get("blocked"):
                    st.markdown(f"<div class='br-banner-red'><b>Rollback blocked:</b> {html.escape(state['rollback']['blocked'])}. "
                                "Manual clean-up steps are listed above.</div>", unsafe_allow_html=True)
                elif state.get("rollback"):
                    rb = state["rollback"]
                    st.markdown(f"<div class='{'br-banner-green' if rb['recovered'] else 'br-banner-red'}'><b>Rollback:</b> "
                                + ", ".join(f"{x['asset']} {x['component']} → {x['to']}" for x in rb["reverted"])
                                + f". Signals {'recovered' if rb['recovered'] else 'NOT recovered'}.</div>", unsafe_allow_html=True)
                cs = execs[0].get("canary_stats")
                if cs:
                    st.markdown("##### Statistical canary judge · canary vs un-upgraded peers, same minutes")
                    st.caption("Each host is normalised to its own pre-change median. The band is the 10th-90th percentile of control "
                               "hosts from the same configuration cohort; one-sided Mann-Whitney U, FAIL when p < "
                               f"{cs['params']['alpha']} and the difference-in-differences ratio is at least {cs['params']['min_effect']}x.")
                    k = st.columns(3)
                    k[0].metric("Statistical verdict", cs["verdict"])
                    k[1].metric("Canary score", f"{cs['score']}/100" if cs["score"] is not None else "-")
                    k[2].metric("Checks", len(cs["checks"]))
                    hosts = list(cs.get("band") or {})
                    failing = [h for h in hosts if (cs.get("hosts") or {}).get(h, {}).get("verdict") == "FAIL"]
                    pick = st.radio("Canary host", hosts, index=hosts.index(failing[0]) if failing else 0, horizontal=True,
                                    key=f"band-{run['run_id']}") if hosts else None
                    band = pd.DataFrame(cs["band"].get(pick, {}).get("nic_latency_ms", []) if pick else [])
                    if not band.empty:
                        import altair as alt

                        base = alt.Chart(band).encode(x=alt.X("t_min:Q", title="t (min)"))
                        area = base.mark_area(opacity=0.25, color="#94a3b8").encode(
                            y=alt.Y("control_p10:Q", title="NIC latency, x own pre-change median"), y2="control_p90:Q")
                        med = base.mark_line(strokeDash=[4, 3], color="#64748b").encode(y="control_median:Q")
                        can = base.mark_line(color="#dc2626" if pick in failing else "#2563eb", strokeWidth=2.5).encode(y="canary:Q")
                        st.altair_chart(area + med + can, width="stretch", height=230)
                    st.dataframe(pd.DataFrame([{"host": c["host"], "metric": c["metric"], "verdict": c["verdict"],
                                                "effect (x)": round(c["effect"], 2) if c.get("effect") is not None else None,
                                                "own change": round(c["canary_ratio"], 2) if c.get("canary_ratio") is not None else None,
                                                "peers' change": round(c["control_ratio"], 2) if c.get("control_ratio") is not None else None,
                                                "p": f"{c['p_value']:.1e}" if c.get("p_value") is not None else "",
                                                "controls": f"{c.get('n_control_hosts', 0)} ({c.get('basis')})"}
                                               for c in cs["checks"]]), hide_index=True, width="stretch")
                biz = state.get("business_impact")
                if biz:
                    from blastradius.business import cost_table

                    st.markdown("##### Business impact, replayed on the twin")
                    h = biz["headline"]
                    k = st.columns(4)
                    k[0].metric("Avoided · illustrative rates (policy.yaml)", f"${h['avoided_usd']:,.0f}")
                    k[1].metric("Conventional process", f"${h['counterfactual_usd']:,.0f}",
                                help="Risk-ranked canary on the greedy wave order, replayed on the twin.")
                    k[2].metric("What happened", f"${h['actual_usd']:,.0f}")
                    opt = biz.get("with_optimised_order")
                    missed = bool(opt) and (opt.get("detected_wave") or 0) > 1
                    k[3].metric("Optimised order alone", f"${opt['counterfactual_usd']:,.0f}" if missed else "-",
                                help="If the canary had missed it but the risk-aware ordering had been used."
                                     + ("" if missed else " Not applicable: a risk-ranked canary would also have caught it."))
                    st.caption(h["text"])
                    st.dataframe(pd.DataFrame(cost_table(biz)), hide_index=True, width="stretch")
                    with st.expander("Timeline, exposure, sensitivity and assumptions"):
                        st.write(biz["explanation"])
                        st.dataframe(pd.DataFrame(biz["counterfactual"]["waves"]), hide_index=True, width="stretch")
                        st.dataframe(pd.DataFrame(biz["sensitivity"]), hide_index=True, width="stretch")
                        st.dataframe(pd.DataFrame([{**a, "value": str(a["value"])} for a in biz["assumptions"]]),
                                     hide_index=True, width="stretch")
                if state.get("lesson"):
                    les = state["lesson"]
                    st.markdown(f"<div class='br-banner-amber'><b>Learned {les['id']}:</b> {les['symptom']} {les['lesson']} "
                                "Press <b>New run</b> and analyse again: affected hosts are now deferred.</div>", unsafe_allow_html=True)
                cf = state.get("counterfactual")
                if cf and not cf["risk_ranked_would_catch"] and cf["exposed_hosts"]:
                    st.markdown(f"<div class='br-banner-red'><b>Counterfactual:</b> a risk-ranked canary of the same size "
                                f"({', '.join(cf['risk_ranked_canary'])}; {cf['risk_ranked_cohorts']} cohorts) has no affected host and "
                                f"would have passed. {cf['sentence']}</div>", unsafe_allow_html=True)

    # --------------------------------------------------------------- audit
    with tabs[4]:
        rep = state.get("report")
        if rep:
            st.markdown("##### Signed post-change report")
            text = Path(rep["path"]).read_text() if Path(rep["path"]).exists() else json.dumps(rep, indent=1, default=str)
            st.markdown(text)
            st.download_button("Download report (JSON)", json.dumps({k: v for k, v in rep.items() if k != "path"}, indent=1, default=str),
                               file_name=f"blastradius-{run['run_id']}.json")
        st.markdown("##### Hash-chained audit ledger")
        entries = sv.ledger.entries(run["run_id"])
        st.dataframe(pd.DataFrame([{"seq": e["seq"], "actor": e["actor"], "event": e["event"], "hash": e["hash"][:16],
                                    "prev": e["prev_hash"][:16]} for e in entries]), hide_index=True, width="stretch", height=260)
        c1, c2 = st.columns(2)
        if c1.button("Verify chain", width="stretch"):
            v = sv.ledger.verify()
            (st.success if v["ok"] else st.error)(f"{v['entries']} entries · chain {'intact' if v['ok'] else 'BROKEN at seq ' + str(v['broken_at'])}")
        if c2.button("Simulate tampering (on a copy)", width="stretch"):
            src = Path(sv.ledger.path)
            if src.exists() and entries:
                tmp = Path(tempfile.mkdtemp()) / "ledger-copy.sqlite"
                shutil.copy(src, tmp)
                if Path(f"{src}.anchor").exists():
                    shutil.copy(f"{src}.anchor", f"{tmp}.anchor")
                led = Ledger(tmp, sv.settings.signing_key)
                victim = next((e for e in entries if e["event"] == "approval"), entries[0])
                led.tamper(victim["seq"], {**victim["payload"], "approver": "mallory"})
                v = led.verify()
                st.error(f"Edited entry {victim['seq']} ({victim['event']}) in a copy: chain BROKEN at seq {v['broken_at']}.")

    # ----------------------------------------------------------------- ask
    with tabs[5]:
        st.markdown("##### Ask BlastRadius")
        st.caption("The Investigator answers from read-only MCP tool calls only, cites the evidence for every sentence, and the "
                   "independent Verifier re-checks the answer. "
                   + ("Offline mode: a deterministic router stands in for the model's tool choices."
                      if not sv.llm.supports_tools else f"Tool choice by {sv.llm.model} (function calling)."))
        examples = ["Why is tor-r1-a the riskiest asset?", "Does System ROM U54 v2.32 fix SYN-CVE-2026-1105?",
                    "How many hosts of PROD-BLR-07 can be in maintenance at once?", "Tell me about blr-esx-07"]
        ex_cols = st.columns(len(examples))
        for col, ex in zip(ex_cols, examples):
            if col.button(ex, key=f"ex-{ex}", width="stretch"):
                st.session_state.ask_q = ex
        with st.form("ask"):
            q = st.text_input("Question", value=st.session_state.get("ask_q", examples[0]))
            asked = st.form_submit_button("Ask", type="primary")
        if asked and q.strip():
            with st.spinner("Investigating over MCP..."):
                try:
                    st.session_state.setdefault("qa", []).insert(0, {"q": q, **InvestigatorAgent(sv).ask(q, state, topo)})
                except LLMError as exc:
                    st.error(f"The model call failed, so there is no answer: {exc}")
        for qa in st.session_state.get("qa", [])[:5]:
            v = qa["verification"]
            with st.container(border=True):
                st.markdown(f"**Q:** {qa['q']}")
                st.markdown(f"**A:** {qa['answer']}")
                k = st.columns(3)
                k[0].metric("Answer Trust Score", f"{v['trust_score']:.0f}")
                k[1].metric("Tool calls", len(qa["steps"]))
                k[2].metric("Claims", sum(v["counts"].values()))
                st.caption(f"Tool choice: {qa['mode']} · verifier: {v['verifier_model']}")
                with st.expander("Claims and tool calls"):
                    st.dataframe(pd.DataFrame([{"": LABEL_ICON[c["label"]], "claim": c["text"], "verdict": c["label"], "why": c["explanation"]}
                                               for c in v["claims"]]), hide_index=True, width="stretch")
                    st.dataframe(pd.DataFrame([{"tool": s["tool"], "args": json.dumps(s["args"]), "evidence": s["evidence"]}
                                               for s in qa["steps"]]), hide_index=True, width="stretch")
