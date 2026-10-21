"""BlastRadius Control Tower (Streamlit).

    streamlit run ui/app.py        # or: python -m blastradius ui
"""

from __future__ import annotations

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

from blastradius.cli import DEFAULT_INTENT  # noqa: E402
from blastradius.constraints import wave_impact  # noqa: E402
from blastradius.ledger import Ledger  # noqa: E402
from blastradius.services import Services  # noqa: E402
from blastradius.workflow import Engine  # noqa: E402
from graph_view import build_dot  # noqa: E402

st.set_page_config(page_title="BlastRadius Control Tower", page_icon="💥", layout="wide")

LABEL_ICON = {"Supported": "✅", "Contradicted": "❌", "Unverifiable": "❔"}
LEVEL_ICON = {"info": "🔹", "warn": "🟠", "error": "🔴", "success": "🟢"}

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
def services(transport: str, faults: bool) -> tuple[Services, Engine]:
    key = (transport, faults)
    if st.session_state.get("svc_key") != key:
        os.environ["BR_FAULTS"] = "on" if faults else "off"
        sv = Services.create(tool_transport=transport, faults_enabled=faults)
        st.session_state.update(svc_key=key, sv=sv, engine=Engine(sv), run=None, animated=set())
    return st.session_state.sv, st.session_state.engine


with st.sidebar:
    st.markdown("## 💥 BlastRadius")
    st.caption("Know what breaks before you break it.")
    transport = st.radio("Tool transport", ["mcp", "inproc"], horizontal=True,
                         help="mcp: every agent tool call goes through an MCP client session to the domain MCP server.")
    faults = st.toggle("Inject canary fault", value=True,
                       help="Firmware combination System ROM U54 v2.32 + NIC fw 229.x regresses NIC latency. Agents cannot see this rule.")
    sv, engine = services(transport, faults)
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
        st.rerun()
    if c2.button("New run", help="Keep lessons, restore twin state", width="stretch"):
        sv.reset_lab(forget_lessons=False)
        st.session_state.run = None
        st.rerun()
    kill = st.toggle("Kill switch", value=os.environ.get("BR_KILL_SWITCH") == "on",
                     help="Blocks every write action immediately (checked by the policy guard before each write).")
    os.environ["BR_KILL_SWITCH"] = "on" if kill else "off"
    st.divider()
    st.caption("Synthetic lab digital twin (BLR-POD-1). Firmware, CVE and advisory IDs are fictitious. No customer data.")

run = st.session_state.get("run")
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
        st.session_state.run = engine.start(intent)
        st.session_state.animated = set()
        s.update(label=f"Analysis complete in {time.time() - t0:.1f}s · {sv.bus.calls} tool calls", state="complete")
    st.rerun()
b2.caption("Example: *Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair to the latest baseline this Saturday 10pm*")

if not run:
    st.info("Enter a change intent and press **Analyse change**. BlastRadius builds a live dependency graph across compute, "
            "network, virtualization and storage, plans canary waves, verifies every claim against tool evidence, and "
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
m[0].metric("Status", status_label)
m[1].metric("Trust Score", f"{ver.get('trust_score', 0):.0f}/100",
            delta=f"self-reported {ver.get('self_confidence')}" if ver.get("self_confidence") is not None else None, delta_color="off")
m[2].metric("Max Blast-Radius Score", f"{cons.get('max_brs', 0):.0f}")
m[3].metric("Plan attempts", len(state.get("attempts", [])))
m[4].metric("Est. outage avoided", f"${state['avoided_cost_usd'] / 1e6:.1f}M" if state.get("avoided_cost_usd") else "-",
            help="Illustrative: assumed 4 h Sev-1 x ITIC 2024 floor of $300K/h (policy.yaml: business).")

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
    tabs = st.tabs(["① Blast radius", "② Plan & Verifier", "③ Go / No-Go", "④ Execution", "⑤ Audit & report"])

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
            choice = st.radio("Overlay", opts, horizontal=True, index=min(1, len(opts) - 1), label_visibility="collapsed")
            impact, overlay, plan_for = None, "none", None
            if choice.startswith("Attempt 1"):
                first = attempts[0]["plan"]["waves"][0]
                impact = wave_impact(first, topo, sv.policy)
                overlay = "impact"
                st.markdown(
                    f"<div class='br-banner-red'><b>{first['name']}</b> ({', '.join(first['assets'])}): "
                    f"{len(impact['impacted_vms'])} VMs lose service incl. tier-0 {', '.join(impact['critical_vms'][:4])}"
                    f"{'...' if len(impact['critical_vms']) > 4 else ''}. "
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
            st.graphviz_chart(build_dot(topo, overlay, plan_for, impact, risk.get("assets"), deferred), width="stretch")
            st.caption("Red outline/edge: single-homed host · dashed red: dead uplink · purple: storage array ports · blue: VSX/MC-LAG peer link · "
                       "dotted amber: tier-0 service placement · dashed grey node: deferred by learned regression")
            if risk.get("assets"):
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
                    st.markdown("**Verifier (independent model, temperature 0)**")
                    k1, k2 = st.columns(2)
                    k1.metric("Planner self-confidence", v["self_confidence"] if v["self_confidence"] is not None else "-")
                    k2.metric("Verified Trust Score", f"{v['trust_score']:.0f}",
                              delta=(f"{v['trust_score'] - v['self_confidence']:+.0f} vs self-report" if v["self_confidence"] is not None else None))
                    if v["blocked_by"]:
                        st.markdown(f"<div class='br-banner-red'>Blocked: {'; '.join(v['blocked_by'])}</div>", unsafe_allow_html=True)
                st.markdown("**Claims extracted from the planner's rationale**")
                cdf = pd.DataFrame([{"": LABEL_ICON[x["label"]], "claim": x["text"], "verdict": x["label"], "why": x["explanation"],
                                     "evidence": ", ".join(x["evidence"])} for x in v["claims"]])
                st.dataframe(cdf, hide_index=True, width="stretch")
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
            st.markdown("**Top risks**")
            for r in card["top_risks"][:4]:
                st.markdown(f"- `{r['asset']}` risk {r['score']}: {'; '.join(r['reasons'])}")
            st.markdown(f"**Rollback plan:** {card['rollback_plan']}")
            with st.expander("Claims and evidence"):
                for c in card["claims"]:
                    st.markdown(f"{LABEL_ICON[c['label']]} {c['text']} <span class='br-tag'>({', '.join(c['evidence'])})</span>", unsafe_allow_html=True)
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
            for i, w in enumerate(plan["waves"], 1):
                ex = next((e for e in execs if e["index"] == i), None)
                if ex is None:
                    s = "⏸ not run" if state.get("status") in ("rolled_back", "halted", "rejected", "stopped_after_canary") else "⏳ pending"
                elif ex.get("result") == "passed":
                    s = "✅ passed"
                else:
                    s = "↩️ rolled back" if state.get("rollback") else "❌ regression"
                status_rows.append({"wave": w["name"], "assets": len(w["assets"]), "status": s,
                                    "actions": len(ex["actions"]) if ex else 0, "VMs migrated": ex["migrated_vms"] if ex else 0})
            st.dataframe(pd.DataFrame(status_rows), hide_index=True, width="stretch")
            if execs:
                ex = execs[0] if not state.get("rollback") else execs[-1]
                st.markdown(f"##### Live golden signals · {ex['name']} · NIC latency (ms)")
                st.caption("Gaps = host in maintenance (evacuated, flashing, rebooting). Threshold: 2x the pre-change baseline.")
                frames = []
                for asset, pts in ex["series"].items():
                    if state.get("rollback") and asset in state["rollback"].get("series", {}):
                        pts = pts + state["rollback"]["series"][asset]
                    for pt in pts:
                        frames.append({"t (min)": pt["t_min"], "asset": asset, "latency": pt["value"]})
                df = pd.DataFrame(frames).drop_duplicates(["t (min)", "asset"]).pivot(index="t (min)", columns="asset", values="latency").sort_index()
                ph = st.empty()
                key = (run["run_id"], ex["index"])
                if key not in st.session_state.animated:
                    for n in range(3, len(df) + 1, 2):
                        ph.line_chart(df.iloc[:n], height=240)
                        time.sleep(0.06)
                    st.session_state.animated.add(key)
                ph.line_chart(df, height=240)
                regs = [r for e in execs for r in e.get("regressions", [])]
                if regs:
                    st.markdown("<div class='br-banner-red'><b>Auto-halt.</b> " + "; ".join(f"{r['asset']}: {r['message']}" for r in regs)
                                + ". Remaining waves cancelled; write access revoked.</div>", unsafe_allow_html=True)
                if state.get("rollback"):
                    rb = state["rollback"]
                    st.markdown(f"<div class='{'br-banner-green' if rb['recovered'] else 'br-banner-red'}'><b>Rollback:</b> "
                                + ", ".join(f"{x['asset']} {x['component']} → {x['to']}" for x in rb["reverted"])
                                + f". Signals {'recovered' if rb['recovered'] else 'NOT recovered'}.</div>", unsafe_allow_html=True)
                if state.get("avoided_cost_usd"):
                    st.metric("Estimated outage avoided", f"${state['avoided_cost_usd']:,.0f}",
                              help="4 h x $300K/h (ITIC 2024 floor). Illustrative assumption from policy.yaml, not a measurement.")
                if state.get("lesson"):
                    les = state["lesson"]
                    st.markdown(f"<div class='br-banner-amber'><b>Learned {les['id']}:</b> {les['symptom']} {les['lesson']} "
                                "Press <b>New run</b> and analyse again: affected hosts are now deferred.</div>", unsafe_allow_html=True)

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
                led = Ledger(tmp)
                victim = next((e for e in entries if e["event"] == "approval"), entries[0])
                led.tamper(victim["seq"], {**victim["payload"], "approver": "mallory"})
                v = led.verify()
                st.error(f"Edited entry {victim['seq']} ({victim['event']}) in a copy: chain BROKEN at seq {v['broken_at']}.")
