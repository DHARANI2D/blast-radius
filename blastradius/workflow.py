"""LangGraph supervisor: the BlastRadius state machine.

    intake -> discover -> assess -> plan -> verify --(gate fails)--> plan (retry with feedback)
                                              |                     \\-> escalate (human)
                                              v
                                       approve_canary (HITL, 1 approver)
                                              v
                    execute -> postcheck --(regression)--> rollback -> report
                       ^          |
                       |          v
                       +--- approve_fleet (HITL, 2 approvers, once) / next wave
                                  |
                                  v
                               report

Human approvals are LangGraph interrupts; the graph is checkpointed, so the UI or
CLI resumes it with ``Command(resume=...)`` after a person decides.
"""

from __future__ import annotations

import operator
import time
import uuid
from typing import Annotated, Any, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from .agents import (ExecutorAgent, IntakeAgent, PlannerAgent, PostValidationAgent, ReporterAgent, RiskAgent,
                     RollbackAgent, TopologyAgent, VerifierAgent)
from .agents.executor import ExecutionHalted
from .agents.reporter import plan_hash
from .constraints import check_plan
from .llm import LLMError
from .mcp_layer import ToolCallError

WRITE_ACTIONS = ["virt.enter_maintenance", "virt.exit_maintenance", "compute.apply_firmware", "network.upgrade_switch_os"]


class RunState(TypedDict, total=False):
    run_id: str
    intent: str
    change_request: dict
    targets: dict
    topology: dict
    risk: dict
    attempts: list
    plan: dict
    plan_hash: str
    plan_provenance: str
    verification: dict
    constraints: dict
    approvals: list
    executions: list
    current_wave: int
    fleet_approved: bool
    status: str
    halt_reason: str
    rollback: dict
    lesson: dict
    avoided_cost_usd: float
    report: dict
    timeline: Annotated[list, operator.add]


def _t(agent: str, event: str, detail: str, level: str = "info", **data) -> list[dict]:
    return [{"ts": round(time.time(), 3), "agent": agent, "event": event, "detail": detail, "level": level, **data}]


def build_graph(sv):
    intake_a, topo_a, risk_a = IntakeAgent(sv), TopologyAgent(sv), RiskAgent(sv)
    planner_a, verifier_a = PlannerAgent(sv), VerifierAgent(sv)
    exec_a, post_a, rb_a, rep_a = ExecutorAgent(sv), PostValidationAgent(sv), RollbackAgent(sv), ReporterAgent(sv)
    pol = sv.policy

    def topo_of(state):
        return sv.runs[state["run_id"]]["topo"]

    def log(state, actor, event, payload=None):
        sv.ledger.append(state["run_id"], actor, event, payload or {})

    # ----------------------------------------------------------- analysis
    def intake(state: RunState):
        out = intake_a.run(state["intent"])
        log(state, "agent:intake", "change_request", {"change_request": out["change_request"], "llm": out["llm"], "evidence": out["evidence"]})
        t = out["targets"]
        cr = out["change_request"]
        return {"change_request": cr, "targets": t, "status": "analysing", "attempts": [], "approvals": [], "executions": [],
                "timeline": _t("intake", "parsed", f"{cr['summary']}: {len(t['servers'])} servers, {len(t['switches'])} switches; "
                               f"window {cr['window']['day']} {cr['window']['start']} for {cr['window']['duration_minutes']} min")}

    def discover(state: RunState):
        topo, summary = topo_a.run()
        sv.runs.setdefault(state["run_id"], {})["topo"] = topo
        log(state, "agent:topology", "dependency_graph", {k: summary[k] for k in ("nodes", "edges", "by_kind", "redundant_pairs", "single_homed", "evidence")})
        sh = summary["single_homed"]
        detail = (f"{summary['nodes']} nodes / {summary['edges']} edges across compute, network, virtualization and storage; "
                  f"{len(summary['redundant_pairs'])} redundant switch pairs; storage array reachable only via "
                  f"{', '.join(next(iter(summary['storage_paths'].values()), []))}")
        tl = _t("topology", "graph_built", detail)
        if sh:
            tl += _t("topology", "hidden_dependency", "; ".join(f"{s['server']} is single-homed to {', '.join(s['up_links'])} "
                                                                f"({', '.join(s['dead_ports'])} down)" for s in sh), "warn")
        return {"topology": summary, "timeline": tl}

    def assess(state: RunState):
        risk = risk_a.run(state["targets"], state["change_request"]["components"], topo_of(state))
        top = sorted(risk["assets"].values(), key=lambda r: -r["score"])[:5]
        log(state, "agent:risk", "risk_assessment", {"top": [{k: r[k] for k in ("asset", "score", "reasons", "evidence")} for r in top],
                                                     "deferred": risk["deferred"]})
        tl = _t("risk", "scored", "highest risk: " + ", ".join(f"{r['asset']} {r['score']}" for r in top[:3]))
        if risk["deferred"]:
            tl += _t("risk", "deferred", f"{len(risk['deferred'])} asset(s) deferred: {risk['deferred'][0]['reason']}", "warn")
        return {"risk": risk, "timeline": tl}

    # -------------------------------------------------------------- plan
    def plan(state: RunState):
        attempts = list(state.get("attempts", []))
        n = len(attempts) + 1
        max_n = int(pol.get("planning.max_plan_attempts", 2))
        feedback = attempts[-1]["feedback"] if attempts else None
        cr, targets, risk, topo = state["change_request"], state["targets"], state["risk"], topo_of(state)
        note = ""
        if n <= max_n:
            try:
                out = planner_a.run(n, cr, targets, risk, topo, feedback)
            except LLMError as exc:
                out = planner_a.fallback(cr, targets, risk, topo)
                note = f" (LLM failed: {exc}; deterministic solver used)"
        else:
            out = planner_a.fallback(cr, targets, risk, topo)
        p = out["plan"]
        cons = check_plan(p, topo, targets["servers"] + targets["switches"], cr["components"], pol,
                          cr["window"]["duration_minutes"], [d["asset"] for d in risk["deferred"]])
        attempts.append({"attempt": n, "plan": p, "provenance": out["provenance"], "constraints": cons, "llm": out["llm"]})
        log(state, "agent:planner", "plan_proposed", {"attempt": n, "provenance": out["provenance"], "plan_hash": plan_hash(p),
                                                       "waves": [w["assets"] for w in p["waves"]], "llm": out["llm"]})
        log(state, "code:constraints", "constraint_check", {"attempt": n, "ok": cons["ok"], "violations": cons["violations"],
                                                             "max_brs": cons["max_brs"]})
        level = "success" if cons["ok"] else "error"
        detail = (f"attempt {n} ({out['provenance']}{note}): {len(p['waves'])} waves, max Blast-Radius Score {cons['max_brs']:.0f}; "
                  + ("all constraints satisfied" if cons["ok"] else f"{len(cons['violations'])} violation(s): "
                     + "; ".join(v["message"] for v in cons["violations"][:2])))
        return {"attempts": attempts, "timeline": _t("planner", "proposed", detail, level)}

    def verify(state: RunState):
        attempts = list(state["attempts"])
        cur = dict(attempts[-1])
        ver = verifier_a.run(cur["plan"], state["change_request"], topo_of(state), state["risk"])
        cons = cur["constraints"]
        passed = cons["ok"] and ver["passed"]
        cur["verification"] = ver
        cur["passed"] = passed
        cur["feedback"] = None if passed else {
            "constraint_violations": [v["message"] for v in cons["violations"]],
            "contradicted_claims": [{"claim": c["text"], "why": c["explanation"]} for c in ver["claims"] if c["label"] == "Contradicted"],
            "unverifiable_claims": [c["text"] for c in ver["claims"] if c["label"] == "Unverifiable"],
        }
        attempts[-1] = cur
        log(state, "agent:verifier", "verification", {"attempt": cur["attempt"], "trust_score": ver["trust_score"],
                                                      "self_confidence": ver["self_confidence"], "counts": ver["counts"],
                                                      "claims": [{k: c[k] for k in ("text", "type", "label", "evidence")} for c in ver["claims"]],
                                                      "verifier_model": ver["verifier_model"]})
        c = ver["counts"]
        detail = (f"Trust Score {ver['trust_score']:.0f} (planner self-confidence {ver['self_confidence']}); "
                  f"{c.get('Supported', 0)} supported, {c.get('Contradicted', 0)} contradicted, {c.get('Unverifiable', 0)} unverifiable")
        tl = _t("verifier", "scored", detail, "success" if ver["passed"] else "error")
        for cl in [x for x in ver["claims"] if x["label"] == "Contradicted"][:3]:
            tl += _t("verifier", "contradicted", f"\"{cl['text']}\" - {cl['explanation']}", "error")
        upd: dict[str, Any] = {"attempts": attempts, "timeline": tl}
        if passed:
            upd.update(plan=cur["plan"], plan_hash=plan_hash(cur["plan"]), plan_provenance=cur["provenance"],
                       verification=ver, constraints=cons, status="awaiting_canary_approval")
        return upd

    def after_verify(state: RunState) -> str:
        if state["attempts"][-1]["passed"]:
            return "approve_canary"
        n = len(state["attempts"])
        max_n = int(pol.get("planning.max_plan_attempts", 2))
        if n < max_n or (n == max_n and pol.get("planning.solver_fallback", True)):
            return "plan"
        return "escalate"

    def escalate(state: RunState):
        last = state["attempts"][-1]
        decision = interrupt({"scope": "escalation", "reason": "no plan passed constraints and verification",
                              "feedback": last["feedback"], "attempts": len(state["attempts"])})
        log(state, f"human:{decision.get('approver', 'operator')}", "escalation_decision", decision)
        return {"status": "escalated", "timeline": _t("supervisor", "escalated", "operator closed the change after escalation", "warn")}

    # ---------------------------------------------------------- approvals
    def card(state: RunState, scope: str) -> dict:
        p, ver, cons, risk = state["plan"], state["verification"], state["constraints"], state["risk"]
        waves = []
        for w, imp in zip(p["waves"], cons["impacts"]):
            waves.append({"index": imp["wave"], "name": w["name"], "assets": w["assets"], "evacuate": w.get("evacuate", []),
                          "duration_min": imp["duration_min"], "brs": imp["brs"], "migrated_vms": imp["migrated_vms"],
                          "impacted_vms": len(imp["impacted_vms"])})
        prev: dict[str, set] = {}
        for r in risk["assets"].values():
            for comp, ver_ in r["current"].items():
                if comp in r["target"]:
                    prev.setdefault(comp, set()).add(ver_)
        rollback_plan = ("Automatic on any golden-signal regression: halt remaining waves, revert the failing wave to the versions "
                         "captured at execution time (" + "; ".join(f"{c} -> {'/'.join(sorted(v))}" for c, v in sorted(prev.items()))
                         + "), re-check signals, record the lesson.")
        top = sorted(risk["assets"].values(), key=lambda r: -r["score"])[:6]
        c = {
            "scope": scope,
            "run_id": state["run_id"],
            "summary": state["change_request"]["summary"],
            "required_approvers": int(pol.get(f"approval.{scope}.approvers", 1)),
            "plan_hash": state["plan_hash"],
            "plan_provenance": state["plan_provenance"],
            "trust_score": ver["trust_score"],
            "self_confidence": ver["self_confidence"],
            "claims": [{k: x[k] for k in ("id", "text", "label", "explanation", "evidence")} for x in ver["claims"]],
            "waves": waves,
            "total_duration_min": cons["total_duration_min"],
            "max_brs": cons["max_brs"],
            "deferred": risk["deferred"],
            "top_risks": [{"asset": r["asset"], "score": r["score"], "reasons": r["reasons"][:2]} for r in top],
            "rollback_plan": rollback_plan,
        }
        if scope == "fleet":
            canary = state["executions"][0]
            c["canary_result"] = {"assets": canary["assets"], "result": canary.get("result"), "checked": canary.get("checked"),
                                  "migrated_vms": canary["migrated_vms"]}
            c["waves"] = c["waves"][1:]
        return c

    def _grant(state, waves: list[dict]):
        assets = sorted({a for w in waves for a in w["assets"] + w.get("evacuate", [])})
        sv.authority.reinstate_run(state["run_id"])
        sv.authority.grant(state["run_id"], assets, WRITE_ACTIONS)
        return assets

    def approve_canary(state: RunState):
        decision = interrupt(card(state, "canary"))
        approver = (decision.get("approver") or "").strip() or "unknown"
        verdict = "approve" if decision.get("decision") == "approve" else "reject"
        rec = sv.authority.sign_approval(state["run_id"], state["plan_hash"], "canary", approver, verdict, decision.get("comment", ""))
        log(state, f"human:{approver}", "approval", rec)
        approvals = list(state.get("approvals", [])) + [rec]
        if verdict == "reject":
            return {"approvals": approvals, "status": "rejected",
                    "timeline": _t("human", "rejected", f"{approver} rejected the plan; nothing executed", "warn")}
        assets = _grant(state, state["plan"]["waves"][:1])
        log(state, "code:authority", "write_grant", {"waves": [1], "assets": assets, "actions": WRITE_ACTIONS})
        return {"approvals": approvals, "current_wave": 1, "status": "executing",
                "timeline": _t("human", "approved", f"{approver} approved plan {state['plan_hash'][:12]} and the canary (signature {rec['signature'][:12]})", "success")}

    def after_canary_approval(state: RunState) -> str:
        return "report" if state["status"] == "rejected" else "execute"

    def approve_fleet(state: RunState):
        decision = interrupt(card(state, "fleet"))
        need = int(pol.get("approval.fleet.approvers", 2))
        approvers = [a.strip() for a in decision.get("approvers", []) if a and a.strip()]
        verdict = "approve" if decision.get("decision") == "approve" else "reject"
        if verdict == "approve" and len(set(approvers)) < need:
            return {"timeline": _t("supervisor", "approval_invalid", f"fleet waves need {need} distinct approvers; got {len(set(approvers))}", "warn")}
        approvals = list(state.get("approvals", []))
        for a in (approvers or ["unknown"]):
            rec = sv.authority.sign_approval(state["run_id"], state["plan_hash"], "fleet", a, verdict, decision.get("comment", ""))
            log(state, f"human:{a}", "approval", rec)
            approvals.append(rec)
        if verdict == "reject":
            return {"approvals": approvals, "status": "stopped_after_canary",
                    "timeline": _t("human", "rejected", "fleet waves rejected after the canary", "warn")}
        assets = _grant(state, state["plan"]["waves"][1:])
        log(state, "code:authority", "write_grant", {"waves": list(range(2, len(state["plan"]["waves"]) + 1)), "assets": assets})
        return {"approvals": approvals, "fleet_approved": True,
                "timeline": _t("human", "approved", f"dual approval by {' and '.join(approvers)} for {len(state['plan']['waves']) - 1} fleet waves", "success")}

    def after_fleet(state: RunState) -> str:
        if state.get("status") == "stopped_after_canary":
            return "report"
        return "execute" if state.get("fleet_approved") else "approve_fleet"

    # ---------------------------------------------------------- execution
    def execute(state: RunState):
        i = state["current_wave"]
        wave = state["plan"]["waves"][i - 1]
        tv = state["risk"]["target_versions"]
        try:
            res = exec_a.run_wave(state["run_id"], i, wave, state["change_request"]["components"], tv, topo_of(state))
        except (ExecutionHalted, ToolCallError) as exc:
            sv.authority.revoke_run(state["run_id"])
            log(state, "agent:executor", "halted", {"wave": i, "reason": str(exc)})
            return {"status": "halted", "halt_reason": str(exc),
                    "timeline": _t("executor", "halted", f"wave {i} halted: {exc}", "error")}
        log(state, "agent:executor", "wave_executed", {"wave": i, "actions": [{k: a[k] for k in ("tool", "asset", "evidence")} for a in res["actions"]],
                                                       "firmware_changes": res["firmware_changes"]})
        return {"executions": list(state.get("executions", [])) + [res],
                "timeline": _t("executor", "wave_done", f"{res['name']}: {len(res['actions'])} guarded write actions, "
                                                        f"{res['migrated_vms']} VMs live-migrated")}

    def after_execute(state: RunState) -> str:
        return "report" if state.get("status") == "halted" else "postcheck"

    def postcheck(state: RunState):
        execs = list(state["executions"])
        cur = dict(execs[-1])
        cmp = post_a.compare(cur["pre"], cur["post"], cur["during"])
        cur.update(result="passed" if cmp["passed"] else "regression", regressions=cmp["regressions"], checked=cmp["checked"])
        execs[-1] = cur
        log(state, "agent:postcheck", "golden_signals", {"wave": cur["index"], "passed": cmp["passed"], "regressions": cmp["regressions"],
                                                         "evidence": cur["evidence"]})
        upd: dict[str, Any] = {"executions": execs}
        if not cmp["passed"]:
            sv.authority.revoke_run(state["run_id"])
            upd["status"] = "rolling_back"
            upd["timeline"] = _t("postcheck", "regression", f"{cur['name']}: " + "; ".join(f"{r['asset']} {r['message']}" for r in cmp["regressions"][:3])
                                 + " - auto-halt, write access revoked", "error")
        elif cur["index"] == len(state["plan"]["waves"]):
            upd["status"] = "completed"
            upd["timeline"] = _t("postcheck", "passed", f"{cur['name']}: {cmp['checked']} signal sets within thresholds; all waves complete", "success")
        else:
            upd["current_wave"] = cur["index"] + 1
            upd["timeline"] = _t("postcheck", "passed", f"{cur['name']}: {cmp['checked']} signal sets within thresholds", "success")
        return upd

    def after_postcheck(state: RunState) -> str:
        if state.get("status") == "rolling_back":
            return "rollback"
        if state.get("status") == "completed":
            return "report"
        if state.get("fleet_approved"):
            return "execute"
        return "approve_fleet"

    def rollback(state: RunState):
        cur = state["executions"][-1]
        topo = topo_of(state)
        sv.authority.reinstate_run(state["run_id"])
        sv.authority.grant(state["run_id"], sorted({c["asset"] for c in cur["firmware_changes"]}), WRITE_ACTIONS)
        rb = rb_a.run(state["run_id"], cur, topo)
        sv.authority.revoke_run(state["run_id"])
        assets = {s["asset"] for s in rb["after"]}
        check = post_a.compare([s for s in cur["pre"] if s["asset"] in assets], rb["after"])
        rb["recovered"] = check["passed"]
        log(state, "agent:rollback", "rolled_back", {"reverted": rb["reverted"], "recovered": check["passed"], "evidence": rb["evidence"]})
        base, _ = sv.bus.call("reporter", "compute.get_firmware_baseline", name="latest")
        lesson = rep_a.lesson_from_rollback(state["run_id"], cur, cur["regressions"], topo, base["components"])
        tl = _t("rollback", "reverted", f"{len(rb['reverted'])} firmware change(s) reverted; signals "
                                        + ("recovered" if check["passed"] else "NOT recovered - page on-call"), "success" if check["passed"] else "error")
        upd: dict[str, Any] = {"rollback": rb, "status": "rolled_back"}
        if lesson:
            ev = rep_a.learn(lesson)
            log(state, "agent:reporter", "lesson_recorded", {"incident": lesson, "evidence": ev})
            upd["lesson"] = lesson
            tl += _t("reporter", "learned", f"{lesson['id']}: {lesson['symptom']} {lesson['lesson']}", "warn")
        hours = float(pol.get("business.assumed_outage_hours", 4))
        rate = float(pol.get("business.downtime_cost_per_hour_usd", 300000))
        upd["avoided_cost_usd"] = hours * rate
        upd["timeline"] = tl
        return upd

    def report(state: RunState):
        rep = rep_a.run(dict(state))
        log(state, "agent:reporter", "report_signed", {"signature": rep["signature"], "outcome": rep["outcome"], "path": rep["path"]})
        return {"report": rep, "timeline": _t("reporter", "report", f"signed post-change report ({rep['outcome']}): {rep['summary']}",
                                              "success" if rep["outcome"] == "completed" else "info")}

    g = StateGraph(RunState)
    for name, fn in [("intake", intake), ("discover", discover), ("assess", assess), ("plan", plan), ("verify", verify),
                     ("escalate", escalate), ("approve_canary", approve_canary), ("approve_fleet", approve_fleet),
                     ("execute", execute), ("postcheck", postcheck), ("rollback", rollback), ("report", report)]:
        g.add_node(name, fn)
    g.add_edge(START, "intake")
    g.add_edge("intake", "discover")
    g.add_edge("discover", "assess")
    g.add_edge("assess", "plan")
    g.add_edge("plan", "verify")
    g.add_conditional_edges("verify", after_verify, ["approve_canary", "plan", "escalate"])
    g.add_edge("escalate", "report")
    g.add_conditional_edges("approve_canary", after_canary_approval, ["execute", "report"])
    g.add_conditional_edges("approve_fleet", after_fleet, ["execute", "approve_fleet", "report"])
    g.add_conditional_edges("execute", after_execute, ["postcheck", "report"])
    g.add_conditional_edges("postcheck", after_postcheck, ["rollback", "report", "execute", "approve_fleet"])
    g.add_edge("rollback", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=InMemorySaver())


class Engine:
    """Thin façade used by the CLI and the UI."""

    def __init__(self, sv):
        self.sv = sv
        self.graph = build_graph(sv)

    def _cfg(self, run_id: str) -> dict:
        return {"configurable": {"thread_id": run_id}, "recursion_limit": 100}

    def _wrap(self, run_id: str, out: dict) -> dict:
        intr = out.pop("__interrupt__", None)
        return {"run_id": run_id, "state": out, "interrupt": intr[0].value if intr else None}

    def start(self, intent: str, run_id: str | None = None) -> dict:
        run_id = run_id or time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
        self.sv.ledger.append(run_id, "system", "run_started", {"intent": intent, "tool_transport": self.sv.bus.transport,
                                                                "planner_model": self.sv.llm.model, "verifier_model": self.sv.verifier_llm.model})
        out = self.graph.invoke({"run_id": run_id, "intent": intent, "timeline": []}, self._cfg(run_id))
        return self._wrap(run_id, out)

    def resume(self, run_id: str, decision: dict) -> dict:
        out = self.graph.invoke(Command(resume=decision), self._cfg(run_id))
        return self._wrap(run_id, out)

    def state(self, run_id: str) -> dict:
        return dict(self.graph.get_state(self._cfg(run_id)).values)
