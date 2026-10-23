"""LangGraph supervisor: the BlastRadius state machine.

    intake -> discover -> assess -> plan -> verify --(gate fails)--> plan (retry with feedback)
      |                    |
      +--------------------+--(no recognised target / every target deferred)--> report
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
CLI resumes it with ``Command(resume=...)`` after a person decides. A wave halted
mid-way keeps the record of its writes: a failed MCP call rolls the partial wave
back; a policy stop (kill switch, scope, rate limit) goes to the report, which lists
what is left and the manual steps.
"""

from __future__ import annotations

import operator
import re
import time
import uuid
from typing import Annotated, Any, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from .agents import (ExecutorAgent, IntakeAgent, PlannerAgent, PostValidationAgent, ReporterAgent, RiskAgent,
                     RollbackAgent, TopologyAgent, VerifierAgent)
from .agents.executor import ExecutionHalted
from .agents.rollback import manual_steps
from .agents.reporter import plan_hash
from .canary_stats import analyse_wave, changed_assets, params as stat_params, summary as stat_summary
from .cohorts import build as build_cohorts, coverage, risk_ranked_canary
from .business import counterfactual_impact
from .constraints import check_plan
from .premortem import card_view as premortem_view, compare as compare_premortem, premortem as run_premortem
from .optimizer import describe as describe_optimization, optimize, regrounded
from .llm import LLMError
from .mcp_layer import ToolCallError

WRITE_ACTIONS = ["virt.enter_maintenance", "virt.exit_maintenance", "compute.apply_firmware", "network.upgrade_switch_os"]
MAINTENANCE_ACTIONS = WRITE_ACTIONS[:2]


class RunState(TypedDict, total=False):
    run_id: str
    intent: str
    change_request: dict
    intake_warnings: list
    outcome_reason: str
    targets: dict
    topology: dict
    risk: dict
    attempts: list
    plan: dict
    plan_hash: str
    plan_provenance: str
    verification: dict
    verification_draft: dict | None
    constraints: dict
    approvals: list
    approval_error: str
    executions: list
    current_wave: int
    fleet_approved: bool
    status: str
    halt_reason: str
    manual_steps: list
    rollback: dict
    lesson: dict
    counterfactual: dict
    business_impact: dict
    premortem: dict
    premortem_compare: list
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

    def fallback(state, agent: str, fb: dict, **extra) -> list[dict]:
        """Ledger and timeline record of a failed model call and the deterministic stand-in used instead."""
        log(state, f"agent:{agent}", "llm_fallback", {**extra, **fb})
        return _t(agent, "llm_fallback", f"{fb['role']} model call failed ({fb['error']}); fallback: {fb['fallback']}", "warn")

    # ----------------------------------------------------------- analysis
    def intake(state: RunState):
        out = intake_a.run(state["intent"])
        tl = fallback(state, "intake", out["llm_fallback"]) if out["llm_fallback"] else []
        log(state, "agent:intake", "change_request", {"change_request": out["change_request"], "provenance": out["provenance"],
                                                      "llm": out["llm"], "evidence": out["evidence"]})
        t = out["targets"]
        cr = out["change_request"]
        tl += _t("intake", "parsed", f"{cr['summary']}: {len(t['servers'])} servers, {len(t['switches'])} switches; "
                                    f"window {cr['window']['day']} {cr['window']['start']} for {cr['window']['duration_minutes']} min")
        tl += [e for w in out["warnings"] for e in _t("intake", "warning", w, "warn")]
        upd = {"change_request": cr, "targets": t, "intake_warnings": out["warnings"], "status": "analysing", "attempts": [],
               "approvals": [], "executions": []}
        if not t["servers"] and not t["switches"]:
            # Nothing to plan: stop here, before any plan, approval or write.
            reason = ("no recognised targets: the intent names no cluster, server or switch in the inventory"
                      + (f" ({'; '.join(w for w in out['warnings'] if w.startswith('Dropped'))})"
                         if any(w.startswith("Dropped") for w in out["warnings"]) else ""))
            log(state, "agent:intake", "no_targets", {"reason": reason})
            return {**upd, "status": "escalated", "outcome_reason": reason, "timeline": tl + _t("supervisor", "escalated", reason, "error")}
        return {**upd, "timeline": tl}

    def after_intake(state: RunState) -> str:
        return "report" if state["status"] == "escalated" else "discover"

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
        t = state["targets"]
        if not set(t["servers"] + t["switches"]) - {d["asset"] for d in risk["deferred"]}:
            by = sorted({(re.search(r"\bINC-[\w-]+", d["reason"]) or [d["reason"]])[0] for d in risk["deferred"]})
            reason = f"nothing to do: all {len(risk['deferred'])} target(s) deferred by {', '.join(by)}"
            log(state, "agent:risk", "nothing_to_do", {"reason": reason})
            return {"risk": risk, "status": "nothing_to_do", "outcome_reason": reason,
                    "timeline": tl + _t("supervisor", "nothing_to_do", reason, "warn")}
        return {"risk": risk, "timeline": tl}

    def after_assess(state: RunState) -> str:
        return "report" if state["status"] == "nothing_to_do" else "plan"

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
        attempts.append({"attempt": n, "plan": p, "provenance": out["provenance"], "constraints": cons, "llm": out["llm"],
                         "memory_rules": out.get("memory_rules", [])})
        log(state, "agent:planner", "plan_proposed", {"attempt": n, "provenance": out["provenance"], "plan_hash": plan_hash(p),
                                                       "waves": [w["assets"] for w in p["waves"]], "llm": out["llm"]})
        log(state, "code:constraints", "constraint_check", {"attempt": n, "ok": cons["ok"], "violations": cons["violations"],
                                                             "max_brs": cons["max_brs"]})
        level = "success" if cons["ok"] else "error"
        cov = cons.get("canary_coverage")
        cov_txt = f", canary covers {cov['covered']}/{cov['total']} configuration cohorts" if cov else ""
        detail = (f"attempt {n} ({out['provenance']}{note}): {len(p['waves'])} waves, max Blast-Radius Score {cons['max_brs']:.0f}{cov_txt}; "
                  + ("all constraints satisfied" if cons["ok"] else f"{len(cons['violations'])} violation(s): "
                     + "; ".join(v["message"] for v in cons["violations"][:2])))
        tl = _t("planner", "proposed", detail, level)
        if out.get("memory_rules"):
            tl = _t("memory", "retrieved", f"{len(out['memory_rules'])} planning rule(s) from earlier rejected plans given to the planner: "
                                           + ", ".join(out["memory_rules"][:3]) + ("..." if len(out["memory_rules"]) > 3 else "")) + tl
        return {"attempts": attempts, "timeline": tl}

    def optimise(state: RunState):
        """Risk-aware wave optimizer: improves a feasible plan under the same hard constraints.

        The Verifier then runs on the optimised waves, so every claim is re-checked and the
        plan hash that the approval signs covers what will actually execute.
        """
        attempts = list(state["attempts"])
        cur = dict(attempts[-1])
        if not cur["constraints"]["ok"] or not pol.get("optimizer.enabled", True):
            return {}
        cr, targets, risk, topo = state["change_request"], state["targets"], state["risk"], topo_of(state)
        res = optimize(cur["plan"], targets, topo, risk, pol, cr["components"], cr["window"]["duration_minutes"],
                       risk["deferred"], seed=int(pol.get("optimizer.seed", 5)),
                       time_budget_s=float(pol.get("optimizer.time_budget_s", 60.0)))
        summary = {k: res[k] for k in ("status", "improved", "before", "after", "changes", "stats", "weights")}
        cur["optimization"] = summary
        tl: list[dict] = []
        if res["improved"]:
            new_plan = res["plan"]
            new_cons = check_plan(new_plan, topo, targets["servers"] + targets["switches"], cr["components"], pol,
                                  cr["window"]["duration_minutes"], [d["asset"] for d in risk["deferred"]])
            if cur["provenance"] == "deterministic-solver":
                new_plan = regrounded(new_plan, topo, targets, pol, cr["components"], risk["deferred"])
            else:
                # The planner's sentences described the old ordering; it re-explains the waves that will run,
                # and the Verifier checks that explanation.
                try:
                    exp = planner_a.explain(new_plan["waves"], cr, targets, risk, topo, new_cons["total_duration_min"])
                    new_plan = {**new_plan, "rationale": exp["rationale"], "self_confidence": exp["self_confidence"]}
                    cur["explain_llm"] = exp["llm"]
                except LLMError as exc:
                    # Keep the better waves; their rationale is rebuilt from the waves themselves (and still verified).
                    new_plan = {**regrounded(new_plan, topo, targets, pol, cr["components"], risk["deferred"]), "self_confidence": None}
                    cur["provenance"] += "; rationale: deterministic re-explanation (planner_explain failed)"
                    tl = fallback(state, "planner", {"role": "planner_explain", "error": str(exc)[:300],
                                                     "fallback": "deterministic grounded rationale"}, attempt=cur["attempt"])
            cur["plan_before_optimization"] = cur["plan"]
            cur["plan"] = new_plan
            cur["constraints"] = new_cons
        attempts[-1] = cur
        log(state, "code:optimizer", "plan_optimized" if res["improved"] else "plan_not_improved",
            {"attempt": cur["attempt"], "plan_hash": plan_hash(cur["plan"]), "before": res["before"], "after": res["after"],
             "moves": len(res.get("moves", [])), "stats": res["stats"], "provenance": cur["provenance"],
             "llm": cur.get("explain_llm") if res["improved"] else None})
        return {"attempts": attempts,
                "timeline": tl + _t("optimizer", "optimized" if res["improved"] else "kept", describe_optimization(res),
                                    "success" if res["improved"] else "info")}

    def verify(state: RunState):
        attempts = list(state["attempts"])
        cur = dict(attempts[-1])
        cr, topo = state["change_request"], topo_of(state)
        # When the optimiser had the planner re-explain re-sequenced waves, the planner's own first rationale
        # is still its claim: verify it against the waves it described, so a hallucinating draft cannot pass
        # just because the optimiser replaced its text.
        draft = cur.get("plan_before_optimization") if not cur["provenance"].startswith("deterministic-solver") else None
        ver_draft = verifier_a.run(draft, cr, topo, state["risk"]) if draft else None
        ver = verifier_a.run(cur["plan"], cr, topo, state["risk"])
        cons = cur["constraints"]
        passed = cons["ok"] and ver["passed"] and (ver_draft is None or ver_draft["passed"])
        failing = [v for v in (ver_draft, ver) if v and not v["passed"]]
        failed_claims = [c for v in failing for c in v["claims"]]
        cur["verification"] = ver
        if ver_draft:
            cur["verification_draft"] = ver_draft
        cur["passed"] = passed
        cur["feedback"] = None if passed else {
            "constraint_violations": [v["message"] for v in cons["violations"]],
            "contradicted_claims": [{"claim": c["text"], "why": c["explanation"]} for c in failed_claims if c["label"] == "Contradicted"],
            "unverifiable_claims": [c["text"] for c in failed_claims if c["label"] == "Unverifiable"],
        }
        attempts[-1] = cur
        tl = []
        for which, v in (("planner draft", ver_draft), ("plan", ver)):
            if v is None:
                continue
            tl += [e for fb in v["llm_fallbacks"] for e in fallback(state, "verifier", fb, attempt=cur["attempt"])]
            log(state, "agent:verifier", "verification", {"attempt": cur["attempt"], "subject": which if ver_draft else "plan",
                                                          "plan_hash": plan_hash(draft if v is ver_draft else cur["plan"]),
                                                          "trust_score": v["trust_score"],
                                                          "self_confidence": v["self_confidence"], "counts": v["counts"],
                                                          "claims": [{k: c[k] for k in ("text", "type", "label", "evidence")} for c in v["claims"]],
                                                          "verifier_model": v["verifier_model"], "extractor": v["extractor"],
                                                          "extraction_coverage": v["extraction_coverage"], "llm": v["llm_calls"]})
            c = v["counts"]
            detail = (("planner's own rationale for the draft waves: " if v is ver_draft else "")
                      + f"Trust Score {v['trust_score']:.0f} (planner self-confidence {v['self_confidence']}); "
                      f"{c.get('Supported', 0)} supported, {c.get('Contradicted', 0)} contradicted, {c.get('Unverifiable', 0)} unverifiable")
            tl += _t("verifier", "scored", detail, "success" if v["passed"] else "error")
            for cl in [x for x in v["claims"] if x["label"] == "Contradicted"][:3]:
                tl += _t("verifier", "contradicted", f"\"{cl['text']}\" - {cl['explanation']}", "error")
        if not passed and pol.get("memory.enabled", True):
            # Rules come from the verification(s) that failed; constraint violations from the attempt itself.
            lesson = {**cur, "verification": {"claims": failed_claims}} if failing else cur
            learned = sv.memory.learn(state["run_id"], cur["feedback"], lesson, topo_of(state))
            log(state, "agent:planner_memory", "rules_learned", {"attempt": cur["attempt"],
                                                                  "rules": [{k: r[k] for k in ("key", "hits", "evidence")} for r in learned]})
            if learned:
                tl += _t("memory", "learned", f"{len(learned)} planning rule(s) learned or reinforced for next time: "
                                              + "; ".join(r["key"] for r in learned[:3]) + ("..." if len(learned) > 3 else ""))
        upd: dict[str, Any] = {"attempts": attempts, "timeline": tl}
        if passed:
            upd.update(plan=cur["plan"], plan_hash=plan_hash(cur["plan"]), plan_provenance=cur["provenance"],
                       verification=ver, verification_draft=ver_draft, constraints=cons,
                       status="awaiting_canary_approval")
            # Pre-mortem (assumption-driven Monte Carlo) of the accepted plan, against the first draft when there was one.
            topo, risk, comps = topo_of(state), state["risk"], state["change_request"]["components"]
            samples, seed = int(pol.get("premortem.samples", 2000)), int(pol.get("premortem.seed", 11))
            if len(attempts) > 1:
                pm = compare_premortem({"attempt 1": attempts[0]["plan"], "accepted": cur["plan"]}, topo, risk, pol, comps, samples, seed)
                acc, rows = pm["results"]["accepted"], pm["rows"]
            else:
                acc, rows = run_premortem(cur["plan"], topo, risk, pol, comps, samples, seed), None
            view = premortem_view(acc)
            upd.update(premortem=view, premortem_compare=rows)
            log(state, "code:premortem", "premortem", {k: acc[k] for k in ("p_tier0_loss", "p_tier0_loss_ci95", "p_tier0_loss_attributable",
                                                                          "expected_vms_lost", "p95_vms_lost", "worst_wave", "assumptions")})
            upd["timeline"] = tl + _t("premortem", "estimated",
                                      f"pre-mortem (assumption-driven): P(tier-0 outage) {acc['p_tier0_loss']:.2%} over the change"
                                      + (f" vs {rows[0]['p_tier0_loss']:.0%} for attempt 1" if rows else "")
                                      + f"; worst wave {acc['worst_wave']}")
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
        what = "the regressed assets" if pol.get("execution.rollback_scope", "wave") == "asset" else "the failing wave"
        rollback_plan = (f"Automatic on any golden-signal regression: halt remaining waves, revert {what} to the versions "
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
            "draft_trust_score": (state.get("verification_draft") or {}).get("trust_score"),
            "claims": [{k: x[k] for k in ("id", "text", "label", "explanation", "evidence")} for x in ver["claims"]],
            "waves": waves,
            "total_duration_min": cons["total_duration_min"],
            "max_brs": cons["max_brs"],
            "deferred": risk["deferred"],
            "top_risks": [{"asset": r["asset"], "score": r["score"], "reasons": r["reasons"][:2]} for r in top],
            "rollback_plan": rollback_plan,
            "canary_coverage": cons.get("canary_coverage"),
            "premortem": state.get("premortem"),
            "premortem_compare": state.get("premortem_compare"),
            "risk_ranked_coverage": _risk_ranked_coverage(state),
            "warnings": list(state.get("intake_warnings") or [])
            + ([f"no eligible low-tier canary; canary is {cons['canary_fallback']}"] if cons.get("canary_fallback") else []),
            "optimizer_stopped_by": (next((a for a in reversed(state["attempts"]) if a.get("passed")), {})
                                     .get("optimization") or {}).get("stats", {}).get("stopped_by"),
        }
        if scope == "fleet":
            canary = state["executions"][0]
            c["canary_result"] = {"assets": canary["assets"], "result": canary.get("result"), "checked": canary.get("checked"),
                                  "migrated_vms": canary["migrated_vms"]}
            cs = canary.get("canary_stats")
            if cs:
                c["canary_result"]["statistical"] = {"verdict": cs["verdict"], "score": cs["score"], "summary": stat_summary(cs)}
            # The fleet gate covers only the waves still to run; the canary has already run.
            c["waves"] = c["waves"][1:]
            c["total_duration_min"] = sum(w["duration_min"] for w in c["waves"])
            c["max_brs"] = max((w["brs"] for w in c["waves"]), default=0.0)
        return c

    def _risk_ranked_coverage(state) -> dict | None:
        """Coverage a conventional lowest-risk canary of the same size would have had (for comparison on the card)."""
        topo, p = topo_of(state), state["plan"]
        scheduled = [a for w in p["waves"] for a in w["assets"] if a in topo.servers]
        if not scheduled:
            return None
        scores = {a: r["score"] for a, r in state["risk"]["assets"].items()}
        naive = risk_ranked_canary(scheduled, topo, scores, pol)
        cov = coverage(naive, build_cohorts(scheduled, topo.servers, state["change_request"]["components"]), topo, pol)
        return {"canary": naive, **{k: cov[k] for k in ("covered", "total", "missing", "hosts_represented", "hosts_total")}}

    def _grant_writes(run_id: str, maintenance: list[str], versions: dict[str, list[str]]) -> None:
        """Grant maintenance on hosts, and firmware writes on assets only at the listed versions."""
        topo = sv.runs[run_id]["topo"]
        sv.authority.grant(run_id, maintenance, MAINTENANCE_ACTIONS)
        servers = [a for a in versions if a in topo.servers]
        switches = [a for a in versions if a in topo.switches]
        sv.authority.grant(run_id, servers, ["compute.apply_firmware"], versions)
        sv.authority.grant(run_id, switches, ["network.upgrade_switch_os"], versions)

    def _grant(state, waves: list[dict]):
        """Grant one approval scope; it replaces the previous scope. Firmware writes are bound to the approved target version."""
        topo, tv, comps = topo_of(state), state["risk"]["target_versions"], state["change_request"]["components"]
        maint, versions = [], {}
        for w in waves:
            maint += [a for a in w["assets"] + w.get("evacuate", []) if a in topo.servers and a not in maint]
            for a in w["assets"]:
                t = tv.get(a, {})
                versions[a] = [t["Switch OS"]] if a in topo.switches else [t[c] for c in comps if c in t]
        sv.authority.revoke_grants(state["run_id"])
        _grant_writes(state["run_id"], maint, versions)
        return sorted(set(maint) | set(versions))

    def _identity(name: str) -> str:
        """Approver identity for distinctness: case and whitespace do not make a second person."""
        return "".join((name or "").split()).casefold()

    def _invalid(msg: str) -> dict:
        # Nothing is signed or granted; the gate asks again and the UI / CLI show the reason next to the form.
        return {"approval_error": msg, "timeline": _t("supervisor", "approval_invalid", msg, "warn")}

    def approve_canary(state: RunState):
        decision = interrupt(card(state, "canary"))
        approver = (decision.get("approver") or "").strip()
        verdict = "approve" if decision.get("decision") == "approve" else "reject"
        if verdict == "approve" and not approver:
            return _invalid("the canary needs a named approver; nothing was signed or executed")
        approver = approver or "unknown"
        rec = sv.authority.sign_approval(state["run_id"], state["plan_hash"], "canary", approver, verdict, decision.get("comment", ""))
        log(state, f"human:{approver}", "approval", rec)
        approvals = list(state.get("approvals", [])) + [rec]
        if verdict == "reject":
            return {"approvals": approvals, "status": "rejected", "approval_error": "",
                    "timeline": _t("human", "rejected", f"{approver} rejected the plan; nothing executed", "warn")}
        if not state["plan"]["waves"]:  # e.g. no target matched: approved, but there is nothing to execute
            return {"approvals": approvals, "status": "completed",
                    "timeline": _t("supervisor", "completed", "the approved plan has no waves; nothing executed", "warn")}
        assets = _grant(state, state["plan"]["waves"][:1])
        log(state, "code:authority", "write_grant", {"waves": [1], "assets": assets, "actions": WRITE_ACTIONS})
        return {"approvals": approvals, "current_wave": 1, "status": "executing", "approval_error": "",
                "timeline": _t("human", "approved", f"{approver} approved plan {state['plan_hash'][:12]} and the canary (signature {rec['signature'][:12]})", "success")}

    def after_canary_approval(state: RunState) -> str:
        if state.get("approval_error"):
            return "approve_canary"
        return "report" if state["status"] in ("rejected", "completed") else "execute"

    def approve_fleet(state: RunState):
        decision = interrupt(card(state, "fleet"))
        need = int(pol.get("approval.fleet.approvers", 2))
        approvers: list[str] = []
        for a in decision.get("approvers", []):
            if (a or "").strip() and _identity(a) not in {_identity(x) for x in approvers}:
                approvers.append(a.strip())
        verdict = "approve" if decision.get("decision") == "approve" else "reject"
        if verdict == "approve" and len(approvers) < need:
            return _invalid(f"fleet waves need {need} distinct approvers; got {len(approvers)} "
                            "(names are compared ignoring case and spaces); nothing was signed or executed")
        approvals = list(state.get("approvals", []))
        for a in (approvers or ["unknown"]):
            rec = sv.authority.sign_approval(state["run_id"], state["plan_hash"], "fleet", a, verdict, decision.get("comment", ""))
            log(state, f"human:{a}", "approval", rec)
            approvals.append(rec)
        if verdict == "reject":
            return {"approvals": approvals, "status": "stopped_after_canary", "approval_error": "",
                    "timeline": _t("human", "rejected", "fleet waves rejected after the canary", "warn")}
        assets = _grant(state, state["plan"]["waves"][1:])
        log(state, "code:authority", "write_grant", {"waves": list(range(2, len(state["plan"]["waves"]) + 1)), "assets": assets})
        return {"approvals": approvals, "fleet_approved": True, "approval_error": "",
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
            part = getattr(exc, "partial", None)
            touched = bool(part and (part["firmware_changes"] or part["in_maintenance"]))
            # A failed MCP call leaves writes possible, so the partial wave is rolled back. A policy stop (kill
            # switch, scope, rate limit) leaves the clean-up to a person: the report lists what is left and how.
            undo = touched and getattr(exc, "tool_error", isinstance(exc, ToolCallError))
            log(state, "agent:executor", "halted", {"wave": i, "reason": str(exc), "rollback": undo, **({
                "actions": [{k: a[k] for k in ("tool", "asset", "evidence")} for a in part["actions"]],
                "firmware_changes": part["firmware_changes"], "in_maintenance": part["in_maintenance"]} if part else {})})
            upd: dict[str, Any] = {"status": "rolling_back" if undo else "halted", "halt_reason": str(exc)}
            detail = f"wave {i} halted: {exc}"
            if part:
                upd["executions"] = list(state.get("executions", [])) + [part]
                detail += (f" after {len(part['actions'])} write action(s), {len(part['firmware_changes'])} firmware change(s); "
                           + ("rolling back the partial wave" if undo else f"{len(part['in_maintenance'])} host(s) left in maintenance - manual clean-up"))
                if not undo:
                    upd["manual_steps"] = manual_steps(part["firmware_changes"], part["in_maintenance"], part["switches_rebooting"])
            upd["timeline"] = _t("executor", "halted", detail, "error")
            return upd
        log(state, "agent:executor", "wave_executed", {"wave": i, "actions": [{k: a[k] for k in ("tool", "asset", "evidence")} for a in res["actions"]],
                                                       "firmware_changes": res["firmware_changes"]})
        return {"executions": list(state.get("executions", [])) + [res],
                "timeline": _t("executor", "wave_done", f"{res['name']}: {len(res['actions'])} guarded write actions, "
                                                        f"{res['migrated_vms']} VMs live-migrated")}

    def after_execute(state: RunState) -> str:
        return {"halted": "report", "rolling_back": "rollback"}.get(state.get("status"), "postcheck")

    def postcheck(state: RunState):
        execs = list(state["executions"])
        cur = dict(execs[-1])
        cmp = post_a.compare(cur["pre"], cur["post"], cur["during"])
        tl_stats: list[dict] = []
        sp = stat_params(pol)
        if sp["enabled"] and (cur["index"] == 1 or sp["all_waves"]):
            # Peer comparison against un-upgraded hosts of the same configuration cohort, same time window.
            stat = analyse_wave(sv, cur, topo_of(state), state["change_request"]["components"], exclude=changed_assets(execs[:-1]))
            cur["canary_stats"] = stat
            cmp["regressions"] = cmp["regressions"] + [r for r in stat["regressions"]
                                                       if (r["asset"], r["metric"]) not in {(x["asset"], x["metric"]) for x in cmp["regressions"]}]
            cmp["passed"] = cmp["passed"] and stat["verdict"] != "FAIL"
            log(state, "agent:postcheck", "canary_stats", {k: stat[k] for k in ("verdict", "score", "checks", "controls", "windows", "evidence")})
            tl_stats = _t("postcheck", "canary_stats", stat_summary(stat), {"FAIL": "error", "MARGINAL": "warn"}.get(stat["verdict"], "info"))
        cur.update(result="passed" if cmp["passed"] else "regression", regressions=cmp["regressions"], checked=cmp["checked"])
        execs[-1] = cur
        log(state, "agent:postcheck", "golden_signals", {"wave": cur["index"], "passed": cmp["passed"], "regressions": cmp["regressions"],
                                                         "evidence": cur["evidence"]})
        upd: dict[str, Any] = {"executions": execs}
        if not cmp["passed"]:
            sv.authority.revoke_run(state["run_id"])
            upd["status"] = "rolling_back"
            upd["timeline"] = tl_stats + _t("postcheck", "regression", f"{cur['name']}: " + "; ".join(f"{r['asset']} {r['message']}" for r in cmp["regressions"][:3])
                                            + " - auto-halt, write access revoked", "error")
        elif cur["index"] == len(state["plan"]["waves"]):
            upd["status"] = "completed"
            upd["timeline"] = tl_stats + _t("postcheck", "passed", f"{cur['name']}: {cmp['checked']} signal sets within thresholds; all waves complete", "success")
        else:
            if not state.get("fleet_approved"):
                sv.authority.revoke_grants(state["run_id"])  # the canary scope ends; fleet waves need their own approval
            upd["current_wave"] = cur["index"] + 1
            upd["timeline"] = tl_stats + _t("postcheck", "passed", f"{cur['name']}: {cmp['checked']} signal sets within thresholds", "success")
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
        # Rollback writes are bound to the versions captured before the wave ran.
        versions: dict[str, list[str]] = {}
        for c in cur["firmware_changes"]:
            versions.setdefault(c["asset"], []).append(c["from"])
        sv.authority.reinstate_run(state["run_id"])
        _grant_writes(state["run_id"], rb_a.hosts(cur, topo), versions)
        try:
            rb = rb_a.run(state["run_id"], cur, topo)
        finally:
            sv.authority.revoke_run(state["run_id"])
        if rb.get("blocked"):
            # The guard stopped the rollback (kill switch, scope, rate limit) or a write failed: a person takes over.
            steps = manual_steps(rb["pending"], rb["in_maintenance"], rb["rebooting"])
            log(state, "agent:rollback", "rollback_blocked", {k: rb[k] for k in ("blocked", "reverted", "pending", "in_maintenance")}
                | {"actions": [{k: a[k] for k in ("tool", "asset", "evidence")} for a in rb["actions"]]})
            return {"rollback": rb, "status": "halted", "halt_reason": f"rollback blocked: {rb['blocked']}; manual action required",
                    "manual_steps": steps,
                    "timeline": _t("rollback", "blocked", f"rollback blocked ({rb['blocked']}) after {len(rb['reverted'])} of "
                                                          f"{len(cur['firmware_changes'])} revert(s); {len(steps)} manual step(s) in the report", "error")}
        assets = {s["asset"] for s in rb["after"]}
        check = post_a.compare([s for s in cur["pre"] if s["asset"] in assets], rb["after"])
        rb["recovered"] = check["passed"]
        log(state, "agent:rollback", "rolled_back", {"reverted": rb["reverted"], "recovered": check["passed"], "evidence": rb["evidence"]})
        base, _ = sv.bus.call("reporter", "compute.get_firmware_baseline", name="latest")
        lesson = rep_a.lesson_from_rollback(state["run_id"], cur, cur.get("regressions", []), topo, base["components"])
        tl = _t("rollback", "reverted", f"{len(rb['reverted'])} firmware change(s) reverted; signals "
                                        + ("recovered" if check["passed"] else "NOT recovered - page on-call"), "success" if check["passed"] else "error")
        upd: dict[str, Any] = {"rollback": rb, "status": "rolled_back"}
        if lesson:
            # Learned incidents change which hosts later plans defer, so recording one is a token-gated write too.
            sv.authority.reinstate_run(state["run_id"])
            sv.authority.grant(state["run_id"], [lesson["id"]], ["knowledge.record_incident"])
            try:
                ev = rep_a.learn(state["run_id"], lesson)
            finally:
                sv.authority.revoke_run(state["run_id"])
            log(state, "agent:reporter", "lesson_recorded", {"incident": lesson, "evidence": ev})
            upd["lesson"] = lesson
            tl += _t("reporter", "learned", f"{lesson['id']}: {lesson['symptom']} {lesson['lesson']}", "warn")
            # The conventional baseline: risk-ranked canary on the greedy (un-optimised) ordering.
            accepted = next((a for a in reversed(state["attempts"]) if a.get("passed")), {})
            baseline = accepted.get("plan_before_optimization") or state["plan"]
            cf = rep_a.counterfactual(lesson, baseline, state["risk"], topo, state["change_request"]["components"])
            upd["counterfactual"] = cf
            log(state, "agent:reporter", "counterfactual", cf)
            if cur["index"] == 1 and not cf["risk_ranked_would_catch"] and cf["exposed_hosts"]:  # only our canary caught it
                tl += _t("reporter", "counterfactual",
                         f"A risk-ranked canary of the same size ({', '.join(cf['risk_ranked_canary'])}; {cf['risk_ranked_cohorts']} cohorts) "
                         f"has no affected host and would have passed. {cf['sentence']}", "warn")
        if lesson:
            comps = state["change_request"]["components"]
            biz = counterfactual_impact(lesson, baseline, topo, pol, comps, risk=state["risk"], actual_exec=cur)
            if baseline is not state["plan"]:
                opt = counterfactual_impact(lesson, state["plan"], topo, pol, comps, risk=state["risk"], actual_exec=cur)
                biz["with_optimised_order"] = {"counterfactual_usd": opt["headline"]["counterfactual_usd"],
                                               "vm_hours": opt["counterfactual"]["vm_hours"],
                                               "tier0_vms": opt["counterfactual"]["tier0_vms"],
                                               "detected_wave": opt["counterfactual"]["detected_wave"]}
            upd["business_impact"] = biz
            upd["avoided_cost_usd"] = biz["avoided"]["usd"]
            log(state, "agent:reporter", "business_impact", {k: biz.get(k) for k in ("headline", "avoided", "assumptions", "with_optimised_order")})
            tl += _t("reporter", "business_impact", biz["headline"]["text"], "warn")
        upd["timeline"] = tl
        return upd

    def report(state: RunState):
        # Every outcome ends here: the run's write access ends with it.
        sv.authority.revoke_run(state["run_id"])
        atts = state.get("attempts") or []
        # The memory metric is about the planner: a first attempt from the deterministic solver, or an empty plan, says nothing.
        if atts and atts[0]["provenance"] != "deterministic-solver" and any(w["assets"] for w in atts[0]["plan"]["waves"]):
            sv.memory.record_run(state["run_id"], bool(atts[0].get("passed")), len(atts), len(atts[0].get("memory_rules", [])))
        rep = rep_a.run(dict(state))
        log(state, "agent:reporter", "report_signed", {"signature": rep["signature"], "outcome": rep["outcome"], "path": rep["path"],
                                                       "summary_source": rep["summary_source"], "llm": rep["summary_llm"]})
        failed = rep["summary_llm"].get("ok") is False
        tl = _t("reporter", "llm_fallback", f"report model call failed ({rep['summary_llm'].get('note')}); deterministic summary signed instead",
                "warn") if failed else []
        return {"report": rep, "timeline": tl + _t("reporter", "report", f"signed post-change report ({rep['outcome']}): {rep['summary']}",
                                                   "success" if rep["outcome"] == "completed" else "info")}

    g = StateGraph(RunState)
    for name, fn in [("intake", intake), ("discover", discover), ("assess", assess), ("plan", plan), ("optimise", optimise),
                     ("verify", verify),
                     ("escalate", escalate), ("approve_canary", approve_canary), ("approve_fleet", approve_fleet),
                     ("execute", execute), ("postcheck", postcheck), ("rollback", rollback), ("report", report)]:
        g.add_node(name, fn)
    g.add_edge(START, "intake")
    g.add_conditional_edges("intake", after_intake, ["discover", "report"])
    g.add_edge("discover", "assess")
    g.add_conditional_edges("assess", after_assess, ["plan", "report"])
    g.add_edge("plan", "optimise")
    g.add_edge("optimise", "verify")
    g.add_conditional_edges("verify", after_verify, ["approve_canary", "plan", "escalate"])
    g.add_edge("escalate", "report")
    g.add_conditional_edges("approve_canary", after_canary_approval, ["execute", "approve_canary", "report"])
    g.add_conditional_edges("approve_fleet", after_fleet, ["execute", "approve_fleet", "report"])
    g.add_conditional_edges("execute", after_execute, ["postcheck", "rollback", "report"])
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

    def _invoke(self, run_id: str, arg) -> dict:
        try:
            out = self.graph.invoke(arg, self._cfg(run_id))
        except Exception:
            self.sv.authority.revoke_run(run_id)  # a run that dies without reaching the report keeps no write access
            raise
        return self._wrap(run_id, out)

    def start(self, intent: str, run_id: str | None = None) -> dict:
        run_id = run_id or time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
        self.sv.ledger.append(run_id, "system", "run_started", {"intent": intent, "tool_transport": self.sv.bus.transport,
                                                                "planner_model": self.sv.llm.model, "verifier_model": self.sv.verifier_llm.model})
        return self._invoke(run_id, {"run_id": run_id, "intent": intent, "timeline": []})

    def resume(self, run_id: str, decision: dict) -> dict:
        return self._invoke(run_id, Command(resume=decision))

    def state(self, run_id: str) -> dict:
        return dict(self.graph.get_state(self._cfg(run_id)).values)
