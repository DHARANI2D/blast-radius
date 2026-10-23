"""Wave Planner agent: the LLM proposes waves; code checks them (constraints.py)."""

from __future__ import annotations

import json

from ..constraints import check_plan
from ..llm import load_prompt
from ..memory import as_prompt
from ..models import Explanation, Plan
from ..solver import grounded_rationale, plan_facts, solve
from ..topology import Topology


class PlannerAgent:
    name = "planner"

    def __init__(self, sv):
        self.sv = sv

    def _inputs(self, cr: dict, targets: dict, risk: dict, topo: Topology) -> dict:
        deferred = {d["asset"] for d in risk["deferred"]}
        servers = [s for s in targets["servers"] if s not in deferred]
        switches = [s for s in targets["switches"] if s not in deferred]
        tv: dict[str, list[str]] = {}
        for asset in servers + switches:
            for c, v in risk["target_versions"].get(asset, {}).items():
                if v not in tv.setdefault(c, []):
                    tv[c].append(v)
        return {"servers": servers, "switches": switches, "target_versions": tv, "deferred": sorted(deferred)}

    def solver_plan(self, cr: dict, targets: dict, risk: dict, topo: Topology) -> tuple[list[dict], int]:
        inp = self._inputs(cr, targets, risk, topo)
        scores = {a: r["score"] for a, r in risk["assets"].items()}
        window = cr["window"]["duration_minutes"]
        waves = solve(inp["servers"], inp["switches"], topo, scores, self.sv.policy, cr["components"], window)
        res = check_plan({"waves": waves}, topo, targets["servers"] + targets["switches"], cr["components"],
                         self.sv.policy, window, inp["deferred"])
        return waves, res["total_duration_min"]

    def run(self, attempt: int, cr: dict, targets: dict, risk: dict, topo: Topology, feedback: dict | None) -> dict:
        policy = self.sv.policy
        inp = self._inputs(cr, targets, risk, topo)
        facts = plan_facts(topo, targets, policy, cr["components"], inp["deferred"])
        cohort_of = {h: c["id"] for c in facts["_cohorts_full"] for h in c["hosts"]}
        hosts = [
            {"name": s, "cluster": topo.servers[s]["cluster"], "most_critical_tier": topo.most_critical_tier(s),
             "risk": risk["assets"][s]["score"], "uplinks": topo.links_of(s), "cohort": cohort_of.get(s)}
            for s in inp["servers"]
        ]
        rules = (self.sv.memory.retrieve(cr, targets, int(policy.get("memory.retrieve_k", 12)), topo=topo)
                 if policy.get("memory.enabled", True) else [])
        prompt_input = {
            "lessons_from_rejected_plans": as_prompt(rules) or None,
            "change_request": cr,
            "targets": {"hosts": hosts, "switches": [
                {"name": s, "peer": topo.peer_of(s), "risk": risk["assets"][s]["score"],
                 "risk_reasons": risk["assets"][s]["reasons"][:3]} for s in inp["switches"]]},
            "deferred": risk["deferred"],
            "target_versions": inp["target_versions"],
            "facts": {**{k: v for k, v in facts.items() if not k.startswith("_")},
                      "clusters": [topo.cluster_capacity(c) for c in topo.clusters],
                      "storage_paths": {a: [p["switch"] for p in arr["ports"]] for a, arr in topo.arrays.items()}},
            "policy": {k: policy.get(f"planning.{k}") for k in ("canary_max_assets", "canary_max_tier", "max_parallel_per_cluster", "max_assets_per_wave")},
            "window_minutes": cr["window"]["duration_minutes"],
            "durations_min": policy.get("execution.durations_min"),
            "feedback": feedback,
        }
        solver_waves, solver_dur = self.solver_plan(cr, targets, risk, topo)
        context = {
            "attempt": attempt,
            "target_servers": inp["servers"],
            "target_switches": inp["switches"],
            "server_cluster": {s: topo.servers[s]["cluster"] for s in inp["servers"]},
            "target_versions": inp["target_versions"],
            "components": cr["components"],
            "facts": facts,
            "feedback": feedback,
            "solver_plan": [dict(w) for w in solver_waves],
            "solver_duration_min": solver_dur,
            "naive_first": True,
            "memory_rules": rules,
        }
        plan: Plan = self.sv.llm.complete_json("planner", load_prompt("planner"), json.dumps(prompt_input, default=str),
                                               Plan, context=context, temperature=0.3)
        if self.sv.settings.offline:
            # Say plainly on screen what offline mode is: a scripted stand-in, not a model.
            from ..offline_llm import scripted_first_attempt

            if scripted_first_attempt(context):
                provenance = "offline stand-in: scripted ungrounded draft (what an unverified LLM plan looks like)"
            elif attempt == 1:
                provenance = "offline stand-in: first draft conditioned on planner memory"
            else:
                provenance = "offline stand-in: corrected draft from verifier feedback"
        else:
            provenance = f"llm:{self.sv.llm.model}"
        return {"plan": plan.model_dump(), "provenance": provenance, "llm": self.sv.llm.last(),
                "memory_rules": [r["key"] for r in rules]}

    def explain(self, waves: list[dict], cr: dict, targets: dict, risk: dict, topo: Topology, total_duration_min: int) -> dict:
        """Ask the planner to re-explain the optimiser's final waves (the Verifier then checks this text)."""
        inp = self._inputs(cr, targets, risk, topo)
        facts = plan_facts(topo, targets, self.sv.policy, cr["components"], inp["deferred"])
        user = {"waves": waves, "total_duration_min": total_duration_min,
                "facts": {k: v for k, v in facts.items() if not k.startswith("_")}, "components": cr["components"]}
        out: Explanation = self.sv.llm.complete_json(
            "planner_explain", load_prompt("planner_explain"), json.dumps(user, default=str), Explanation,
            context={"waves": waves, "facts": facts, "components": cr["components"], "total_duration_min": total_duration_min},
            temperature=0.2)
        return {"rationale": out.rationale, "self_confidence": out.self_confidence, "llm": self.sv.llm.last()}

    def fallback(self, cr: dict, targets: dict, risk: dict, topo: Topology) -> dict:
        waves, dur = self.solver_plan(cr, targets, risk, topo)
        inp = self._inputs(cr, targets, risk, topo)
        facts = plan_facts(topo, targets, self.sv.policy, cr["components"], inp["deferred"])
        plan = {"waves": waves, "rationale": grounded_rationale(waves, facts, cr["components"], dur), "self_confidence": None}
        return {"plan": plan, "provenance": "deterministic-solver", "llm": {}}
