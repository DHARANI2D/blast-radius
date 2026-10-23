"""Reporter agent: signed post-change report, plus the learning loop.

When a wave is rolled back, the reporter turns the canary result into a lesson
by differential diagnosis: per-component probes on the regressed host pin the
culprit component, healthy canary hosts that got the same version act as
controls, and the untouched-firmware attributes that separate the regressed
hosts from those controls become the incident's matching conditions. The lesson is
written to the knowledge base, so the next plan for a similar change scores
those hosts as high risk.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from pydantic import BaseModel

from ..ledger import canonical
from ..llm import LLMError, load_prompt
from ..topology import Topology


class _ReportOut(BaseModel):
    summary: str
    lessons: list[str] = []


class ReporterAgent:
    name = "reporter"

    def __init__(self, sv):
        self.sv = sv

    # ------------------------------------------------------------- learning
    def _regressed(self, pre: dict | None, sig: dict, stat_regs: list[dict] = ()) -> bool:
        """Did this probe snapshot already show the regression?

        Fixed thresholds first. For a regression only the statistical judge caught (e.g. 1.3x),
        the snapshot is compared with the shift the judge measured: a probe that already shows
        at least three quarters of that shift is where the regression started.
        """
        if pre is None:
            return False
        from .postcheck import PostValidationAgent

        if not PostValidationAgent(self.sv).compare([pre], [sig])["passed"]:
            return True
        for r in stat_regs:
            base, now, post = pre.get(r["metric"]), sig.get(r["metric"]), r.get("post")
            if not base or now is None or not r.get("pre") or not post:
                continue
            shift = post / r["pre"]
            if shift > 1 and now / base >= 1 + 0.75 * (shift - 1):
                return True
        return False

    def lesson_from_rollback(self, run_id: str, wave_exec: dict, regressions: list[dict], topo: Topology,
                             baseline_versions: dict) -> dict | None:
        """Differential diagnosis of a canary regression.

        1. Culprit: the canary probes each host after every component it flashes. The first
           component after which a regressed host's signals break is the culprit; components
           flashed before it are exonerated *on that host*, which is the only valid evidence
           for exonerating them. Without probes we fall back to a set difference and say so.
        2. Scope: healthy canary hosts that received the same culprit version are controls.
           Untouched-firmware attributes shared by every regressed host and by no control
           are the regression's conditions (e.g. NIC firmware 229.x). With no control, the
           lesson is scoped to the regressed hosts' whole configuration cohort.
        """
        bad = sorted({r["asset"] for r in regressions if r["asset"] in topo.servers})
        if not bad:
            return None
        changes = wave_exec["firmware_changes"]
        changed = sorted({c["component"] for c in changes})
        good = [a for a in wave_exec["assets"] if a in topo.servers and a not in bad]
        pre = {s["asset"]: s for s in wave_exec.get("pre", [])}

        culprit, cleared, method = None, [], "set-difference"
        for p in wave_exec.get("probes", []):
            if p["host"] not in bad or culprit:
                continue
            stat_regs = [r for r in regressions if r.get("check") == "statistical" and r["asset"] == p["host"]]
            if self._regressed(pre.get(p["host"]), p["signals"], stat_regs):
                culprit, method = (p["component"], p["version"]), "per-component probe"
            else:
                cleared.append((p["component"], p["version"], p["host"]))
        if culprit is None:
            bad_v = {(c["component"], c["to"]) for c in changes if c["asset"] in bad}
            good_v = {(c["component"], c["to"]) for c in changes if c["asset"] in good}
            culprit = (sorted(bad_v - good_v) or sorted(bad_v))[0]
            cleared, method = [], "set-difference (ambiguous: no per-component probe)"
        comp, ver = culprit
        exonerated = sorted({(c, v) for c, v, _h in cleared if (c, v) != culprit})

        # Untouched-firmware attributes every regressed host shares (pre-change firmware from discovery).
        bad_fw = [topo.servers[a]["firmware"] for a in bad]
        shared = {}
        for k, v in bad_fw[0].items():
            if k in changed:
                continue
            maj = v.split(".")[0] + "."
            if all(f.get(k, "").startswith(maj) for f in bad_fw):
                shared[k] = maj
        controls = sorted(a for a in good if any(c["asset"] == a and (c["component"], c["to"]) == culprit for c in changes))
        if controls:
            prefixes = {k: p for k, p in shared.items()
                        if all(not topo.servers[c]["firmware"].get(k, "").startswith(p) for c in controls)}
            scope = "control" if prefixes else "intermittent"
            if not prefixes:
                prefixes = shared
        else:
            prefixes, scope = shared, "cohort"
        models = sorted({topo.servers[a]["model"] for a in bad})
        short = models[0].replace("HPE ProLiant ", "")
        cond_txt = ", ".join(f"{k} {p}x" for k, p in prefixes.items())

        worst = next((r for r in regressions if r["metric"] == "nic_latency_ms"), regressions[0])
        parts = []
        if method == "per-component probe":
            parts.append(f"Per-component probe: signals on {', '.join(bad)} were normal after "
                         + (", ".join(f"{c} {v}" for c, v in exonerated) or "the earlier steps")
                         + f" and broke right after {comp} {ver}"
                         + (f", so {', '.join(f'{c} {v}' for c, v in exonerated)} is exonerated." if exonerated else "."))
        else:
            parts.append(f"No per-component probe was available, so {comp} {ver} is only the most likely suspect.")
        if scope == "control":
            ctl = controls[0]
            ctl_attrs = ", ".join(f"{k} {topo.servers[ctl]['firmware'].get(k, '?').split('.')[0]}.x" for k in prefixes)
            parts.append(f"Control {', '.join(controls)} ({topo.servers[ctl]['model'].replace('HPE ProLiant ', '')}, {ctl_attrs}) "
                         f"received the same {comp} {ver} and stayed healthy, so the regression is specific to {cond_txt}.")
        elif scope == "intermittent":
            parts.append(f"Control {', '.join(controls)} has the same configuration and stayed healthy; the regression may be "
                         "intermittent, so the lesson covers the whole cohort.")
        else:
            parts.append(f"No healthy canary host received {comp} {ver}, so the lesson covers the whole {short} cohort"
                         + (f" ({cond_txt})." if cond_txt else "."))
        for c, p in prefixes.items():
            target = baseline_versions.get(models[0], {}).get(c)
            if target and not target.startswith(p):
                parts.append(f"Update {c} to {target} before applying {comp} {ver}.")
        return {
            "id": f"INC-BR-{run_id}",
            "title": f"{comp} {ver} regression on {short} (learned by BlastRadius)",
            "date": time.strftime("%Y-%m-%d"),
            "severity": "high",
            "kind": "regression",
            "component": comp,
            "version": ver,
            "models": models,
            "conditions": {"firmware_prefix": prefixes} if prefixes else {},
            "symptom": f"{worst['message']} on {'canary' if wave_exec.get('index', 1) == 1 else 'wave ' + str(wave_exec['index'])} "
                       f"{', '.join(bad)} after {comp} {ver}" + (f" with {cond_txt}" if cond_txt else "") + ".",
            "lesson": " ".join(parts),
            "diagnosis": {"method": method, "culprit": f"{comp} {ver}", "exonerated": [f"{c} {v}" for c, v in exonerated],
                          "controls": controls, "scope": scope},
            "source": f"blastradius run {run_id} (automatic rollback)",
        }

    def counterfactual(self, lesson: dict, plan: dict, risk: dict, topo: Topology, components: list[str]) -> dict:
        """Would a conventional risk-ranked canary of the same size have caught this regression?

        The fleet is the plan with that canary as wave 1 (``business.baseline_waves``) and hosts match the lesson as
        in ``business.matcher``, so these counts are the ones the business-impact replay prices."""
        from ..business import baseline_waves, matcher
        from ..cohorts import build, coverage, risk_ranked_canary

        pol = self.sv.policy
        scheduled = [a for w in plan["waves"] for a in w["assets"] if a in topo.servers]
        scores = {a: r["score"] for a, r in risk["assets"].items()}
        naive = risk_ranked_canary(scheduled, topo, scores, pol)
        affected = matcher(lesson, topo, components, risk.get("target_versions"))
        fleet = baseline_waves(plan, naive, topo)[1:]
        later = [(i, h) for i, w in enumerate(fleet, start=2) for h in w["assets"] if h in topo.servers and affected(h)]
        hosts = [h for _, h in later]
        vms = [v for h in hosts for v in topo.vms_on(h)]
        tier0 = sorted(v["name"] for v in vms if v["tier"] == 0)
        cov = coverage(naive, build(scheduled, topo.servers, components), topo, pol)
        first = later[0][0] if later else None
        first_hosts = [h for i, h in later if i == first]
        last = later[-1][0] if later else None
        sentence = ""
        if later:
            sentence = (f"Wave {first} would then have flashed {len(first_hosts)} affected host(s)"
                        + (f"; had its post-check missed it too, waves {first + 1}-{last} would have flashed "
                           f"{len(hosts) - len(first_hosts)} more" if last > first else "")
                        + f" ({len(hosts)} affected hosts running {len(vms)} VMs in all"
                        + (f", {len(tier0)} of them tier-0: {', '.join(tier0[:3])}" if tier0 else "") + ").")
        return {
            "risk_ranked_canary": naive,
            "risk_ranked_would_catch": any(affected(h) for h in naive),
            "risk_ranked_cohorts": f"{cov['covered']}/{cov['total']}",
            "first_exposed_wave": first,
            "first_wave_hosts": first_hosts,
            "last_exposed_wave": last,
            "exposed_hosts": hosts,
            "exposed_vms": len(vms),
            "exposed_tier0_vms": tier0,
            "sentence": sentence,
        }

    def learn(self, run_id: str, incident: dict) -> str:
        """Record the lesson; the token is granted for this run and incident only after a rollback (workflow.rollback)."""
        token = self.sv.authority.token(run_id, incident["id"], "knowledge.record_incident")
        _, ev = self.sv.bus.call(self.name, "knowledge.record_incident", incident=incident, run_id=run_id, approval_token=token)
        return ev

    # --------------------------------------------------------------- report
    def run(self, state: dict) -> dict:
        sv = self.sv
        waves = state.get("executions", [])
        outcome = state.get("status", "unknown")
        reg = [r for w in waves for r in w.get("regressions", [])]
        ctx = {
            "outcome": outcome,
            "waves_completed": sum(1 for w in waves if w.get("result") == "passed"),
            "waves_executed": len(waves),
            "recovered": bool((state.get("rollback") or {}).get("recovered")),
            "waves_total": len((state.get("plan") or {}).get("waves", [])),
            "regressed_assets": sorted({r["asset"] for r in reg}),
            "regression_summary": "; ".join(r["message"] for r in reg[:2]),
            "lesson": (state.get("lesson") or {}).get("symptom", ""),
            "halt_reason": state.get("halt_reason", ""),
            "outcome_reason": state.get("outcome_reason", ""),
            "halted_wave": state.get("current_wave"),
            "manual_steps": len(state.get("manual_steps") or []),
        }
        try:
            out: _ReportOut = sv.llm.complete_json("report", load_prompt("report"), json.dumps(ctx), _ReportOut, context=ctx, temperature=0.1)
            source = "offline stand-in (templated summary)" if sv.settings.offline else f"llm:{sv.llm.model}"
            llm_rec = sv.llm.last()
        except LLMError as exc:
            # The writes have happened: the signed report is due whatever the model does.
            from ..offline_llm import report as deterministic_report

            out = _ReportOut.model_validate(deterministic_report(ctx))
            llm_error = str(exc)[:300]
            source = f"deterministic summary (LLM failed: {llm_error})"
            llm_rec = {"role": "report", "model": sv.llm.model, "ok": False, "note": llm_error}
            sv.ledger.append(state["run_id"], "agent:reporter", "llm_fallback",
                             {"role": "report", "error": llm_error, "fallback": "deterministic summary"})
        verify = sv.ledger.verify()
        body = {
            "run_id": state["run_id"],
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "intent": state.get("intent"),
            "change_request": state.get("change_request"),
            "outcome": outcome,
            "outcome_reason": state.get("outcome_reason"),
            "summary": out.summary,
            "summary_source": source,
            "summary_llm": llm_rec,
            "lessons": out.lessons,
            "plan_hash": state.get("plan_hash"),
            "plan_provenance": state.get("plan_provenance"),
            "trust_score": (state.get("verification") or {}).get("trust_score"),
            "planner_self_confidence": (state.get("verification") or {}).get("self_confidence"),
            "approvals": [{k: a[k] for k in ("scope", "approver", "decision", "signature")} for a in state.get("approvals", [])],
            "waves": [{"index": w["index"], "name": w["name"], "result": w.get("result"), "assets": len(w["assets"]),
                       "regressions": w.get("regressions", [])} for w in waves],
            "halt_reason": state.get("halt_reason"),
            "partial_wave": next(({"index": w["index"], "name": w["name"], "actions": [f"{a['tool']} {a['asset']}" for a in w["actions"]],
                                   "firmware_changes": w["firmware_changes"], "in_maintenance": w["in_maintenance"]}
                                  for w in waves if w.get("result") == "halted"), None),
            "manual_steps": state.get("manual_steps") or [],
            "rollback": {"reverted": (state.get("rollback") or {}).get("reverted", []),
                         "recovered": (state.get("rollback") or {}).get("recovered"),
                         "blocked": (state.get("rollback") or {}).get("blocked")} if state.get("rollback") else None,
            "deferred": (state.get("risk") or {}).get("deferred", []),
            "learned_incident": (state.get("lesson") or {}).get("id"),
            "diagnosis": (state.get("lesson") or {}).get("diagnosis"),
            "counterfactual": state.get("counterfactual"),
            "avoided_cost_usd": state.get("avoided_cost_usd"),
            "business_impact": state.get("business_impact"),
            "premortem": state.get("premortem"),
            "planning_memory": sv.memory.stats() if sv.memory else None,
            "ledger": {"entries": verify["entries"], "chain_ok": verify["ok"], "head": verify.get("head")},
            "model": {"planner": sv.llm.model, "verifier": sv.verifier_llm.model},
        }
        body["signature"] = sv.authority.sign(body)
        body["signature_alg"] = "HMAC-SHA256 over canonical JSON (key: BR_SIGNING_KEY)"
        out_dir = Path(sv.settings.runtime_dir) / "runs" / state["run_id"]
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.json").write_text(json.dumps(body, indent=1, default=str))
        (out_dir / "report.md").write_text(self.markdown(body))
        body["path"] = str(out_dir / "report.md")
        return body

    @staticmethod
    def markdown(r: dict) -> str:
        lines = [
            f"# BlastRadius post-change report: {r['run_id']}",
            "",
            f"**Outcome:** {r['outcome']}" + (f" ({r['outcome_reason']})" if r.get("outcome_reason") else "") + "  ",
            f"**Intent:** {r['intent']}  ",
            (f"**Plan:** {r['plan_provenance']} (hash `{(r['plan_hash'] or '')[:16]}`), Trust Score {r['trust_score']}, "
             f"planner self-confidence {r['planner_self_confidence']}" if r.get("plan_hash") else "**Plan:** none"),
            "",
            "## Summary",
            r["summary"],
            "",
            f"_Summary: {r.get('summary_source') or 'n/a'}_",
            "",
            "## Waves",
        ]
        for w in r["waves"]:
            lines.append(f"- {w['name']}: **{w['result']}** ({w['assets']} assets)"
                         + ("".join(f"\n  - {x['asset']}: {x['message']}" for x in w["regressions"]) if w["regressions"] else ""))
        if r.get("halt_reason"):
            lines += ["", "## Halt", f"Reason: {r['halt_reason']}"]
            pw = r.get("partial_wave")
            if pw:
                lines += [f"{pw['name']} stopped part-way after {len(pw['actions'])} write action(s):"]
                lines += [f"- {x['asset']} {x['component']}: {x['from']} -> {x['to']}" for x in pw["firmware_changes"]]
                lines += [f"- {h} was in maintenance when the wave stopped" for h in pw["in_maintenance"]]
        if r.get("manual_steps"):
            lines += ["", "## Manual steps (writes are blocked)"] + [f"{i}. {x}" for i, x in enumerate(r["manual_steps"], 1)]
        if r.get("rollback"):
            lines += ["", "## Rollback", f"Recovered: {r['rollback']['recovered']}"
                      + (f" (blocked: {r['rollback']['blocked']})" if r["rollback"].get("blocked") else "")]
            lines += [f"- {x['asset']} {x['component']} -> {x['to']}" for x in r["rollback"]["reverted"]]
        if r.get("deferred"):
            lines += ["", "## Deferred assets"] + [f"- {d['asset']}: {d['reason']}" for d in r["deferred"]]
        if r.get("lessons"):
            lines += ["", "## Lessons"] + [f"- {x}" for x in r["lessons"]]
        if r.get("diagnosis"):
            d = r["diagnosis"]
            lines += ["", "## Diagnosis", f"- Method: {d['method']}", f"- Culprit: {d['culprit']}",
                      f"- Exonerated: {', '.join(d['exonerated']) or 'none'}", f"- Controls: {', '.join(d['controls']) or 'none'} (scope: {d['scope']})"]
        cf = r.get("counterfactual")
        if cf:
            lines += ["", "## Counterfactual: risk-ranked canary",
                      f"- Canary {', '.join(cf['risk_ranked_canary'])} covers {cf['risk_ranked_cohorts']} configuration cohorts; "
                      f"would have caught the regression: {cf['risk_ranked_would_catch']}",
                      f"- Affected hosts in the fleet waves: {len(cf['exposed_hosts'])} ({cf['exposed_vms']} VMs, "
                      f"{len(cf['exposed_tier0_vms'])} tier-0); {len(cf.get('first_wave_hosts', []))} in wave {cf['first_exposed_wave']}, "
                      f"the rest by wave {cf.get('last_exposed_wave')}"]
        if r.get("business_impact"):
            from ..business import markdown as business_md

            lines += ["", business_md(r["business_impact"])]
        pm = r.get("premortem")
        if pm:
            lines += ["", "## Pre-mortem (assumption-driven, not measured)",
                      f"P(tier-0 outage over the change) {pm.get('p_tier0_loss', 0):.2%}; expected VMs lost {pm.get('expected_vms_lost', 0):.2f}"]
        mem = r.get("planning_memory")
        if mem:
            lines += ["", "## Planning memory",
                      f"{mem.get('rules', 0)} rules; first-attempt pass rate {mem.get('first_attempt_pass_rate')} over {mem.get('runs', 0)} run(s)"]
        lines += ["", "## Approvals"] + [f"- {a['scope']}: {a['approver']} {a['decision']} (sig `{a['signature'][:16]}...`)" for a in r["approvals"]]
        lines += ["", "## Integrity",
                  f"Ledger entries: {r['ledger']['entries']}, chain verified: {r['ledger']['chain_ok']}, head `{(r['ledger']['head'] or '')[:16]}`  ",
                  f"Report signature ({r['signature_alg']}): `{r['signature']}`", ""]
        return "\n".join(lines)


def plan_hash(plan: dict) -> str:
    import hashlib

    return hashlib.sha256(canonical(plan).encode()).hexdigest()
