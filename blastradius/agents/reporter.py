"""Reporter agent: signed post-change report, plus the learning loop.

When a wave is rolled back, the reporter turns the canary result into a lesson
by differential diagnosis: components whose new version also went onto a host
that stayed healthy are exonerated, and the firmware attributes shared only by
the regressed hosts become the incident's matching conditions. The lesson is
written to the knowledge base, so the next plan for a similar change scores
those hosts as high risk.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from pydantic import BaseModel

from ..ledger import canonical
from ..llm import load_prompt
from ..topology import Topology


class _ReportOut(BaseModel):
    summary: str
    lessons: list[str] = []


class ReporterAgent:
    name = "reporter"

    def __init__(self, sv):
        self.sv = sv

    # ------------------------------------------------------------- learning
    def lesson_from_rollback(self, run_id: str, wave_exec: dict, regressions: list[dict], topo: Topology,
                             baseline_versions: dict) -> dict | None:
        bad_assets = sorted({r["asset"] for r in regressions if r["asset"] in topo.servers})
        if not bad_assets:
            return None
        changes = wave_exec["firmware_changes"]
        good_assets = [a for a in wave_exec["assets"] if a in topo.servers and a not in bad_assets]
        healthy_versions = {(c["component"], c["to"]) for c in changes if c["asset"] in good_assets}
        suspects = sorted({(c["component"], c["to"]) for c in changes if c["asset"] in bad_assets} - healthy_versions)
        exonerated = sorted({(c["component"], c["to"]) for c in changes if c["asset"] in bad_assets} & healthy_versions)
        if not suspects:
            suspects = sorted({(c["component"], c["to"]) for c in changes if c["asset"] in bad_assets})
        bad_fw = [topo.servers[a]["firmware"] for a in bad_assets]
        good_fw = [topo.servers[a]["firmware"] for a in good_assets]
        model = topo.servers[bad_assets[0]]["model"]
        prefixes = {}
        for comp, ver in bad_fw[0].items():
            if any(comp == s[0] for s in suspects):
                continue
            major = ver.split(".")[0] + "."
            if all(f.get(comp, "").startswith(major) for f in bad_fw) and not any(f.get(comp, "").startswith(major) for f in good_fw):
                prefixes[comp] = major
        comp, ver = suspects[0]
        worst = next((r for r in regressions if r["metric"] == "nic_latency_ms"), regressions[0])
        fix_hint = ""
        for c, p in prefixes.items():
            target = baseline_versions.get(model, {}).get(c)
            if target and not target.startswith(p):
                fix_hint = f" Update {c} to {target} before applying {comp} {ver}."
        return {
            "id": f"INC-BR-{run_id}",
            "title": f"{comp} {ver} regression on {model.replace('HPE ProLiant ', '')} (learned by BlastRadius)",
            "date": time.strftime("%Y-%m-%d"),
            "severity": "high",
            "kind": "regression",
            "component": comp,
            "version": ver,
            "models": [model],
            "conditions": {"firmware_prefix": prefixes} if prefixes else {},
            "symptom": f"{worst['message']} on canary {', '.join(bad_assets)} after {comp} {ver}"
                       + (f" with {', '.join(f'{c} {p}x' for c, p in prefixes.items())}" if prefixes else "") + ".",
            "lesson": ("Exonerated: " + ", ".join(f"{c} {v}" for c, v in exonerated) + " (applied to healthy canary "
                       + ", ".join(good_assets) + ")." if exonerated else "No healthy control host in the canary.") + fix_hint,
            "source": f"blastradius run {run_id} (automatic rollback)",
        }

    def learn(self, incident: dict) -> str:
        _, ev = self.sv.bus.call(self.name, "knowledge.record_incident", incident=incident)
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
        }
        out: _ReportOut = sv.llm.complete_json("report", load_prompt("report"), json.dumps(ctx), _ReportOut, context=ctx, temperature=0.1)
        verify = sv.ledger.verify()
        body = {
            "run_id": state["run_id"],
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "intent": state.get("intent"),
            "change_request": state.get("change_request"),
            "outcome": outcome,
            "summary": out.summary,
            "lessons": out.lessons,
            "plan_hash": state.get("plan_hash"),
            "plan_provenance": state.get("plan_provenance"),
            "trust_score": (state.get("verification") or {}).get("trust_score"),
            "planner_self_confidence": (state.get("verification") or {}).get("self_confidence"),
            "approvals": [{k: a[k] for k in ("scope", "approver", "decision", "signature")} for a in state.get("approvals", [])],
            "waves": [{"index": w["index"], "name": w["name"], "result": w.get("result"), "assets": len(w["assets"]),
                       "regressions": w.get("regressions", [])} for w in waves],
            "rollback": {"reverted": (state.get("rollback") or {}).get("reverted", []),
                         "recovered": (state.get("rollback") or {}).get("recovered")} if state.get("rollback") else None,
            "deferred": (state.get("risk") or {}).get("deferred", []),
            "learned_incident": (state.get("lesson") or {}).get("id"),
            "avoided_cost_usd": state.get("avoided_cost_usd"),
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
            f"**Outcome:** {r['outcome']}  ",
            f"**Intent:** {r['intent']}  ",
            f"**Plan:** {r['plan_provenance']} (hash `{(r['plan_hash'] or '')[:16]}`), Trust Score {r['trust_score']}, "
            f"planner self-confidence {r['planner_self_confidence']}",
            "",
            "## Summary",
            r["summary"],
            "",
            "## Waves",
        ]
        for w in r["waves"]:
            lines.append(f"- {w['name']}: **{w['result']}** ({w['assets']} assets)"
                         + ("".join(f"\n  - {x['asset']}: {x['message']}" for x in w["regressions"]) if w["regressions"] else ""))
        if r.get("rollback"):
            lines += ["", "## Rollback", f"Recovered: {r['rollback']['recovered']}"]
            lines += [f"- {x['asset']} {x['component']} -> {x['to']}" for x in r["rollback"]["reverted"]]
        if r.get("deferred"):
            lines += ["", "## Deferred assets"] + [f"- {d['asset']}: {d['reason']}" for d in r["deferred"]]
        if r.get("lessons"):
            lines += ["", "## Lessons"] + [f"- {x}" for x in r["lessons"]]
        lines += ["", "## Approvals"] + [f"- {a['scope']}: {a['approver']} {a['decision']} (sig `{a['signature'][:16]}...`)" for a in r["approvals"]]
        lines += ["", "## Integrity",
                  f"Ledger entries: {r['ledger']['entries']}, chain verified: {r['ledger']['chain_ok']}, head `{(r['ledger']['head'] or '')[:16]}`  ",
                  f"Report signature ({r['signature_alg']}): `{r['signature']}`", ""]
        return "\n".join(lines)


def plan_hash(plan: dict) -> str:
    import hashlib

    return hashlib.sha256(canonical(plan).encode()).hexdigest()
