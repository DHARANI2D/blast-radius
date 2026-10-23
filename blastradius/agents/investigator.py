"""Investigator agent ("Ask BlastRadius"): grounded Q&A over the MCP tools.

With a live model the LLM itself chooses which read-only MCP tools to call
(OpenAI-style function calling, up to six rounds) and must cite the evidence id
of every tool result it relies on. The answer then goes through the same
Verifier as a plan rationale: its sentences are split into typed claims and each
is checked against evidence the Verifier gathers itself, giving the answer its
own Trust Score.

In offline mode a deterministic router stands in for the model: it maps asset
names, CVE ids and "why/risk" questions to tool calls and composes cited
sentences. The tool calls, evidence and verification are the real code path;
only the choice of calls and the wording are scripted.
"""

from __future__ import annotations

import inspect
import json
import re
import typing

from ..cohorts import major
from ..llm import load_prompt
from ..offline_llm import _sentences
from .verifier import VerifierAgent

EXCLUDE = {"telemetry.advance_clock", "knowledge.record_incident", "network.wait_upgrade_complete"}
METRIC = {"nic_latency_ms": "NIC latency (ms)", "rx_drop_rate": "rx drop rate", "crc_errors_per_min": "CRC errors per minute"}
CVE_RE = re.compile(r"(?:SYN-)?CVE-\d{4}-\d+", re.I)
TRAILING_CITE = re.compile(r"\.\s*(\[EV-\d{4}(?:,\s*EV-\d{4})*\])")


TOOL_RESULT_CHARS = 6000


def _fit(payload: dict, hint: str, limit: int = TOOL_RESULT_CHARS) -> str:
    """A tool message as valid JSON of at most ``limit`` characters that says what it left out.

    A long list (the result, or the longest list inside a dict result) keeps as many leading items
    as fit, plus the count omitted and a hint to narrow the call, so the model never counts hosts
    or uplinks from a silently cut list.
    """
    text = json.dumps(payload, default=str)
    if len(text) <= limit:
        return text
    res = payload.get("result")
    key = max((k for k, v in res.items() if isinstance(v, list)), key=lambda k: len(res[k]), default=None) if isinstance(res, dict) else None
    items = res if isinstance(res, list) else res[key] if key else None
    if items is None:
        return json.dumps({**{k: v for k, v in payload.items() if k != "result"}, "result": None, "truncated": True,
                           "result_chars": len(text), "hint": hint}, default=str)

    def cut(n: int) -> str:
        shown = items[:n] if key is None else {**res, key: items[:n]}
        return json.dumps({**payload, "result": shown, "truncated": True, "total_items": len(items),
                           "omitted_items": len(items) - n, "hint": hint}, default=str)

    lo, hi = 0, len(items)
    while lo < hi:  # the most leading items that fit
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if len(cut(mid)) <= limit else (lo, mid - 1)
    return cut(lo)


def _json_type(ann) -> dict:
    args = [a for a in typing.get_args(ann) if a is not type(None)]
    if args and type(None) in typing.get_args(ann):  # Optional[X] -> X
        ann = args[0]
    origin = typing.get_origin(ann)
    if ann in (str, "str"):
        return {"type": "string"}
    if ann in (int, "int"):
        return {"type": "integer"}
    if ann in (bool, "bool"):
        return {"type": "boolean"}
    if origin is list or ann is list or str(ann).startswith("list"):
        return {"type": "array", "items": {"type": "string"}}
    if origin is dict or ann is dict or str(ann).startswith("dict"):
        return {"type": "object"}
    return {"type": "string"}


class InvestigatorAgent:
    name = "investigator"

    def __init__(self, sv):
        self.sv = sv

    # ------------------------------------------------------------ tool specs
    def tool_specs(self) -> list[dict]:
        """OpenAI function specs for every read-only tool (dots become double underscores)."""
        specs = []
        for key, spec in sorted(self.sv.bus.registry.items()):
            if spec.write or key in EXCLUDE:
                continue
            props, required = {}, []
            hints = typing.get_type_hints(spec.fn)
            for pname, p in inspect.signature(spec.fn).parameters.items():
                props[pname] = _json_type(hints.get(pname, str))
                if p.default is inspect.Parameter.empty:
                    required.append(pname)
            specs.append({"type": "function", "function": {
                "name": key.replace(".", "__"), "description": (spec.description or "").strip()[:300],
                "parameters": {"type": "object", "properties": props, "required": required}}})
        return specs

    def _call(self, key: str, args: dict) -> tuple[object, str]:
        if key in EXCLUDE or key not in self.sv.bus.registry or self.sv.bus.registry[key].write:
            raise PermissionError(f"{key} is not an allowed read-only tool")
        return self.sv.bus.call(self.name, key, **args)

    # ------------------------------------------------------------------ ask
    def ask(self, question: str, state: dict | None = None, topo=None, max_steps: int = 6) -> dict:
        state = state or {}
        if topo is None:
            from .topology_agent import TopologyAgent

            topo, _ = TopologyAgent(self.sv).run()
        if self.sv.llm.supports_tools:
            out = self._ask_llm(question, state, max_steps)
        else:
            out = self._ask_offline(question, state, topo)
        out["verification"] = self.verify(out["answer"], state, topo)
        return out

    @staticmethod
    def _context(state: dict) -> dict:
        """The run facts the offline router answers from, compact and with their evidence ids, for the live model."""
        context: dict = {}
        if state.get("change_request"):
            context["change_request"] = state["change_request"].get("summary")
        if state.get("status"):
            context["run_status"] = state["status"]
        risk = (state.get("risk") or {}).get("assets", {})
        if risk:
            context["top_risks"] = [{"asset": r["asset"], "score": r["score"], "reasons": r["reasons"][:3], "evidence": r["evidence"][:3]}
                                    for r in sorted(risk.values(), key=lambda r: -r["score"])[:5]]
        if state.get("attempts"):
            context["plan_attempts"] = [{
                "attempt": a["attempt"], "provenance": a["provenance"], "passed": a.get("passed"),
                "trust_score": (a.get("verification") or {}).get("trust_score"),
                "violated_rules": sorted({v["code"] for v in a["constraints"]["violations"]}),
                "contradicted_claims": [{"claim": c["text"], "why": c["explanation"], "evidence": c["evidence"][:3]}
                                        for c in (a.get("verification") or {}).get("claims", []) if c["label"] == "Contradicted"][:4],
            } for a in state["attempts"]]
        if state.get("plan"):
            waves = state["plan"]["waves"]
            context["plan"] = {"waves": [w["assets"] for w in waves], "canary": waves[0]["assets"] if waves else []}
            cov = (state.get("constraints") or {}).get("canary_coverage")
            if cov:
                context["plan"]["canary_coverage"] = {k: cov[k] for k in ("covered", "total", "hosts_represented", "hosts_total")}
        if state.get("executions"):
            context["executions"] = [{"wave": x["index"], "assets": x["assets"], "result": x.get("result"), "evidence": x.get("evidence"),
                                      "regressions": [{k: r.get(k) for k in ("asset", "metric", "pre", "post", "message")}
                                                      for r in x.get("regressions", [])[:3]]} for x in state["executions"]]
        if state.get("halt_reason"):
            context["halt_reason"] = state["halt_reason"]
        if state.get("rollback"):
            rb = state["rollback"]
            context["rollback"] = {"reverted": len(rb["reverted"]), "recovered": rb.get("recovered"), "evidence": rb.get("evidence")}
        if state.get("lesson"):
            context["lesson"] = {k: state["lesson"].get(k) for k in ("id", "component", "version", "symptom", "lesson")}
        return context

    def _ask_llm(self, question: str, state: dict, max_steps: int) -> dict:
        context = self._context(state)
        messages = [{"role": "system", "content": load_prompt("investigator")},
                    {"role": "user", "content": question + (f"\n\nContext: {json.dumps(context)}" if context else "")}]
        tools, steps = self.tool_specs(), []
        for _ in range(max_steps):
            turn = self.sv.llm.chat_tools("investigator", messages, tools)
            if not turn["tool_calls"]:
                return {"answer": turn["content"] or "", "steps": steps, "mode": f"llm:{self.sv.llm.model}"}
            messages.append({"role": "assistant", "content": turn["content"] or "",
                             "tool_calls": [{"id": c["id"], "type": "function",
                                             "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}}
                                            for c in turn["tool_calls"]]})
            for c in turn["tool_calls"]:
                key = c["name"].replace("__", ".")
                try:
                    res, ev = self._call(key, c["arguments"])
                    payload = {"evidence_id": ev, "result": res}
                except Exception as exc:  # noqa: BLE001 - the model sees the error and can recover
                    payload, ev = {"error": str(exc)}, None
                steps.append({"tool": key, "args": c["arguments"], "evidence": ev})
                params = list(inspect.signature(self.sv.bus.registry[key].fn).parameters) if key in self.sv.bus.registry else []
                hint = "result cut to fit; " + (f"narrow the call with its arguments ({', '.join(params)})" if params else "ask a narrower question")
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": _fit(payload, hint)})
        messages.append({"role": "user", "content": "Tool budget exhausted. Answer now with what the evidence shows."})
        turn = self.sv.llm.chat_tools("investigator", messages, [])
        return {"answer": turn["content"] or "", "steps": steps, "mode": f"llm:{self.sv.llm.model}"}

    def _ask_offline(self, question: str, state: dict, topo) -> dict:
        """Deterministic stand-in for the model's tool choices (offline mode)."""
        q = question.lower()
        steps, sentences = [], []

        def say(text: str, *evs) -> None:
            ids = [e for e in evs if e]
            sentences.append(text + (f" [{', '.join(ids)}]" if ids else "") + ".")

        def call(key, **args):
            res, ev = self._call(key, args)
            steps.append({"tool": key, "args": args, "evidence": ev})
            return res, ev

        servers = [s for s in topo.servers if re.search(rf"\b{re.escape(s)}\b", q)]
        switches = [s for s in topo.switches if re.search(rf"\b{re.escape(s)}\b", q)]
        clusters = [c for c in topo.clusters if c.lower() in q]
        cves = sorted({m.upper() for m in CVE_RE.findall(question)})
        lldp, lev = (call("network.get_lldp_neighbors") if servers or switches else (None, None))
        ups: dict[str, set[str]] = {}
        for p in lldp or []:
            if p["status"] == "up" and p.get("neighbor"):
                ups.setdefault(p["neighbor"], set()).add(p["switch"])

        for s in servers:
            srv, ev = call("compute.get_server", name=s)
            vms, vev = call("virt.list_vms", host=s)
            n_up = len(ups.get(s, ()))
            say(f"{s} is {'single' if n_up < 2 else 'dual'}-homed", lev)
            say(f"{s} is a {srv['model'].replace('HPE ProLiant ', '')} in {srv['cluster']} running iLO 6 "
                f"{srv['firmware'].get('iLO 6')}, System ROM {srv['firmware'].get('System ROM')} and NIC firmware "
                f"{major(srv['firmware'].get('NIC BCM57414', '?'))}x", ev)
            t0 = [v["name"] for v in vms if v["tier"] == 0]
            say(f"{s} runs {len(vms)} VMs" + (f", including tier-0 {', '.join(t0)}" if t0 else ", none of them tier-0"), vev)
        for w in switches:
            sw, ev = call("network.get_switch", name=w)
            peer = (sw.get("redundancy") or {}).get("peer")
            hosts = sorted(h for h, s in ups.items() if w in s and h in topo.servers)
            only = sorted(h for h in hosts if ups.get(h) == {w})
            say(f"{w} is a {sw['model']} on {sw['os']} {sw['firmware']} with redundancy peer {peer}", ev)
            say(f"{len(hosts)} hosts have a live uplink to {w}", lev)
            for h in only:
                vms, vev = call("virt.list_vms", host=h)
                t0 = [v["name"] for v in vms if v["tier"] == 0]
                say(f"{h} is single-homed", lev)
                if t0:
                    say(f"{h} runs tier-0 {', '.join(t0)}, so {w} rebooting while {h} is in service isolates it", vev)
            arrays = sorted({p["neighbor"] for p in lldp if p["switch"] == w and p.get("neighbor") and p["neighbor"] not in topo.servers
                             and p["neighbor"] not in topo.switches})
            if arrays:
                say(f"{w} carries storage ports of {', '.join(arrays)}", lev)
        for c in clusters:
            vms, vev = call("virt.list_vms", cluster=c)
            hs, hev = call("compute.list_servers", cluster=c)
            cls, cev = call("virt.list_clusters")
            cl = next(x for x in cls if x["name"] == c)
            demand = sum(v["memoryGB"] for v in vms)
            per_host = sum(h["memoryGB"] for h in hs) / max(1, len(hs))
            lim = cl.get("maxMemoryUtilPct", 85) / 100
            k = max([k for k in range(len(hs)) if demand <= lim * per_host * (len(hs) - k)], default=0)
            say(f"{c} can tolerate {k} hosts in maintenance at once", vev, hev, cev)
        for cve in cves:
            advs, aev = call("knowledge.list_advisories", cve=cve)
            for a in advs:
                fx = a.get("fixed_in") or {}
                say(f"{a['id']} says {cve} is fixed in {fx.get('component')} {fx.get('version')}", aev)
            for r in self.sv.kb.release_notes:
                if cve in r.get("security_fixes", []):
                    rn, rev = call("knowledge.get_release_notes", component=r["component"], version=r["version"])
                    say(f"{rn['component']} {rn['version']} fixes {cve}", rev)
            if not advs and not any(cve in r.get("security_fixes", []) for r in self.sv.kb.release_notes):
                say(f"The knowledge base has no release note or advisory for {cve}", aev)
        execs = state.get("executions") or []
        about_attempts = bool(re.search(r"\b(attempts?|drafts?|plans?|reject\w*|block\w*)\b", q))
        about_run = bool(re.search(r"\b(fail\w*|wrong|regress\w*|roll ?back\w*|rolled back|halt\w*|happened|lesson|incident)\b", q))
        if about_run and not about_attempts and (execs or state.get("halt_reason")):
            # What the change did: post-check regressions, the halt and rollback, and the lesson it recorded.
            if "canary" in q and execs and execs[0].get("result") == "passed":
                say(f"The canary ({', '.join(execs[0]['assets'])}) passed its signal checks", (execs[0].get("evidence") or {}).get("post"))
            for ex in [x for x in execs if x.get("result") == "regression"]:
                ev = ex.get("evidence") or {}
                say(f"{'The canary' if ex['index'] == 1 else ex['name']} ({', '.join(ex['assets'])}) regressed on "
                    + ", ".join(sorted({r["asset"] for r in ex["regressions"]})), ev.get("post"))
                for r in ex["regressions"][:3]:
                    if r.get("check") == "statistical":
                        series = [e for e in (ex.get("canary_stats") or {}).get("evidence", [])
                                  if (self.sv.evidence.get(e) or {}).get("args", {}).get("asset") == r["asset"]]
                        say(f"Against un-upgraded peers, {r['asset']} {r['message']}", *series[:2])
                    else:
                        say(f"{r['asset']} {METRIC.get(r['metric'], r['metric'])} went from {r['pre']} to {r['post']}", ev.get("pre"), ev.get("post"))
            if state.get("halt_reason"):
                say(f"Execution halted: {state['halt_reason'].rstrip('.')}")
            rb = state.get("rollback")
            if rb:
                hosts = sorted({c["asset"] for c in rb["reverted"]})
                say(f"BlastRadius halted the remaining waves and reverted {len(rb['reverted'])} firmware change(s) on {', '.join(hosts)}; "
                    f"their signals {'recovered' if rb.get('recovered') else 'did NOT recover'}", rb.get("evidence"))
            lesson = state.get("lesson")
            if lesson:
                _, iev = call("knowledge.list_incidents", component=lesson["component"], version=lesson["version"])
                say(f"The lesson was recorded as {lesson['id']}: {lesson['symptom'].rstrip('.')}", iev)
                for part in _sentences(lesson["lesson"]):
                    say(part.rstrip("."), iev)
        elif about_run and not about_attempts and "canary" in q:
            say("The canary has not run yet in this change, so there is no canary result to explain")
        attempts = state.get("attempts") or []
        if attempts and (about_attempts or (about_run and not execs and "canary" not in q)):
            m = re.search(r"\b(?:attempt|draft)\s*#?(\d+)", q)
            pick = ([a for a in attempts if m and a["attempt"] == int(m.group(1))]
                    or [a for a in attempts if not a["passed"]][:1] or attempts[-1:])
            for a in pick:
                ver, viol = a["verification"], a["constraints"]["violations"]
                bad = [c for c in ver["claims"] if c["label"] == "Contradicted"]
                if a["passed"]:
                    say(f"Attempt {a['attempt']} passed with no constraint violations and Trust Score {ver['trust_score']:.0f}")
                    continue
                say(f"Attempt {a['attempt']} was rejected with {len(viol)} constraint violations and Trust Score "
                    f"{ver['trust_score']:.0f}, {len(bad)} claims contradicted")
                codes = sorted({v["code"] for v in viol})
                if codes:
                    say(f"The violated rules were {', '.join(codes)}")
                for c in bad[:2]:  # the Verifier's own findings, each sentence with the evidence it rests on
                    for part in _sentences(c["explanation"]):
                        say(part.rstrip("."), *c["evidence"][:3])
        cov = (state.get("constraints") or {}).get("canary_coverage")
        if cov and state.get("plan") and "canary" in q:
            canary = [x for x in state["plan"]["waves"][0]["assets"] if x in topo.servers]
            say(f"The canary {', '.join(canary)} covers {cov['covered']}/{cov['total']} configuration cohorts")
        risk = (state.get("risk") or {}).get("assets", {})
        if re.search(r"\b(risk|risky|riskiest)\b", q) or (re.search(r"\bwhy\b", q) and (servers or switches)):
            named = servers + switches or sorted(risk, key=lambda a: -risk[a]["score"])[:1]
            for a in named:
                if a in risk:
                    r = risk[a]
                    say(f"The Risk agent scored {a} {r['score']}/100: {'; '.join(r['reasons'][:3])}", *r["evidence"][:3])
        if not sentences:
            sentences.append("I could not map the question to a host, switch, cluster or CVE in the inventory. "
                             "Name one and I will look it up.")
        return {"answer": " ".join(sentences), "steps": steps, "mode": "offline router (stand-in for model tool choice)"}

    # --------------------------------------------------------------- verify
    def verify(self, answer: str, state: dict, topo) -> dict:
        # Citations go before the full stop so each claim keeps its own evidence ids.
        text = TRAILING_CITE.sub(r" \1.", answer)
        plan = {"waves": (state.get("plan") or {}).get("waves", []), "rationale": text, "self_confidence": None}
        cr = state.get("change_request") or {"components": [], "window": {"duration_minutes": 480}}
        risk = state.get("risk") or {"target_versions": {}}
        res = VerifierAgent(self.sv).run(plan, cr, topo, risk)
        return {k: res[k] for k in ("claims", "trust_score", "counts", "passed", "verifier_model")}
