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
from .verifier import VerifierAgent

EXCLUDE = {"telemetry.advance_clock", "knowledge.record_incident", "network.wait_upgrade_complete"}
CVE_RE = re.compile(r"(?:SYN-)?CVE-\d{4}-\d+", re.I)
TRAILING_CITE = re.compile(r"\.\s*(\[EV-\d{4}(?:,\s*EV-\d{4})*\])")


def _json_type(ann) -> dict:
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

    def _ask_llm(self, question: str, state: dict, max_steps: int) -> dict:
        context = {}
        if state.get("change_request"):
            context["change_request"] = state["change_request"].get("summary")
        if state.get("plan"):
            context["approved_plan_waves"] = [w["assets"] for w in state["plan"]["waves"]]
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
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(payload, default=str)[:6000]})
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
        risk = (state.get("risk") or {}).get("assets", {})
        if re.search(r"\b(why|risk|risky|riskiest)\b", q):
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
