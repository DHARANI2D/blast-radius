import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from blastradius.agents.investigator import InvestigatorAgent
from blastradius.llm import OpenAICompatClient


def test_offline_router_answers_with_cited_tool_evidence(sv, topo):
    out = InvestigatorAgent(sv).ask("How many hosts of PROD-BLR-07 can be in maintenance at once?", {}, topo)
    assert "PROD-BLR-07 can tolerate 7 hosts" in out["answer"]
    for eid in re.findall(r"EV-\d{4}", out["answer"]):
        assert sv.evidence.get(eid)
    assert out["verification"]["claims"][0]["type"] == "cluster_capacity"
    assert out["verification"]["claims"][0]["label"] == "Supported"


def test_offline_router_explains_a_rejected_attempt_and_the_canary(tmp_path):
    from conftest import make_services

    from blastradius.workflow import Engine

    sv = make_services(tmp_path)
    r = Engine(sv).start("Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair "
                         "to the latest baseline this Saturday 10pm")
    st, topo = r["state"], sv.runs[r["run_id"]]["topo"]
    out = InvestigatorAgent(sv).ask("Why was attempt 1 rejected?", st, topo)
    assert out["answer"].startswith("Attempt 1 was rejected with 13 constraint violations")
    assert "REDUNDANT_PAIR" in out["answer"] and "Risk agent" not in out["answer"]
    claims = out["verification"]["claims"]
    # the Verifier's own findings are restated with their evidence and hold up when re-checked
    lldp = next(c for c in claims if c["text"].startswith("LLDP shows blr-esx-07 with fewer than two live uplinks [EV-"))
    assert lldp["label"] == "Supported" and lldp["type"] == "single_homed"
    assert "Contradicted" not in {c["label"] for c in claims}
    cov = InvestigatorAgent(sv).ask("What does the canary cover?", st, topo)
    assert cov["answer"].endswith("covers 3/3 configuration cohorts.")
    assert [c["label"] for c in cov["verification"]["claims"]] == ["Supported"]
    # "why" alone no longer falls through to the riskiest asset
    assert "Risk agent" not in InvestigatorAgent(sv).ask("Why?", st, topo)["answer"]


def test_offline_router_explains_the_canary_regression_from_the_execution(tmp_path):
    from conftest import INTENT, make_services

    from blastradius.workflow import Engine

    sv = make_services(tmp_path)
    eng = Engine(sv)
    r = eng.start(INTENT)
    st, topo = r["state"], sv.runs[r["run_id"]]["topo"]
    before = InvestigatorAgent(sv).ask("Why did the canary fail?", st, topo)["answer"]
    assert before.startswith("The canary has not run yet") and "Attempt 1" not in before
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})
    st = r["state"]
    assert st["status"] == "rolled_back"
    for q in ("Why did the canary fail?", "What went wrong?"):
        out = InvestigatorAgent(sv).ask(q, st, topo)
        ans = out["answer"]
        assert ans.startswith("The canary (blr-esx-21, blr-esx-01, blr-esx-03) regressed on blr-esx-01 [EV-")
        assert "NIC latency (ms) went from" in ans and "reverted 6 firmware change(s)" in ans and "recovered" in ans
        assert f"recorded as {st['lesson']['id']}" in ans and "System ROM U54 v2.32 with NIC BCM57414 229.x" in ans
        assert "Attempt 1" not in ans
        counts = out["verification"]["counts"]
        assert "Contradicted" not in counts and out["verification"]["trust_score"] >= 90
    # questions about the plan attempts keep their own route
    assert InvestigatorAgent(sv).ask("Why was attempt 1 rejected?", st, topo)["answer"].startswith("Attempt 1 was rejected")


def test_investigator_never_calls_write_tools(sv):
    names = {t["function"]["name"] for t in InvestigatorAgent(sv).tool_specs()}
    assert "compute__apply_firmware" not in names and "virt__enter_maintenance" not in names
    assert "network__get_lldp_neighbors" in names
    with pytest.raises(PermissionError):
        InvestigatorAgent(sv)._call("compute.apply_firmware", {})


class _ToolUsingModel(BaseHTTPRequestHandler):
    """Fake OpenAI-compatible model: first asks for a tool, then answers citing the tool's evidence id."""

    seen: list = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.seen.append(body)
        last = body["messages"][-1]
        if last["role"] == "tool":
            ev = json.loads(last["content"])["evidence_id"]
            msg = {"role": "assistant", "content": f"blr-esx-07 is single-homed [{ev}]. blr-esx-03 is single-homed [{ev}]."}
        else:
            msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "network__get_lldp_neighbors", "arguments": json.dumps({"switch": "tor-r1-b"})}}]}
        out = json.dumps({"choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_live_function_calling_loop_is_verified(sv, topo):
    srv = HTTPServer(("127.0.0.1", 0), _ToolUsingModel)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        sv.llm = OpenAICompatClient(f"http://127.0.0.1:{srv.server_port}/v1", "k", "fake-tools", "openai", "x", 5, sv.policy.redact)
        out = InvestigatorAgent(sv).ask("Which hosts are single-homed?", {}, topo)
    finally:
        srv.shutdown()
    assert out["steps"] == [{"tool": "network.get_lldp_neighbors", "args": {"switch": "tor-r1-b"}, "evidence": out["steps"][0]["evidence"]}]
    assert any(t["function"]["name"] == "compute__get_server" for t in _ToolUsingModel.seen[0]["tools"])
    labels = {c["text"].split(" ")[0]: c["label"] for c in out["verification"]["claims"]}
    # the model's second sentence is false and the Verifier catches it from LLDP
    assert labels["blr-esx-07"] == "Supported" and labels["blr-esx-03"] == "Contradicted"
    assert not out["verification"]["passed"]


class _LoopingModel(BaseHTTPRequestHandler):
    """Asks for another tool while tools are offered; validates requests the way OpenAI does."""

    seen: list = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.seen.append(body)
        status = 200
        if ("tools" in body and not body["tools"]) or ("tool_choice" in body and not body.get("tools")):
            status, out = 400, {"error": {"message": "Invalid 'tools': empty array."}}
        elif body.get("tools"):
            out = {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": f"c{len(self.seen)}", "type": "function",
                 "function": {"name": "network__get_switch", "arguments": json.dumps({"name": "tor-r1-a"})}}]}}]}
        else:
            ev = json.loads(body["messages"][-2]["content"])["evidence_id"]
            out = {"choices": [{"message": {"role": "assistant", "content": f"tor-r1-a has redundancy peer tor-r1-b [{ev}]."}}]}
        data = json.dumps(out).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def test_final_answer_after_the_tool_budget_sends_no_tools(sv, topo):
    _LoopingModel.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _LoopingModel)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        sv.llm = OpenAICompatClient(f"http://127.0.0.1:{srv.server_port}/v1", "k", "fake-tools", "openai", "x", 5, sv.policy.redact)
        out = InvestigatorAgent(sv).ask("Tell me about tor-r1-a", {}, topo, max_steps=2)
    finally:
        srv.shutdown()
    final = _LoopingModel.seen[-1]
    assert len(_LoopingModel.seen) == 3 and "tools" not in final and "tool_choice" not in final
    assert out["answer"].startswith("tor-r1-a has redundancy peer tor-r1-b") and len(out["steps"]) == 2


class _Recorder:
    """A tool-calling client that records what the live model would be sent and answers at once."""

    supports_tools, model = True, "recorder"

    def __init__(self):
        self.seen = []

    def chat_tools(self, role, messages, tools, temperature=0.0):
        self.seen.append(messages)
        return {"content": "No answer.", "tool_calls": [], "message": {}}


def test_live_model_gets_the_run_facts_the_offline_router_uses(tmp_path):
    from conftest import drive, make_services

    from blastradius.workflow import Engine

    sv = make_services(tmp_path)
    r, _ = drive(Engine(sv))
    st, topo = r["state"], sv.runs[r["run_id"]]["topo"]
    sv.llm = rec = _Recorder()
    InvestigatorAgent(sv).ask("Why is tor-r1-a the riskiest asset? Why was attempt 1 rejected? Why did the canary fail?", st, topo)
    ctx = json.loads(rec.seen[0][1]["content"].split("\n\nContext: ", 1)[1])
    top = ctx["top_risks"][0]
    assert top["asset"] == "tor-r1-a" and top["reasons"] and all(sv.evidence.get(e) for e in top["evidence"])
    first = ctx["plan_attempts"][0]
    assert first["passed"] is False and "REDUNDANT_PAIR" in first["violated_rules"] and first["contradicted_claims"][0]["evidence"]
    assert ctx["plan"]["canary_coverage"]["covered"] == 3 and "approved_plan_waves" not in ctx
    assert ctx["executions"][0]["result"] == "regression" and ctx["executions"][0]["regressions"][0]["asset"] == "blr-esx-01"
    assert ctx["rollback"]["recovered"] is True and ctx["lesson"]["id"] == st["lesson"]["id"]
    assert len(rec.seen[0][1]["content"]) < 8000


def test_long_tool_results_stay_valid_json_and_say_what_was_left_out(sv):
    from blastradius.agents.investigator import _fit

    lldp, ev = sv.bus.call("investigator", "network.get_lldp_neighbors")
    assert len(json.dumps(lldp)) > 6000
    out = json.loads(_fit({"evidence_id": ev, "result": lldp}, "narrow the call with its arguments (switch)"))
    assert out["evidence_id"] == ev and out["truncated"] and out["total_items"] == len(lldp)
    assert out["omitted_items"] == len(lldp) - len(out["result"]) > 0 and out["result"] == lldp[:len(out["result"])]
    assert "switch" in out["hint"] and len(_fit({"evidence_id": ev, "result": lldp}, "h")) <= 6000
    nested = json.loads(_fit({"evidence_id": ev, "result": {"switch": "tor-r1-a", "ports": lldp}}, "h"))
    assert nested["result"]["switch"] == "tor-r1-a" and nested["omitted_items"] > 0
    assert json.loads(_fit({"evidence_id": ev, "result": "x" * 9000}, "h"))["result_chars"] > 9000
    small = {"evidence_id": ev, "result": lldp[:2]}
    assert json.loads(_fit(small, "h")) == small
