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
