import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from blastradius.llm import LLMError, OpenAICompatClient
from blastradius.models import Plan

SEEN = []


class _Handler(BaseHTTPRequestHandler):
    replies: list = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        content = self.replies.pop(0)
        out = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    SEEN.clear()
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def client(server, redact=lambda s: s.replace("SECRET", "[REDACTED]"), style="openai"):
    return OpenAICompatClient(f"http://127.0.0.1:{server.server_port}/v1", "k", "nemotron-test", style, "2024-10-21", 5, redact)


GOOD = json.dumps({"waves": [{"name": "w1", "assets": ["blr-esx-03"]}], "rationale": "r", "self_confidence": 70})


def test_openai_compatible_call_validates_schema_and_redacts(server):
    _Handler.replies = ["not json at all", "```json\n" + GOOD + "\n```"]
    out = client(server).complete_json("planner", "sys", "password SECRET", Plan, context={})
    assert out.waves[0].assets == ["blr-esx-03"]
    assert len(SEEN) == 2  # one repair round-trip
    first = SEEN[0]
    assert first["path"] == "/v1/chat/completions" and first["body"]["model"] == "nemotron-test"
    assert "SECRET" not in json.dumps(first["body"])
    assert first["headers"]["authorization"] == "Bearer k"


def test_gives_up_after_three_invalid_replies(server):
    _Handler.replies = ["{}", "{}", "{}"]
    with pytest.raises(LLMError):
        client(server).complete_json("planner", "s", "u", Plan, context={})


def test_azure_url_scheme(server):
    _Handler.replies = [GOOD]
    client(server, style="azure").complete_json("planner", "s", "u", Plan, context={})
    assert SEEN[0]["path"].startswith("/v1/openai/deployments/nemotron-test/chat/completions?api-version=")
    assert SEEN[0]["headers"]["api-key"] == "k"


def test_extract_json_tolerates_prose_think_blocks_citations_and_fences():
    from pydantic import BaseModel

    from blastradius.llm import _extract_json

    class Summary(BaseModel):
        summary: str

    def get(text):
        return _extract_json(text, Summary.model_validate).summary

    assert get('{"summary": "ok"}\n\nI hope this helps the CAB.') == "ok"
    assert get('Based on [EV-0042], my judgement is: {"summary": "cited"}') == "cited"
    assert get('<think>The plan is {roughly} fine</think>\n{"summary": "thought"}') == "thought"
    assert get('Draft:\n```\n{"summary": "draft"}\n```\nFinal:\n```json\n{"summary": "final"}\n```') == "final"
    with pytest.raises(json.JSONDecodeError):
        get("no json here")


def test_trailing_prose_needs_no_repair_round_trip(server):
    _Handler.replies = [GOOD + "\n\nLet me know if the CAB needs more detail."]
    out = client(server).complete_json("planner", "s", "u", Plan, context={})
    assert out.rationale == "r" and len(SEEN) == 1


class _FaultyHandler(BaseHTTPRequestHandler):
    """Each request takes the next fault: (status, raw body bytes) or "slow" / "reset"."""

    faults: list = []

    def do_POST(self):  # noqa: N802
        import socket
        import time

        self.rfile.read(int(self.headers["Content-Length"]))
        fault = self.faults.pop(0)
        if fault == "slow":
            time.sleep(1.5)
            fault = (200, json.dumps({"choices": [{"message": {"content": GOOD}}]}).encode())
        if fault == "reset":
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        status, out = fault
        self.send_response(status)
        if status == 429:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def _reply(content):
    return 200, json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()


@pytest.mark.parametrize("faults,expect", [
    ([(200, b"<html>Sign in to the gateway</html>")], "non-JSON body"),
    (["slow"], "TimeoutError"),
    (["reset", "reset", "reset"], "RemoteDisconnected"),
    ([(200, b'{"choices": []}')], "unexpected LLM response shape"),
    ([(400, b'{"error": "bad request"}')], "HTTP 400"),
])
def test_transport_and_shape_failures_surface_as_llm_error(faults, expect):
    srv = HTTPServer(("127.0.0.1", 0), _FaultyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _FaultyHandler.faults = list(faults)
    c = OpenAICompatClient(f"http://127.0.0.1:{srv.server_port}/v1", "", "m", "openai", "", 0.5, lambda s: s)
    c.retry_backoff_s = 0
    try:
        with pytest.raises(LLMError, match=expect):
            c.complete_json("planner", "s", "u", Plan, context={})
    finally:
        srv.shutdown()


def test_null_content_is_repaired_and_rate_limits_are_retried():
    srv = HTTPServer(("127.0.0.1", 0), _FaultyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _FaultyHandler.faults = [(429, b'{"error": "rate limited"}'), (503, b"busy"), _reply(None), _reply(GOOD)]
    c = OpenAICompatClient(f"http://127.0.0.1:{srv.server_port}/v1", "", "m", "openai", "", 5, lambda s: s)
    c.retry_backoff_s = 0
    try:
        out = c.complete_json("planner", "s", "u", Plan, context={})
    finally:
        srv.shutdown()
    assert out.waves[0].assets == ["blr-esx-03"] and _FaultyHandler.faults == []


def test_default_llm_timeout_suits_a_slow_model(monkeypatch):
    from blastradius.config import Settings

    monkeypatch.delenv("BR_LLM_TIMEOUT_S", raising=False)
    assert Settings().llm_timeout_s == 180


def test_planner_explain_asks_only_for_the_rationale(server, tmp_path):
    """A live model that re-explains the optimised waves without echoing them is accepted on the first reply."""
    from conftest import INTENT, make_services

    from blastradius.agents import IntakeAgent, PlannerAgent, RiskAgent, TopologyAgent
    from blastradius.llm import load_prompt

    sv = make_services(tmp_path)
    cr = IntakeAgent(sv).run(INTENT)
    topo, _ = TopologyAgent(sv).run()
    risk = RiskAgent(sv).run(cr["targets"], cr["change_request"]["components"], topo)
    sv.llm = client(server)
    _Handler.replies = [json.dumps({"rationale": "Wave 1 is a canary of blr-esx-03.", "self_confidence": 90})]
    out = PlannerAgent(sv).explain([{"name": "w1", "assets": ["blr-esx-03"]}], cr["change_request"], cr["targets"], risk, topo, 60)
    assert out["rationale"] == "Wave 1 is a canary of blr-esx-03." and out["self_confidence"] == 90 and len(SEEN) == 1
    assert '"waves"' not in load_prompt("planner_explain")


def test_prompt_hash_is_of_the_redacted_prompt_that_was_sent(server):
    import hashlib

    _Handler.replies = [GOOD]
    c = client(server)
    c.complete_json("planner", "system SECRET", "user SECRET", Plan, context={})
    sent = SEEN[0]["body"]["messages"]
    assert "SECRET" not in json.dumps(sent)
    assert c.last()["prompt_sha256"] == hashlib.sha256((sent[0]["content"] + sent[1]["content"]).encode()).hexdigest()


def test_dotenv_file_is_loaded_without_overriding_the_environment(tmp_path, monkeypatch):
    from blastradius.config import Settings, load_env_file

    env = tmp_path / ".env"
    env.write_text("# comment\nBR_LLM_MODE=openai\nexport BR_LLM_MODEL='approved-x'   \nBR_TOOL_TRANSPORT=inproc          # mcp | inproc\n"
                   "BR_FAULTS=off\nBR_VERIFIER_MODEL=\nnot a line\n")
    for k in ("BR_LLM_MODE", "BR_LLM_MODEL", "BR_TOOL_TRANSPORT", "BR_VERIFIER_MODEL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BR_FAULTS", "subtle")  # already set: the file must not win
    monkeypatch.setenv("BR_ENV_FILE", str(env))
    try:
        assert load_env_file() == {"BR_LLM_MODE": "openai", "BR_LLM_MODEL": "approved-x", "BR_TOOL_TRANSPORT": "inproc"}
        s = Settings()
        assert (s.llm_mode, s.llm_model, s.tool_transport, s.fault_scenario, s.verifier_model) == ("openai", "approved-x", "inproc", "subtle", "")
    finally:
        for k in ("BR_LLM_MODE", "BR_LLM_MODEL", "BR_TOOL_TRANSPORT"):
            os.environ.pop(k, None)
