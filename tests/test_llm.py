import json
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
