"""A2A endpoint: lets an upstream agent (an OpsRamp or Morpheus copilot, a change-ticket
workflow) ask BlastRadius to assess a change.

Read-only by design. The skill runs intake, discovery, risk, planning and verification,
then stops at the human approval gate and returns the go/no-go card as the task
artifact with state ``input-required``. Approval and execution are only possible
through a human in the Control Tower; there is no A2A method that approves.

Transport: JSON-RPC 2.0 over HTTP (stdlib server), agent card served at
``/.well-known/agent-card.json`` (and the older ``/.well-known/agent.json``).
Method names are accepted in both the slash form used by A2A 0.x (``message/send``,
``tasks/get``) and the PascalCase form (``SendMessage``, ``GetTask``). This is a
subset of the protocol (no streaming, no push notifications) and has not been run
against an official A2A conformance suite.

    python -m blastradius a2a-serve --port 8765
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


SEND = {"message/send", "SendMessage"}
GET = {"tasks/get", "GetTask"}
CANCEL = {"tasks/cancel", "CancelTask"}


DEFAULT_BASE_URL = "http://127.0.0.1:8765"  # a2a-serve's default --host and --port

# The one definition of the card: a2a-serve serves it, ``python -m blastradius a2a-card``
# prints it, and a2a/agent-card.json is that output (regenerate it with the CLI).
# Only the skill this endpoint implements is listed.
CARD = {
    "protocolVersion": "1.0",
    "name": "BlastRadius Change-Safety Agent",
    "description": "Predicts the cross-domain blast radius of firmware and configuration changes on HPE compute, network and "
                   "virtualization, plans canary waves and verifies every planner claim against tool evidence (Trust Score). "
                   "Read-only over A2A: approval and execution happen only in the Control Tower, by a human.",
    "version": "0.1.0",
    "provider": {"organization": "HPE Agentic AI Hackathon India 2026 team (PoC)"},
    "defaultInputModes": ["text/plain", "application/json"],
    "defaultOutputModes": ["application/json", "text/markdown"],
    "capabilities": {"streaming": False, "pushNotifications": False},
    "skills": [{
        "id": "assess-change",
        "name": "Assess change blast radius",
        "description": "Natural-language change intent in; dependency graph, per-asset risk, staged wave plan, Trust Score and "
                       "go/no-go card out. Read-only.",
        "tags": ["change-management", "firmware", "risk", "dependency-graph"],
        "examples": ["Upgrade iLO 6 and System ROM on PROD-BLR-07 and the ToR switch pair to the latest baseline on Saturday"],
    }],
}


def agent_card(base_url: str = DEFAULT_BASE_URL) -> dict:
    return {**CARD, "url": base_url.rstrip("/") + "/a2a", "preferredTransport": "JSONRPC"}


def _text_of(message: dict) -> str:
    parts = message.get("parts") or []
    texts = [p.get("text", "") for p in parts if p.get("kind", p.get("type", "text")) == "text" or "text" in p]
    return " ".join(t for t in texts if t).strip()


def _summarise(run: dict) -> dict:
    """Compact, JSON-safe go/no-go card for an upstream agent."""
    card, st = run.get("interrupt") or {}, run["state"]
    ver = st.get("verification") or (st.get("attempts") or [{}])[-1].get("verification", {})
    out = {
        "run_id": run["run_id"],
        "summary": (st.get("change_request") or {}).get("summary"),
        "status": st.get("status"),
        "outcome_reason": st.get("outcome_reason"),
        "trust_score": ver.get("trust_score"),
        "planner_self_confidence": ver.get("self_confidence"),
        "attempts": len(st.get("attempts", [])),
        "contradicted_claims_first_attempt": [c["text"] for c in (st.get("attempts") or [{}])[0].get("verification", {}).get("claims", [])
                                              if c["label"] == "Contradicted"],
    }
    if card.get("scope") in ("canary", "fleet"):
        out.update({
            "plan_hash": card["plan_hash"],
            "max_blast_radius_score": card["max_brs"],
            "total_duration_min": card["total_duration_min"],
            "waves": [{"name": w["name"], "assets": w["assets"], "brs": w["brs"]} for w in card["waves"]],
            "deferred": card["deferred"],
            "top_risks": card["top_risks"],
            "canary_coverage": card.get("canary_coverage"),
            "required_approvers": card["required_approvers"],
            "approve_in": "BlastRadius Control Tower (human approval only; not available over A2A)",
        })
    elif card.get("scope") == "escalation":
        out["escalation"] = card.get("feedback")
    return out


class A2AService:
    def __init__(self, engine, base_url: str = "http://localhost:8765"):
        self.engine = engine
        self.base_url = base_url
        self.tasks: dict[str, dict] = {}
        self._lock = threading.Lock()

    def card(self) -> dict:
        return agent_card(self.base_url)

    def handle(self, req: dict) -> dict:
        rid = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}
        try:
            if req.get("jsonrpc") != "2.0":
                return _err(rid, -32600, "jsonrpc must be '2.0'")
            if method in SEND:
                return {"jsonrpc": "2.0", "id": rid, "result": self._send(params)}
            if method in GET:
                task = self.tasks.get(params.get("id", ""))
                return {"jsonrpc": "2.0", "id": rid, "result": task} if task else _err(rid, -32001, "task not found")
            if method in CANCEL:
                return _err(rid, -32002, "task cannot be canceled: nothing executes without human approval")
            return _err(rid, -32601, f"method not found: {method}")
        except Exception as exc:  # noqa: BLE001 - report as a JSON-RPC internal error
            return _err(rid, -32603, f"{type(exc).__name__}: {exc}")

    def _send(self, params: dict) -> dict:
        msg = params.get("message") or {}
        intent = _text_of(msg)
        if not intent:
            raise ValueError("message must contain a text part with the change intent")
        with self._lock:  # one analysis at a time: the twin and the graph are shared
            run = self.engine.start(intent)
        summary = _summarise(run)
        intr = run.get("interrupt") or {}
        reason = run["state"].get("outcome_reason")
        state = "input-required" if intr.get("scope") in ("canary", "fleet") else (
            "failed" if intr.get("scope") == "escalation" else "rejected" if run["state"].get("status") == "escalated" else "completed")
        note = {"input-required": "Plan verified. Awaiting human approval in the BlastRadius Control Tower.",
                "failed": "No plan passed constraints and verification; escalated to a human.",
                "rejected": f"Not a change BlastRadius can plan: {reason}.",
                "completed": f"Analysis finished: {reason}." if reason else "Analysis finished."}[state]
        task = {
            "kind": "task",
            "id": run["run_id"],
            "contextId": msg.get("contextId") or str(uuid.uuid4()),
            "status": {"state": state, "message": {"kind": "message", "role": "agent", "messageId": str(uuid.uuid4()),
                                                    "parts": [{"kind": "text", "text": note}]}},
            "artifacts": [{"artifactId": f"go-no-go-{run['run_id']}", "name": "go-no-go card",
                           "parts": [{"kind": "data", "data": summary}]}],
        }
        self.tasks[task["id"]] = task
        return task


def _err(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def make_server(service: A2AService, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, code: int, body: Any) -> None:
            data = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
                self._send_json(200, service.card())
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path.rstrip("/") not in ("/a2a", ""):
                self._send_json(404, {"error": "not found"})
                return
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            except json.JSONDecodeError:
                self._send_json(200, _err(None, -32700, "parse error"))
                return
            self._send_json(200, service.handle(req))

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    service.base_url = f"http://{host}:{srv.server_port}"
    return srv
