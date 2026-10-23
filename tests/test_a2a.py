import json
import threading
import urllib.request

import pytest

from blastradius.a2a_server import A2AService, make_server
from blastradius.workflow import Engine


@pytest.fixture
def server(sv):
    svc = A2AService(Engine(sv))
    srv = make_server(svc, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield svc
    srv.shutdown()


def rpc(svc, method, params, rid=1):
    req = urllib.request.Request(svc.base_url + "/a2a", data=json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def test_agent_card_is_served(server):
    with urllib.request.urlopen(server.base_url + "/.well-known/agent-card.json", timeout=10) as r:
        card = json.loads(r.read())
    assert card["url"] == server.base_url + "/a2a" and [s["id"] for s in card["skills"]] == ["assess-change"]


def test_static_card_and_cli_card_are_the_served_card(capsys):
    from blastradius.a2a_server import agent_card
    from blastradius.cli import main
    from blastradius.config import ROOT

    main(["a2a-card"])
    printed = json.loads(capsys.readouterr().out)
    assert printed == agent_card() == json.loads((ROOT / "a2a" / "agent-card.json").read_text())
    assert printed["url"] == "http://127.0.0.1:8765/a2a"  # a2a-serve's defaults, not the Streamlit port


def test_send_message_returns_go_no_go_and_never_executes(server, sv):
    before = sv.twin.snapshot()["firmware"]
    msg = {"message": {"role": "user", "messageId": "m1", "parts": [{"kind": "text", "text":
           "Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair to the latest baseline this Saturday 10pm"}]}}
    res = rpc(server, "message/send", msg)["result"]
    assert res["status"]["state"] == "input-required"
    data = res["artifacts"][0]["parts"][0]["data"]
    assert data["trust_score"] >= 80 and data["plan_hash"] and data["waves"]
    assert any("SYN-CVE-2026-1105" in c for c in data["contradicted_claims_first_attempt"])
    assert sv.twin.snapshot()["firmware"] == before  # analysis only
    again = rpc(server, "GetTask", {"id": res["id"]})["result"]
    assert again["id"] == res["id"]


def test_errors(server):
    assert rpc(server, "tasks/cancel", {"id": "x"})["error"]["code"] == -32002
    assert rpc(server, "nope", {})["error"]["code"] == -32601
    assert rpc(server, "message/send", {"message": {"parts": []}})["error"]["code"] == -32603


def test_message_naming_no_known_asset_is_rejected(server, sv):
    msg = {"message": {"role": "user", "messageId": "m9", "metadata": {"skillId": "execute-approved-change"},
                       "parts": [{"kind": "text", "text": "Execute approved plan 20261022-000000-abcd"}]}}
    res = rpc(server, "message/send", msg)["result"]
    assert res["status"]["state"] == "rejected"
    assert "no recognised targets" in res["status"]["message"]["parts"][0]["text"]
    data = res["artifacts"][0]["parts"][0]["data"]
    assert data["status"] == "escalated" and data["attempts"] == 0 and "plan_hash" not in data
