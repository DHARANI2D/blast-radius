from blastradius.approval import ApprovalAuthority
from blastradius.ledger import Ledger


def test_chain_verifies_and_detects_tampering(tmp_path):
    led = Ledger(tmp_path / "l.sqlite")
    for i in range(5):
        led.append("run-1", "agent:test", "event", {"i": i})
    assert led.verify()["ok"]
    led.tamper(3, {"i": 99})
    v = led.verify()
    assert not v["ok"] and v["broken_at"] == 3


def test_approval_signature_round_trip():
    auth = ApprovalAuthority("k")
    rec = auth.sign_approval("r", "planhash", "canary", "asha", "approve")
    body = {k: v for k, v in rec.items() if k != "signature"}
    assert auth.verify_signature(body, rec["signature"])
    assert not auth.verify_signature({**body, "approver": "mallory"}, rec["signature"])
