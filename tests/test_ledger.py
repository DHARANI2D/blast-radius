from pathlib import Path

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


def test_deleting_the_newest_entries_or_rechaining_without_the_key_is_detected(tmp_path):
    import sqlite3

    path = tmp_path / "l.sqlite"
    led = Ledger(path, "k1")
    for i in range(6):
        led.append("run-1", "agent:test", "event", {"i": i})
    assert led.verify()["ok"] and led.read_anchor()["seq"] == 6
    db = sqlite3.connect(path)
    db.execute("DELETE FROM ledger WHERE seq >= 5")  # drop the halt / rollback / report records
    db.commit()
    v = Ledger(path, "k1").verify()
    assert not v["ok"] and v["broken_at"] == 5 and "removed" in v["reason"]
    # an attacker without the key re-chains the remaining rows and rewrites the anchor: still detected
    forged = Ledger(tmp_path / "forged.sqlite", "guessed-key")
    for e in Ledger(path, "k1").entries():
        forged.append(e["run_id"], e["actor"], e["event"], e["payload"])
    v = Ledger(tmp_path / "forged.sqlite", "k1").verify()
    assert not v["ok"] and v["broken_at"] == 1
    # an anchor moved back to match the truncated table without the key is rejected too
    (tmp_path / "l.sqlite.anchor").write_text('{"seq": 4, "head": "%s", "mac": "x"}' % Ledger(path, "k1").head()[1])
    assert Ledger(path, "k1").verify()["reason"] == "head anchor signature invalid"


def test_in_memory_ledger_keeps_its_anchor():
    led = Ledger(":memory:", "k")
    led.append("r", "a", "e", {})
    assert led.verify()["ok"] and led.read_anchor()["seq"] == 1


def test_the_head_anchor_can_live_away_from_the_database(tmp_path):
    db, anchor = tmp_path / "db" / "ledger.sqlite", tmp_path / "worm" / "head.anchor"
    led = Ledger(db, "k", anchor_path=anchor)
    for i in range(3):
        led.append("r", "a", "e", {"i": i})
    assert anchor.exists() and not Path(f"{db}.anchor").exists() and led.verify()["ok"]
    led._db.execute("DELETE FROM ledger WHERE seq = (SELECT MAX(seq) FROM ledger)")
    led._db.commit()
    assert not Ledger(db, "k", anchor_path=anchor).verify()["ok"]  # the newest entry was removed
