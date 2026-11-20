"""Rollback feasibility: the iLO downgrade policy, from inventory to canary choice, card and rollback."""

import pytest
from conftest import INTENT

from blastradius.config import PUBLISHED_KEYS, Settings
from blastradius.twin import TwinError


def test_the_lab_card_reports_every_host_reversible(engine):
    card = engine.start(INTENT)["interrupt"]
    assert card["rollback_feasibility"] == {"hosts": 40, "allow": 40, "blocked": [], "unknown": []}
    assert not any("rolled back automatically" in w for w in card["warnings"])


def test_a_host_that_refuses_downgrades_is_never_the_canary(sv, engine):
    sv.twin.servers["blr-esx-01"]["ilo"]["downgradePolicy"] = "NoDowngrade"
    r = engine.start(INTENT)
    card = r["interrupt"]
    assert "blr-esx-01" not in card["waves"][0]["assets"]
    assert card["canary_coverage"]["ok"]  # another host of the same cohort stands in
    assert card["rollback_feasibility"]["blocked"] == [{"host": "blr-esx-01", "policy": "NoDowngrade"}]
    assert any("cannot be rolled back automatically" in w and "blr-esx-01" in w for w in card["warnings"])
    assert any("iLO downgrade policy NoDowngrade" in x for x in r["state"]["risk"]["assets"]["blr-esx-01"]["reasons"])


def test_the_twin_refuses_a_downgrade_its_ilo_policy_forbids(sv):
    t = sv.twin
    t.servers["blr-esx-02"]["ilo"]["downgradePolicy"] = "NoDowngrade"
    t.apply_firmware("blr-esx-02", "iLO 6", "1.64")  # an upgrade is always allowed
    with pytest.raises(TwinError, match="refuses iLO 6 1.64 -> 1.58"):
        t.apply_firmware("blr-esx-02", "iLO 6", "1.58")
    t.servers["blr-esx-02"]["ilo"]["downgradePolicy"] = "AllowDowngrade"
    t.apply_firmware("blr-esx-02", "iLO 6", "1.58")


def test_a_rollback_ilo_refuses_stops_and_lists_the_manual_steps(sv, engine):
    r = engine.start(INTENT)
    canary = r["interrupt"]["waves"][0]["assets"]
    assert "blr-esx-01" in canary  # the host the demo regression hits
    sv.twin.servers["blr-esx-01"]["ilo"]["downgradePolicy"] = "NoDowngrade"  # changed on the device after planning
    st = engine.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})["state"]
    assert st["status"] == "halted" and "downgrade policy NoDowngrade" in st["rollback"]["blocked"]
    assert any("blr-esx-01" in step for step in st["manual_steps"])


def test_no_published_signing_key_is_ever_used(tmp_path, monkeypatch):
    for value in ["", *PUBLISHED_KEYS]:
        monkeypatch.setenv("BR_SIGNING_KEY", value)
        s = Settings(runtime_dir=tmp_path / "rt")
        assert s.signing_key_source == "generated" and s.signing_key not in PUBLISHED_KEYS and len(s.signing_key) == 64
    # every process sharing the runtime directory gets the same key; another installation gets its own
    assert Settings(runtime_dir=tmp_path / "rt").signing_key == s.signing_key
    assert Settings(runtime_dir=tmp_path / "other").signing_key != s.signing_key
    assert oct((tmp_path / "rt" / "signing.key").stat().st_mode & 0o777) == "0o600"
    monkeypatch.setenv("BR_SIGNING_KEY", "a-real-secret")
    s = Settings(runtime_dir=tmp_path / "rt")
    assert (s.signing_key, s.signing_key_source) == ("a-real-secret", "BR_SIGNING_KEY")


def test_a_ledger_signed_with_a_published_key_is_set_aside_not_reported_as_tampered(tmp_path, monkeypatch):
    from blastradius.ledger import Ledger

    monkeypatch.delenv("BR_SIGNING_KEY", raising=False)
    rt = tmp_path / "rt"
    old = Ledger(rt / "ledger.sqlite", "blastradius-demo-key-change-me")  # what an earlier version left behind
    old.append("r", "system", "run_started", {})
    s = Settings(runtime_dir=rt)  # the upgrade: first run with a generated key
    assert (rt / "ledger.sqlite.published-key").exists() and not (rt / "ledger.sqlite").exists()
    new = Ledger(rt / "ledger.sqlite", s.signing_key)
    new.append("r", "system", "run_started", {})
    assert new.verify()["ok"]
    assert Settings(runtime_dir=rt).signing_key == s.signing_key and (rt / "ledger.sqlite").exists()  # only once
