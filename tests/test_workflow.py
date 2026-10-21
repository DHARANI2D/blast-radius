import json

from conftest import INTENT, drive, make_services

from blastradius.workflow import Engine


def test_full_story_with_canary_regression(engine, sv):
    r, gates = drive(engine)
    st = r["state"]
    # first plan blocked by constraints and the verifier, second accepted
    a1, a2 = st["attempts"]
    assert not a1["passed"] and a1["verification"]["trust_score"] < 50
    assert any(c["label"] == "Contradicted" and "SYN-CVE-2026-1105" in c["text"] for c in a1["verification"]["claims"])
    assert a2["passed"] and a2["verification"]["trust_score"] >= 80
    # only the canary gate is reached; the canary regresses and is rolled back
    assert [g["scope"] for g in gates] == ["canary"]
    assert st["status"] == "rolled_back"
    assert st["rollback"]["recovered"] is True
    # the cohort canary includes a DL380 on NIC 229.x (regresses) and a DL380 on NIC 230.x (control)
    assert {"blr-esx-01", "blr-esx-03"} <= set(st["plan"]["waves"][0]["assets"])
    assert {r["asset"] for r in st["executions"][0]["regressions"]} == {"blr-esx-01"}
    for c in st["executions"][0]["firmware_changes"]:
        assert sv.twin.servers[c["asset"]]["firmware"][c["component"]] == c["from"]
    # lesson: the per-component probe blames ROM and exonerates iLO on the regressed host itself;
    # the same-model control on NIC 230.x narrows the condition to NIC 229.x
    les = st["lesson"]
    assert les["component"] == "System ROM" and les["conditions"]["firmware_prefix"] == {"NIC BCM57414": "229."}
    d = les["diagnosis"]
    assert d["method"] == "per-component probe" and d["exonerated"] == ["iLO 6 1.64"]
    assert d["controls"] == ["blr-esx-03"] and d["scope"] == "control"
    # counterfactual: a risk-ranked canary of the same size would have missed it
    cf = st["counterfactual"]
    assert not cf["risk_ranked_would_catch"] and "payments-db-01" in cf["exposed_tier0_vms"]
    assert st["avoided_cost_usd"] == 1_200_000
    assert sv.ledger.verify()["ok"]


def test_report_is_signed(engine, sv):
    r, _ = drive(engine)
    rep = r["state"]["report"]
    body = {k: v for k, v in rep.items() if k not in ("signature", "signature_alg", "path")}
    assert sv.authority.verify_signature(json.loads(json.dumps(body, default=str)), rep["signature"])


def test_learned_regression_defers_matching_hosts(tmp_path):
    sv = make_services(tmp_path)
    drive(Engine(sv))
    sv.reset_lab(forget_lessons=False)
    r, gates = drive(Engine(sv))
    st = r["state"]
    deferred = {d["asset"] for d in st["risk"]["deferred"]}
    # only DL380s still on NIC 229.x are deferred; the four DL380s on NIC 230.x proceed
    assert len(deferred) == 16
    assert all(sv.twin.servers[a]["model"].endswith("DL380 Gen11")
               and sv.twin.servers[a]["firmware"]["NIC BCM57414"].startswith("229.") for a in deferred)
    assert st["status"] == "completed"
    planned = {a for w in st["plan"]["waves"] for a in w["assets"]}
    assert not planned & deferred


def test_clean_run_needs_dual_approval_for_fleet(tmp_path):
    sv = make_services(tmp_path, faults=False)
    eng = Engine(sv)
    r = eng.start(INTENT)
    assert r["interrupt"]["scope"] == "canary"
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})
    assert r["interrupt"]["scope"] == "fleet" and r["interrupt"]["canary_result"]["result"] == "passed"
    # one approver twice is not two approvers: the gate asks again
    r = eng.resume(r["run_id"], {"decision": "approve", "approvers": ["asha.ops", "asha.ops"]})
    assert r["interrupt"]["scope"] == "fleet"
    r = eng.resume(r["run_id"], {"decision": "approve", "approvers": ["asha.ops", "ravi.net"]})
    st = r["state"]
    assert st["status"] == "completed"
    assert all(e["result"] == "passed" for e in st["executions"])
    assert {s["firmware"]["iLO 6"] for s in sv.twin.servers.values()} == {"1.64"}
    assert sv.twin.switches["tor-r1-a"]["firmware"] == "10.14.1000"
    assert len([a for a in st["approvals"] if a["scope"] == "fleet"]) == 2


def test_rejection_executes_nothing(engine, sv):
    before = sv.twin.snapshot()
    r, _ = drive(engine, canary="reject")
    assert r["state"]["status"] == "rejected"
    assert sv.twin.snapshot()["firmware"] == before["firmware"]
