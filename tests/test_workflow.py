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
    # inventory-02 is moved onto a canary host that is evacuated later: 56 migrations, 55 distinct VMs
    assert (st["executions"][0]["migrations"], st["executions"][0]["migrated_vms"]) == (56, 55)
    assert "55 VMs live-migrated" in " ".join(e["detail"] for e in st["timeline"])
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
    # business impact replayed on the twin against the conventional baseline (risk-ranked canary, greedy ordering)
    biz = st["business_impact"]
    assert st["avoided_cost_usd"] == biz["avoided"]["usd"] > 0
    assert "payments-db-01" in biz["counterfactual"]["tier0_vms"] and biz["counterfactual"]["cost"]["sev1"]
    assert biz["itic_reference"]["flat_usd"] == 1_200_000  # cross-check only, never the headline
    # the risk-aware ordering alone would also have kept the regression away from tier-0
    assert biz["with_optimised_order"]["tier0_vms"] == [] and biz["with_optimised_order"]["counterfactual_usd"] < biz["headline"]["counterfactual_usd"]
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
    probes = []
    call = sv.bus.call

    def spy(agent, key, **args):
        if agent == "executor" and key == "virt.enter_maintenance" and args["host"] == "blr-esx-07":
            # blr-esx-07 is deferred and only evacuated for its switch: maintenance is granted, firmware never is
            run_id, tv = args["run_id"], sv.authority
            probes.append([tv.check(tv.token(run_id, "blr-esx-07", "compute.apply_firmware", v), run_id, "blr-esx-07",
                                    "compute.apply_firmware", v)[0] for v in ("1.64", "U54 v2.32")])
        return call(agent, key, **args)

    sv.bus.call = spy
    r, gates = drive(Engine(sv))
    st = r["state"]
    assert any("blr-esx-07" in w.get("evacuate", []) for w in st["plan"]["waves"]) and probes == [[False, False]]
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
    # an approval with no approver name is not signed and nothing runs: the gate asks again and says why
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "   "})
    assert r["interrupt"]["scope"] == "canary" and "named approver" in r["state"]["approval_error"]
    assert r["state"]["approvals"] == [] and r["state"]["executions"] == [] and sv.twin.maintenance == set()
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})
    assert r["interrupt"]["scope"] == "fleet" and r["interrupt"]["canary_result"]["result"] == "passed"
    assert r["state"]["approval_error"] == ""
    # the fleet card's duration and max BRS cover the waves still to run, not the canary that already ran
    fc = r["interrupt"]
    assert fc["total_duration_min"] == sum(w["duration_min"] for w in fc["waves"]) < r["state"]["constraints"]["total_duration_min"]
    assert fc["max_brs"] == max(w["brs"] for w in fc["waves"])
    # one approver twice, in any case or spacing, is not two approvers: the gate asks again and says why
    for names in (["asha.ops", "asha.ops"], ["asha.ops", " ASHA.OPS "], ["asha.ops", "   "]):
        r = eng.resume(r["run_id"], {"decision": "approve", "approvers": names})
        assert r["interrupt"]["scope"] == "fleet" and "2 distinct approvers; got 1" in r["state"]["approval_error"]
        assert len(r["state"]["executions"]) == 1
    r = eng.resume(r["run_id"], {"decision": "approve", "approvers": [" asha.ops", "ravi.net"]})
    st = r["state"]
    assert st["approval_error"] == "" and [a["approver"] for a in st["approvals"]] == ["asha.ops", "asha.ops", "ravi.net"]
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


def test_report_lists_each_section_once(engine, sv):
    r, _ = drive(engine)
    md = open(r["state"]["report"]["path"]).read()
    heads = [ln for ln in md.splitlines() if ln.startswith("## ")]
    assert len(heads) == len(set(heads))
    assert any(h.startswith("## Business impact") for h in heads)


def test_intent_with_no_known_target_stops_at_intake(engine, sv):
    before = sv.twin.snapshot()["firmware"]
    for intent in ("hello", "Upgrade System ROM on PROD-BLR-99 this Saturday 10pm", "Execute approved plan 123"):
        r, gates = drive(engine, intent)
        st = r["state"]
        assert gates == [] and st["status"] == "escalated" and st["outcome_reason"].startswith("no recognised targets")
        assert not st.get("plan") and not st["attempts"] and not st["approvals"] and not st["executions"]
        assert st["report"]["outcome"] == "escalated" and "No change was planned or executed" in st["report"]["summary"]
    assert sv.twin.snapshot()["firmware"] == before and sv.memory.stats()["runs"] == 0


def test_every_target_deferred_is_nothing_to_do(tmp_path):
    sv = make_services(tmp_path)
    eng = Engine(sv)
    drive(eng)  # learns the NIC 229.x regression on blr-esx-01
    sv.reset_lab(forget_lessons=False)
    r, gates = drive(eng, "Upgrade iLO 6 and System ROM on blr-esx-01 and blr-esx-02 to the latest baseline this Saturday 10pm")
    st = r["state"]
    assert gates == [] and st["status"] == "nothing_to_do" and not st["attempts"] and not st["executions"]
    assert st["outcome_reason"].startswith("nothing to do: all 2 target(s) deferred by INC-BR-")
    assert st["report"]["outcome"] == "nothing_to_do"


def test_go_no_go_card_carries_the_intake_assumption(engine):
    r = engine.start(INTENT)
    card = r["interrupt"]
    assert card["scope"] == "canary" and any(w.startswith("Assumption: 'the ToR switch pair' is ambiguous") for w in card["warnings"])
    assert any(e["event"] == "warning" and e["agent"] == "intake" for e in r["state"]["timeline"])


def test_switch_only_change_is_planned_with_a_one_asset_canary_and_a_warning(tmp_path):
    sv = make_services(tmp_path, faults=False)
    r, gates = drive(Engine(sv), "Upgrade switch OS on tor-r1-a and tor-r1-b to the latest baseline this Saturday 10pm")
    st = r["state"]
    assert [g["scope"] for g in gates] == ["canary", "fleet"] and st["status"] == "completed"
    assert st["plan"]["waves"][0]["assets"] == ["tor-r1-b"]
    assert "no eligible low-tier canary; canary is tor-r1-b" in gates[0]["warnings"]
    assert sv.twin.switches["tor-r1-a"]["firmware"] == sv.twin.switches["tor-r1-b"]["firmware"] == "10.14.1000"
