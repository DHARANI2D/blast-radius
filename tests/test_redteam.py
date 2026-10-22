"""Red-team benchmark: the Verifier and the constraint checker against labelled false claims and mutated plans."""

import pytest

from blastradius import redteam
from blastradius.agents import RiskAgent, TopologyAgent, VerifierAgent
from blastradius.offline_llm import extract_claims
from blastradius.solver import grounded_rationale, plan_facts, solve
from conftest import make_services

COMPS = ["iLO 6", "System ROM", "Switch OS"]
NAMED_OPERATORS = {"swap_cve", "fake_dual_homing", "fake_single_homing", "inflate_capacity", "wrong_install_order",
                   "peers_same_wave", "pair_safe_together", "unsafe_canary", "canary_missing_cohort", "outage_plan",
                   "wrong_duration", "deny_known_issue"}
# check_plan has no rule against scheduling an asset the Risk agent deferred (after a learned
# regression); the benchmark reports these two mutations as a gap rather than hiding them.
KNOWN_CONSTRAINT_GAPS: list[str] = []  # the DEFERRED gap this benchmark found is closed in constraints.check_plan


@pytest.fixture(scope="module")
def sv(tmp_path_factory):
    return make_services(tmp_path_factory.mktemp("redteam"))


@pytest.fixture(scope="module")
def res(sv):
    return redteam.run_benchmark(sv, seed=7, paraphrases=True)


def test_runs_fast_and_leaves_the_session_untouched(tmp_path):
    sv = make_services(tmp_path)
    before = (len(sv.evidence), sv.twin.snapshot())
    r = redteam.run_benchmark(sv, seed=7, paraphrases=False)
    assert r["elapsed_s"] < 30
    assert (len(sv.evidence), sv.twin.snapshot()) == before


def test_corpus_covers_every_typed_claim_with_true_and_false_instances(res):
    by_type = res["typed"]["by_type"]
    assert set(by_type) == set(redteam.TYPED) and "freeform" not in by_type
    for t, s in by_type.items():
        assert s["n_true"] >= 1 and s["n_false"] >= 1, t
    ops = res["typed"]["by_operator"]
    assert NAMED_OPERATORS <= set(ops)
    rows = res["typed"]["rows"]
    for op in NAMED_OPERATORS - {"wrong_install_order"}:  # several instances per operator, not one
        assert len({(r["text"], r["ctx"]) for r in rows if r["operator"] == op}) >= 2, op
    # the knowledge base states exactly one install order (iLO 6 before System ROM), so one reversal exists
    assert ops["wrong_install_order"]["n_false"] == 1


def test_labels_agree_with_the_raw_twin_oracle(res):
    assert res["label_audit"]["checked"] >= 50
    assert res["label_audit"]["mismatches"] == []


def test_typed_claims_no_dangerous_misses_no_false_blocks(res):
    o = res["typed"]["overall"]
    assert o["dangerous_misses"] == 0
    assert o["false_blocks"] == 0
    assert o["errors"] == 0
    assert o["catch_rate"] >= 0.9
    # what is not contradicted is flagged, never passed: hallucinated firmware versions
    flagged = {r["operator"] for r in res["typed"]["rows"] if r["outcome"] == "flagged"}
    assert flagged <= {"phantom_version"}


def test_known_examples(res):
    rows = res["typed"]["rows"]
    ilo = next(r for r in rows if r["operator"] == "deny_known_issue" and r["args"] == {"component": "iLO 6", "version": "1.64"})
    assert ilo["label"] == "Contradicted" and "ADV-SYN-2026-017" in ilo["explanation"]
    esx07 = [r for r in rows if r["type"] == "dual_homed" and r["args"]["server"].lower() == "blr-esx-07"]
    assert esx07 and all(r["label"] == "Contradicted" for r in esx07)
    assert any(r["type"] == "single_homed" and r["args"]["server"] == "blr-esx-07" and r["label"] == "Supported" for r in rows)
    order = {(r["args"]["first"], r["args"]["second"]): r["label"] for r in rows if r["type"] == "install_order"}
    assert order == {("iLO 6", "System ROM"): "Supported", ("System ROM", "iLO 6"): "Contradicted"}


def test_every_plan_mutation_is_detected_except_the_documented_gap(res):
    pm = res["plan_mutations"]
    assert pm["n"] >= 15
    assert sorted(pm["constraint_gaps"]) == KNOWN_CONSTRAINT_GAPS
    cases = {c["name"]: c for c in pm["cases"]}
    for name, c in cases.items():
        if name not in KNOWN_CONSTRAINT_GAPS:
            assert c["detected"] and c["expected_fired"], (name, c["fired"])
        else:
            assert not c["rule_exists"]
    assert "REDUNDANT_PAIR" in cases["merge_vsx_peers"]["fired"]
    assert "PLANNED_OUTAGE" in cases["strand_single_homed"]["fired"]
    assert "CANARY_FIRST" in cases["tier0_canary"]["fired"]
    assert "CANARY_COVERAGE" in cases["drop_cohort_from_canary"]["fired"]
    assert "WINDOW" in cases["blow_window"]["fired"]


def test_paraphrases_end_to_end(res):
    bs = res["paraphrase"]["summary"]["by_split"]
    assert set(bs) == {"canonical", "dev", "held-out"}
    for split, s in bs.items():
        assert s["dangerous_misses"] == 0 and s["false_blocks"] == 0, split
    assert bs["canonical"]["exact_rate"] >= 0.95 and bs["dev"]["exact_rate"] >= 0.95
    assert bs["canonical"]["clean_pass_rate"] == 1.0
    # Held-out phrasings measure the offline regex extractor's generalisation; it is low, and reported.
    assert 0 <= bs["held-out"]["exact_rate"] < bs["dev"]["exact_rate"]
    assert res["headline"]["slipped_held_out"] == f"{bs['held-out']['slipped_through']}/{bs['held-out']['dirty_rationales']}"


def test_injection_is_caught_and_blocks_the_plan(res):
    inj = res["injection"]
    assert inj["n"] == len(redteam.HALLUCINATION_KINDS)
    assert inj["caught"] == inj["n"] and inj["blocked"] == inj["n"]
    assert inj["clean_passed"]


def test_inject_hallucination_appends_one_labelled_sentence():
    facts = {"redundant_pairs": [["tor-r1-a", "tor-r1-b"]], "single_homed": ["blr-esx-07"], "dual_homed": ["blr-esx-01"]}
    text, lab = redteam.inject_hallucination("Plan is staggered.", "pair_safe_together", facts)
    assert text == "Plan is staggered. " + lab["sentence"] and lab["truth"] is False
    assert lab["type"] == "pair_safe_together" and lab["args"] == {"a": "tor-r1-a", "b": "tor-r1-b"}
    _, lab = redteam.inject_hallucination("", "fake_dual_homing", facts)
    assert lab["sentence"] == "blr-esx-07 is dual-homed."
    with pytest.raises(ValueError):
        redteam.inject_hallucination("x", "no_such_kind", facts)
    with pytest.raises(ValueError):
        redteam.inject_hallucination("x", "wrong_duration", facts)


def test_verify_injected_on_a_live_session_plan(sv):
    topo, _ = TopologyAgent(sv).run()
    servers = sorted(topo.servers)
    risk = RiskAgent(sv).run({"servers": servers, "switches": ["tor-r1-a", "tor-r1-b"]}, COMPS, topo)
    scores = {a: r["score"] for a, r in risk["assets"].items()}
    waves = solve(servers, ["tor-r1-a", "tor-r1-b"], topo, scores, sv.policy, COMPS, 480)
    facts = plan_facts(topo, {"servers": servers, "switches": ["tor-r1-a", "tor-r1-b"]}, sv.policy, COMPS)
    plan = {"waves": waves, "rationale": grounded_rationale(waves, facts, COMPS, 160), "self_confidence": 88}
    cr = {"components": COMPS, "window": {"day": "Saturday", "start": "22:00", "duration_minutes": 480}}
    r = redteam.verify_injected(sv, plan, cr, topo, risk, "swap_cve")
    assert r["type"] == "fixes_cve" and r["caught"] and r["plan_blocked"]


def test_deterministic_for_a_seed(sv):
    a = redteam.run_benchmark(sv, seed=11, paraphrases=False)
    b = redteam.run_benchmark(sv, seed=11, paraphrases=False)
    strip = [(r["id"], r["text"], r["ctx"], r["label"]) for r in a["typed"]["rows"]]
    assert strip == [(r["id"], r["text"], r["ctx"], r["label"]) for r in b["typed"]["rows"]]
    assert a["headline"] == b["headline"]


def test_markdown_report(res):
    md = redteam.format_markdown(res)
    for heading in ("## Headline", "## Typed claims by type", "## False claims by mutation operator",
                    "## Paraphrase robustness", "## Plan mutations", "## Live injection", "## Method"):
        assert heading in md
    assert "schedule_deferred_host" in md and "(no such rule)" not in md  # the DEFERRED gap is closed
    # labels produced by the checker's own duration and cohort code are called consistency checks, not measurements
    assert "| `in_window` (consistency check) |" in md and "| `canary_covers_cohorts` (consistency check) |" in md
    assert "Consistency checks, not independent measurements" in md and "cohorts.build" in md


def test_wilson_interval():
    assert redteam.wilson(0, 0) is None
    lo, hi = redteam.wilson(0, 10)
    assert lo == 0.0 and 0.27 < hi < 0.28
    lo, hi = redteam.wilson(10, 10)
    assert 0.72 < lo < 0.73 and hi == 1.0


# ---------------------------------------------- bugs the benchmark found (regression tests)
def _ctx(sv):
    topo, _ = TopologyAgent(sv).run()
    return {"plan": {"waves": []}, "cr": {"components": COMPS}, "topo": topo,
            "target_versions": {"blr-esx-01": {"iLO 6": "1.64", "System ROM": "U54 v2.32"}}}


@pytest.mark.parametrize("claim,label", [
    ({"type": "single_homed", "args": {"server": "blr-esx-60"}}, "Contradicted"),  # was Supported: 0 uplinks
    ({"type": "cluster_capacity", "args": {"cluster": "PROD-BLR-44", "hosts": 3}}, "Contradicted"),  # was StopIteration
    ({"type": "pair_safe_together", "args": {"a": "tor-r3-a", "b": "tor-r3-b"}}, "Contradicted"),  # was ToolCallError
    ({"type": "install_order", "args": {"first": "System ROM", "second": "iLO 6"}}, "Contradicted"),  # was Unverifiable
    ({"type": "fixes_cve", "args": {"component": "iLO 6", "version": "1.66", "cve": "SYN-CVE-2026-1105"}}, "Supported"),
    ({"type": "dual_homed", "args": {"server": "BLR-ESX-07"}}, "Contradicted"),
])
def test_verifier_fixes(sv, claim, label):
    got, why, _ev = VerifierAgent(sv).check({**claim, "text": ""}, _ctx(sv))
    assert got == label, why


@pytest.mark.parametrize("sentence,ctype,args", [
    ("tor-r1-a and tor-r1-b are never in the same wave.", "pair_staggered", {"a": "tor-r1-a", "b": "tor-r1-b"}),
    ("tor-r3-a and tor-r3-b can safely be rebooted in the same wave.", "pair_safe_together", {"a": "tor-r3-a", "b": "tor-r3-b"}),
    ("BLR-ESX-07 has two live uplinks.", "dual_homed", {"server": "BLR-ESX-07"}),
    ("Every host in prod-blr-07 has two live uplinks.", "all_dual_homed", {"cluster": "prod-blr-07"}),
    ("SYN-CVE-2026-1105 is fixed in iLO 6 1.66.", "fixes_cve", {"component": "iLO 6", "version": "1.66", "cve": "SYN-CVE-2026-1105"}),
    ("blr-esx-07 is not dual-homed.", "freeform", {}),
    ("LLDP shows blr-esx-07 with fewer than two live uplinks.", "single_homed", {"server": "blr-esx-07"}),
])
def test_extractor_paraphrases(sentence, ctype, args):
    switches = ["tor-r1-a", "tor-r1-b", "tor-r2-a", "tor-r2-b", "spine-1", "spine-2"]
    (c,) = extract_claims({"rationale": sentence, "switch_names": switches})["claims"]
    assert (c["type"], c["args"]) == (ctype, args)


def test_abbreviations_do_not_end_a_sentence():
    text = "504 VMs lose service (incl. payments-db-01). Wave 2 waits, e.g. for the soak. Done."
    assert extract_claims({"rationale": text, "switch_names": []})["claims"][0]["text"].endswith("(incl. payments-db-01).")
    assert len(extract_claims({"rationale": text, "switch_names": []})["claims"]) == 3
