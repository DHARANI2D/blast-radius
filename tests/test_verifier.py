from blastradius.agents import RiskAgent, VerifierAgent
from blastradius.solver import solve

SERVERS = [f"blr-esx-{i:02d}" for i in range(1, 41)]
SWITCHES = ["tor-r1-a", "tor-r1-b"]
COMPS = ["iLO 6", "System ROM", "Switch OS"]
CR = {"components": COMPS, "window": {"day": "Saturday", "start": "22:00", "duration_minutes": 480}}


def ctx(sv, topo, plan):
    risk = RiskAgent(sv).run({"servers": SERVERS, "switches": SWITCHES}, COMPS, topo)
    return {"plan": plan, "cr": CR, "topo": topo, "target_versions": risk["target_versions"]}, risk


def check(sv, topo, plan, ctype, args, text="claim"):
    v = VerifierAgent(sv)
    c, _ = ctx(sv, topo, plan)
    return v.check({"type": ctype, "args": args, "text": text}, c)


def test_hallucinated_cve_is_contradicted_with_evidence(sv, topo):
    label, why, ev = check(sv, topo, {"waves": []}, "fixes_cve",
                           {"component": "System ROM", "version": "U54 v2.32", "cve": "SYN-CVE-2026-1105"})
    assert label == "Contradicted"
    assert "ADV-SYN-2026-017" in why and "1.66" in why
    assert all(sv.evidence.get(e) for e in ev)


def test_true_cve_claim_is_supported(sv, topo):
    label, _, _ = check(sv, topo, {"waves": []}, "fixes_cve", {"component": "iLO 6", "version": "v1.64", "cve": "SYN-CVE-2026-1101"})
    assert label == "Supported"


def test_redundant_pair_together_is_contradicted(sv, topo):
    label, why, _ = check(sv, topo, {"waves": []}, "pair_safe_together", {"a": "tor-r1-a", "b": "tor-r1-b"})
    assert label == "Contradicted" and "one member at a time" in why


def test_dual_homed_claim_checked_against_lldp(sv, topo):
    assert check(sv, topo, {"waves": []}, "all_dual_homed", {"cluster": "PROD-BLR-07"})[0] == "Contradicted"
    assert check(sv, topo, {"waves": []}, "all_dual_homed", {"cluster": "PROD-BLR-08"})[0] == "Supported"
    assert check(sv, topo, {"waves": []}, "single_homed", {"server": "blr-esx-07"})[0] == "Supported"


def test_freeform_claims_default_to_unverifiable(sv, topo):
    assert check(sv, topo, {"waves": []}, "freeform", {}, "Traffic will be low on Saturday night.")[0] == "Unverifiable"


def test_trust_score_blocks_contradictions(sv, topo):
    waves = solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    good = {"waves": waves, "self_confidence": 90,
            "rationale": "tor-r1-a and tor-r1-b are upgraded in different waves. No wave causes a workload outage. "
                         "Update iLO 6 before System ROM."}
    _, risk = ctx(sv, topo, good)
    res = VerifierAgent(sv).run(good, CR, topo, risk)
    assert res["passed"] and res["trust_score"] == 100
    bad = dict(good, rationale=good["rationale"] + " System ROM U54 v2.32 remediates SYN-CVE-2026-1105.")
    res = VerifierAgent(sv).run(bad, CR, topo, risk)
    assert not res["passed"]
    assert res["counts"]["Contradicted"] == 1
    assert res["trust_score"] < 80


def test_oddly_typed_arguments_are_checked_or_unverifiable_never_a_crash(sv, topo):
    # A live extractor may write versions as JSON numbers and "all" for the cohort count.
    assert check(sv, topo, {"waves": []}, "fixes_cve", {"component": "iLO 6", "version": 1.64, "cve": "SYN-CVE-2026-1101"})[0] == "Supported"
    assert check(sv, topo, {"waves": []}, "no_known_issues", {"component": "iLO 6", "version": 1.64})[0] == "Contradicted"
    plan = {"waves": solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)}
    for cohorts in ("all", "Every", 3, "3", None):
        assert check(sv, topo, plan, "canary_covers_cohorts", {"cohorts": cohorts})[0] == "Supported", cohorts
    assert check(sv, topo, plan, "canary_covers_cohorts", {"cohorts": 7})[0] == "Contradicted"
    # any failure inside a typed checker makes that one claim Unverifiable
    v = VerifierAgent(sv)
    v._c_canary_safe = lambda a, c: {}["missing"].strip()
    v._c_per_wave_cap = lambda a, c: None.strip()
    c, _ = ctx(sv, topo, plan)
    for t in ("canary_safe", "per_wave_cap"):
        label, why, ev = v.check({"type": t, "args": {}, "text": "claim"}, c)
        assert label == "Unverifiable" and why.startswith("checker could not evaluate: ") and ev == []


def test_judge_may_only_cite_the_evidence_it_was_given(sv, topo):
    import json

    from blastradius.models import Judgement

    foreign = sv.evidence.add("intake", "compute.list_servers", {}, [])  # in the store, but never shown to the judge
    cite = {}

    def judge(role, system, user, schema, context=None, temperature=0.0):
        given = [e.split(" ")[0] for e in json.loads(user)["evidence"]]
        return Judgement(label="Supported", explanation="looks fine", evidence=cite["ids"](given))

    sv.verifier_llm.complete_json = judge
    text = "Payments VMs fail over cleanly, so customers see no downtime."
    cite["ids"] = lambda given: [foreign]
    label, why, ev = check(sv, topo, {"waves": []}, "freeform", {}, text)
    assert label == "Unverifiable" and foreign in why and foreign not in ev
    cite["ids"] = lambda given: [foreign] + given
    label, _, ev = check(sv, topo, {"waves": []}, "freeform", {}, text)
    assert label == "Supported" and foreign not in ev and ev
