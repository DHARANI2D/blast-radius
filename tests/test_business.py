import copy

import pytest
from conftest import drive, make_services

from blastradius import business
from blastradius.constraints import wave_duration
from blastradius.policy import Policy
from blastradius.workflow import Engine


def _run(tmp_path, scenario=None):
    sv = make_services(tmp_path)
    if scenario:
        sv.twin.set_scenario(scenario)
        sv.reset_lab()
    r, _ = drive(Engine(sv))
    st = r["state"]
    return sv, st, sv.runs[st["run_id"]]["topo"]


def baseline_plan(st):
    """The conventional baseline the workflow uses: the accepted plan before the risk-aware optimiser re-ordered it."""
    accepted = next(a for a in reversed(st["attempts"]) if a.get("passed"))
    return accepted.get("plan_before_optimization") or st["plan"]


def _impact(sv, st, topo, lesson=None, policy=None, actual_exec="last", plan=None):
    ex = st["executions"][-1] if actual_exec == "last" else actual_exec
    return business.counterfactual_impact(lesson or st["lesson"], plan or baseline_plan(st), topo, policy or sv.policy,
                                          st["change_request"]["components"], risk=st["risk"], actual_exec=ex)


@pytest.fixture(scope="module")
def canon(tmp_path_factory):
    """The genuine canonical run: cohort canary catches System ROM U54 v2.32 on blr-esx-01 and rolls back."""
    sv, st, topo = _run(tmp_path_factory.mktemp("biz"))
    assert st["status"] == "rolled_back" and st["lesson"]
    return sv, st, topo, _impact(sv, st, topo)


def test_counterfactual_replays_the_risk_ranked_canary(canon):
    sv, st, topo, imp = canon
    cf = imp["counterfactual"]
    # same conventional canary as the Reporter's counterfactual, and it would have passed
    assert cf["canary"] == st["counterfactual"]["risk_ranked_canary"] and not cf["canary_would_catch"]
    # the swapped plan is otherwise valid (only the cohort-coverage rule objects to a risk-ranked canary)
    assert cf["plan_violations"] == []
    scheduled = sorted(a for w in st["plan"]["waves"] for a in w["assets"])
    assert sorted(a for w in business.baseline_waves(st["plan"], cf["canary"], topo) for a in w["assets"]) == scheduled
    # wave 2 holds the first affected hosts; its post-check at the end of the soak is when the regression is seen
    comps = st["change_request"]["components"]
    w = business.baseline_waves(st["plan"], cf["canary"], topo)
    assert cf["detected_wave"] == 2 and imp["fleet_detection"]["detects"]
    assert cf["detected_at_min"] == sum(wave_duration(x["assets"], [], topo, comps, sv.policy) for x in w[:2])
    assert [r["status"] for r in cf["waves"][2:]] == ["not started: rollout halted"] * (len(w) - 2)
    assert cf["rollback_complete_min"] > cf["detected_at_min"]
    # one counterfactual, one count: the Reporter's sentence uses the hosts and VMs the replay prices
    rc = st["counterfactual"]
    assert rc["exposed_hosts"] == cf["if_undetected"]["hosts"] and rc["exposed_vms"] == cf["if_undetected"]["vms"]
    assert rc["first_exposed_wave"] == cf["detected_wave"] and len(rc["first_wave_hosts"]) == cf["hosts_exposed"]
    assert len(rc["first_wave_hosts"]) <= int(sv.policy.get("planning.max_assets_per_wave"))
    assert (f"Wave 2 would then have flashed {cf['hosts_exposed']} affected host(s)" in rc["sentence"]
            and f"{len(rc['exposed_hosts'])} affected hosts running {rc['exposed_vms']} VMs in all" in rc["sentence"])


def test_exposure_is_placement_times_minutes(canon):
    _, _, topo, imp = canon
    cf = imp["counterfactual"]
    exposed = [h for h in cf["hosts"] if h["exposed_min"]]
    assert exposed and all(h["exposed_min"] > 0 for h in exposed)
    assert cf["vm_minutes"] == sum(len(topo.vms_on(h["host"])) * h["exposed_min"] for h in exposed)
    assert sum(t["vm_minutes"] for t in cf["tiers"]) == cf["vm_minutes"]
    # tier-0 exposure includes payments-db-01 (as in the Reporter counterfactual); payments degrades, keeps a replica
    assert "payments-db-01" in cf["tier0_vms"] and "payments" in cf["tier0_services"]
    assert cf["services"]["payments"]["state"] == "degraded" and not cf["unavailable_services"]


def test_costs_actual_and_avoided(canon):
    _, st, _, imp = canon
    cf, act, av = imp["counterfactual"]["cost"], imp["actual"]["cost"], imp["avoided"]
    assert cf["total_usd"] > 0 and cf["sev1"] and cf["diagnosis_engineer_hours"] > act["diagnosis_engineer_hours"]
    # what happened: only the canary host regressed, it runs no tier-0/1 VMs, no Sev-1
    assert [h["host"] for h in imp["actual"]["hosts"]] == ["blr-esx-01"] and not imp["actual"]["tier0_vms"]
    assert not act["sev1"] and act["customer_impact_usd"] < 0.01 * cf["customer_impact_usd"]
    # the twin itself measured no VMs on the regressed canary host during the soak
    assert imp["twin_check"]["consistent"] and imp["twin_check"]["vms_on_regressed_hosts_during_soak"] == {"blr-esx-01": 0}
    assert av["usd"] == pytest.approx(cf["total_usd"] - act["total_usd"]) and av["usd"] > 0 and av["sev1_avoided"]
    rows = business.cost_table(imp)
    assert rows[-1]["item"] == "Total" and rows[-1]["avoided_usd"] == av["usd"]
    assert sum(r["counterfactual_usd"] for r in rows[:-1]) == pytest.approx(cf["total_usd"])


def test_no_company_wide_rate_and_assumptions_are_sourced(canon):
    _, _, _, imp = canon
    # ITIC's hourly cost is for a whole business outage; it is never applied to one pod's degraded VMs
    assert "itic_reference" not in imp and "ITIC" not in imp["explanation"]
    assert all(a["source"] for a in imp["assumptions"]) and "ITIC 2024" not in {a["source"] for a in imp["assumptions"]}
    # every rate in the totals is listed in policy.yaml, not only defaulted in code
    biz = [a for a in imp["assumptions"] if a["key"].startswith("business.")]
    assert len(biz) >= 8 and all(a["source"] == "illustrative (policy.yaml)" for a in biz)
    assert business._rates(canon[0].policy) == business._rates(Policy({}))  # the code fallbacks match: no number changed
    md = business.markdown(imp)
    assert "ITIC" not in md and "payments-db-01" in md and imp["explanation"] in md
    assert business.summary_lines(imp)[0] == imp["headline"]["text"]


def test_deterministic_and_sensitivity_monotonic(canon):
    sv, st, topo, imp = canon
    assert _impact(sv, st, topo) == imp
    s = imp["sensitivity"]
    assert [x["detection_delay_min"] for x in s] == [0, 60, 240]
    assert all(a["vm_hours"] <= b["vm_hours"] and a["avoided_usd"] <= b["avoided_usd"] for a, b in zip(s, s[1:]))


def test_rates_come_from_policy(canon):
    sv, st, topo, imp = canon
    data = copy.deepcopy(sv.policy.data)
    data["business"] |= {"degraded_cost_per_vm_hour_usd": {0: 40000, 1: 5000, 2: 300, 3: 20}, "sev1_sla_credits_usd": 0}
    alt = _impact(sv, st, topo, policy=Policy(data))
    assert alt["counterfactual"]["cost"]["degraded_vms_usd"] == pytest.approx(2 * imp["counterfactual"]["cost"]["degraded_vms_usd"])
    assert alt["counterfactual"]["cost"]["sev1_usd"] == imp["counterfactual"]["cost"]["sev1_usd"] - 50000
    assert {a["key"]: a["value"] for a in alt["assumptions"]}["business.sev1_sla_credits_usd"] == 0


def test_statistical_only_regression_slips_past_fleet_postchecks(canon):
    sv, st, topo, imp = canon
    ex = copy.deepcopy(st["executions"][-1])
    ex["regressions"] = [r | {"check": "statistical"} for r in ex["regressions"]]
    assert not business.fleet_detection(ex["regressions"], sv.policy)["detects"]
    data = copy.deepcopy(sv.policy.data)
    data.setdefault("canary_stats", {})["all_waves"] = True
    assert business.fleet_detection(ex["regressions"], Policy(data))["detects"]
    slow = _impact(sv, st, topo, actual_exec=ex)
    cf = slow["counterfactual"]
    assert cf["detection_delay_min"] == 240 and cf["detected_wave"] == 2
    assert cf["vm_hours"] > imp["counterfactual"]["vm_hours"] and slow["avoided"]["usd"] > imp["avoided"]["usd"]


def test_lesson_matching_no_host_avoids_nothing(canon):
    sv, st, topo, _ = canon
    lesson = copy.deepcopy(st["lesson"])
    lesson["conditions"] = {"firmware_prefix": {"NIC BCM57414": "999."}}
    imp = _impact(sv, st, topo, lesson=lesson, actual_exec=None)
    assert imp["counterfactual"]["detected_wave"] is None and imp["actual"]["detected_wave"] is None
    assert imp["avoided"]["usd"] == 0 and imp["counterfactual"]["cost"]["total_usd"] == 0
    assert imp["twin_check"] is None and "matches" in imp["headline"]["text"]


def test_risk_ranked_canary_that_also_catches_it_avoids_nothing(tmp_path):
    # "subtle" DL360/NIC 230.x regression: blr-esx-21 is in both canaries, so the conventional canary catches it too
    sv, st, topo = _run(tmp_path, "subtle")
    assert st["status"] == "rolled_back"
    imp = _impact(sv, st, topo)
    cf, act = imp["counterfactual"], imp["actual"]
    assert cf["canary_would_catch"] and cf["detected_wave"] == act["detected_wave"] == 1
    assert imp["avoided"]["usd"] == 0 and not cf["cost"]["sev1"]


def test_workflow_reports_the_same_impact_and_the_optimised_order(canon):
    sv, st, topo, imp = canon
    assert st["business_impact"]["headline"] == imp["headline"]
    opt = _impact(sv, st, topo, plan=st["plan"])
    # the optimiser moved the single-homed payments host late, so even a missed canary is caught before tier-0
    assert opt["counterfactual"]["tier0_vms"] == [] and opt["headline"]["counterfactual_usd"] < imp["headline"]["counterfactual_usd"]
    assert st["business_impact"]["with_optimised_order"]["counterfactual_usd"] == opt["headline"]["counterfactual_usd"]


def test_regression_caught_in_a_fleet_wave_earns_no_canary_saving(tmp_path):
    # with the cohort-coverage rule off the risk-ranked canary runs, passes, and wave 2 regresses
    sv = make_services(tmp_path)
    sv.policy.data["planning"]["canary_cohort_coverage"] = False
    r, gates = drive(Engine(sv))
    st = r["state"]
    assert [g["scope"] for g in gates] == ["canary", "fleet"] and st["status"] == "rolled_back"
    assert st["executions"][-1]["index"] == 2
    biz = st["business_impact"]
    assert biz["actual"]["label"] == "Risk-ranked canary (what happened)"
    assert biz["avoided"]["usd"] == 0 == st["avoided_cost_usd"] and not biz["avoided"]["sev1_avoided"]
    assert biz["avoided"]["caught_in_fleet_wave"] == 2 and all(s["avoided_usd"] == 0 for s in biz["sensitivity"])
    assert biz["headline"]["text"].startswith("No canary saving") and "same wave" not in biz["headline"]["text"]
    assert "no saving is credited to the canary" in biz["explanation"]
    # the lesson names the wave its hosts were in, and no "our canary caught it" counterfactual is told
    assert " on wave 2 blr-esx-" in st["lesson"]["symptom"] and "on canary" not in st["lesson"]["symptom"]
    assert not [e for e in st["timeline"] if e["event"] == "counterfactual"]
