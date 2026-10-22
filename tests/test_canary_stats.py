import itertools
import math

import pytest

from conftest import INTENT, make_services

from blastradius.agents import PostValidationAgent
from blastradius.canary_stats import (FAIL, INCONCLUSIVE, MARGINAL, PASS, _subset_sum_counts, analyse_wave, changed_assets,
                                      classify, did_ratio, hodges_lehmann, judge, mann_whitney_u, midranks, ratio_of_medians,
                                      select_controls, summary)
from blastradius.twin import parse_scenario
from blastradius.workflow import Engine

COMPS = ["iLO 6", "System ROM", "Switch OS"]


def run_canary(tmp_path, scenario: str):
    """Plan, approve and execute the canary wave of the demo intent under a fault scenario."""
    sv = make_services(tmp_path)
    sv.twin.set_scenario(scenario)
    sv.reset_lab()
    eng = Engine(sv)
    r = eng.start(INTENT)
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})
    st = r["state"]
    ex = st["executions"][0]
    stat = analyse_wave(sv, ex, sv.runs[r["run_id"]]["topo"], st["change_request"]["components"])
    return sv, r, ex, stat


def check(stat, host, metric="nic_latency_ms"):
    return next(c for c in stat["checks"] if c["host"] == host and c["metric"] == metric)


# ----------------------------------------------------------------- statistics
def _brute_force_p(x, y):
    ranks, _ = midranks(list(x) + list(y))
    obs = sum(ranks[:len(x)])
    sums = [sum(ranks[i] for i in idx) for idx in itertools.combinations(range(len(ranks)), len(x))]
    return sum(s >= obs - 1e-9 for s in sums) / len(sums)


def test_mann_whitney_exact_matches_full_enumeration_with_ties():
    assert mann_whitney_u([4, 5, 6], [1, 2, 3])["p_value"] == pytest.approx(1 / 20)  # 1 / C(6, 3)
    cases = [([3, 3, 4, 5], [1, 2, 3, 3, 3]), ([1, 1, 1], [1, 1, 2, 2]), ([2.5, 7, 7, 9, 1], [7, 2.5, 3]), ([5, 6], [1, 2, 2, 3, 4, 6, 6])]
    for x, y in cases:
        res = mann_whitney_u(x, y)
        assert res["method"] == "exact" and res["p_value"] == pytest.approx(_brute_force_p(x, y))
    assert mann_whitney_u([2, 2, 2], [2, 2, 2, 2])["p_value"] == 1.0  # all tied: no evidence either way
    assert mann_whitney_u([2] * 30, [2] * 30, exact_max_n=0)["p_value"] == 1.0  # same when the sample is large


def test_p_value_never_below_what_a_rank_test_can_produce():
    """Noise-free twin metrics tie almost everything; the normal approximation's variance then collapses
    (it gave p=1e-36 on the demo). The smallest attainable p is 1 / C(n1 + n2, min(n1, n2))."""
    floor = 1 / math.comb(160, 10)
    res = mann_whitney_u([120.0] * 10, [1.0] * 150, exact_max_n=0)  # one tie group holds most of the sample
    assert res["method"] == "exact" and res["p_value"] == pytest.approx(floor)
    res = mann_whitney_u([120.0] * 10, [1.0] * 150)  # demo size: exact
    assert res["method"] == "exact" and res["p_value"] == pytest.approx(floor)
    res = mann_whitney_u([10, 11, 12], [1, 2, 3], exact_max_n=0)  # no ties, normal branch: z gives 0.04 < 1/C(6, 3)
    assert res["method"] == "normal" and res["p_value"] == pytest.approx(1 / 20)


def test_tie_corrected_variance_equals_the_permutation_variance():
    x, y = [1, 2, 2, 3, 3, 3, 5], [2, 3, 3, 4, 4, 6, 6, 6]
    n1, n2 = len(x), len(y)
    n = n1 + n2
    ranks, ties = midranks(x + y)
    counts = _subset_sum_counts([int(2 * r) for r in ranks], n1)
    total = sum(counts.values())
    mean = sum(s * c for s, c in counts.items()) / total
    var_perm = sum((s - mean) ** 2 * c for s, c in counts.items()) / total / 4  # rank sums were doubled
    var_formula = n1 * n2 / 12 * ((n + 1) - sum(t ** 3 - t for t in ties) / (n * (n - 1)))
    assert var_perm == pytest.approx(var_formula)
    # and the normal approximation lands close to the exact p-value
    assert mann_whitney_u(x, y, "less", exact_max_n=0)["p_value"] == pytest.approx(mann_whitney_u(x, y, "less")["p_value"], abs=0.02)


def test_effect_sizes_and_decision_rule():
    x, y = [1.3, 1.31, 1.29, 1.32], [1.0, 1.01, 0.99, 1.02, 0.98]
    assert hodges_lehmann(x, y) == pytest.approx(0.3, abs=0.011)
    assert ratio_of_medians(x, y) == pytest.approx(1.305)
    # both groups slow down 1.4x (common mode); only the canary has an extra 1.3x
    assert did_ratio([1, 1, 1], [1.82, 1.82], [2, 2, 2], [2.8, 2.8]) == pytest.approx(1.3)
    assert classify(1e-6, 1.3) == FAIL
    assert classify(1e-6, 1.05) == MARGINAL  # significant but small
    assert classify(0.2, 1.5) == MARGINAL    # large but not significant (e.g. too few samples)
    assert classify(0.2, 1.01) == PASS


def test_judge_scores_like_kayenta():
    pre = [1.0, 1.02, 0.98, 1.01, 0.99, 1.0]
    ctl = {f"c{i}": {"pre": pre, "post": [v * (1 + i / 100) for v in pre]} for i in range(4)}
    obs = [{"host": "a", "metric": "m1", "canary": {"pre": pre, "post": [v * 1.5 for v in pre]}, "controls": ctl},
           {"host": "a", "metric": "m2", "canary": {"pre": pre, "post": [None] + pre}, "controls": ctl},
           {"host": "b", "metric": "m1", "insufficient": "insufficient controls: 1 un-upgraded peer(s)"}]
    res = judge(obs)
    assert [c["verdict"] for c in res["checks"]] == [FAIL, PASS, INCONCLUSIVE]
    assert res["verdict"] == FAIL and res["score"] == 50  # inconclusive checks are not scored
    assert res["hosts"]["a"] == {"verdict": FAIL, "score": 50, "failed": ["m1"]}
    a = res["checks"][0]
    assert a["n_canary"] == 6 and a["n_control"] == 24 and a["n_control_hosts"] == 4 and a["method"] == "exact"
    assert judge(obs[2:])["verdict"] == INCONCLUSIVE and judge(obs[2:])["score"] is None


# -------------------------------------------------------------------- controls
def test_controls_come_from_the_cohort_then_the_model_else_insufficient(topo):
    pick = select_controls("blr-esx-03", topo.servers, COMPS, exclude=["blr-esx-01", "blr-esx-21"])
    assert pick["basis"] == "cohort" and pick["controls"] == ["blr-esx-11", "blr-esx-16", "blr-esx-20"]
    assert pick["cohort"] == "DL380 Gen11 · NIC BCM57414 230.x"
    # one same-cohort peer already upgraded: widen to every un-upgraded DL380
    pick = select_controls("blr-esx-03", topo.servers, COMPS, exclude=["blr-esx-11"])
    assert pick["basis"] == "model" and "blr-esx-01" in pick["controls"] and "blr-esx-11" not in pick["controls"]
    # every other DL380 already in a wave or changed: say so instead of guessing
    dl380 = [h for h, s in topo.servers.items() if s["model"].endswith("DL380 Gen11")]
    pick = select_controls("blr-esx-03", topo.servers, COMPS, exclude=[h for h in dl380 if h not in ("blr-esx-03", "blr-esx-04", "blr-esx-11")])
    assert pick["basis"] == "insufficient" and pick["controls"] == []
    assert pick["reason"].startswith("insufficient controls: 1 un-upgraded peer(s) in cohort") and "2 of model DL380" in pick["reason"]
    assert changed_assets([{"assets": ["a"], "evacuate": ["b"], "firmware_changes": [{"asset": "c"}]}]) == {"a", "b", "c"}


def test_insufficient_controls_is_reported_not_guessed(tmp_path):
    sv = make_services(tmp_path)
    eng = Engine(sv)
    r = eng.start(INTENT)
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})
    st = r["state"]
    topo = sv.runs[r["run_id"]]["topo"]
    dl380 = {h for h, s in topo.servers.items() if s["model"].endswith("DL380 Gen11")}
    # pretend every other DL380 was already upgraded by earlier waves
    stat = analyse_wave(sv, st["executions"][0], topo, st["change_request"]["components"], exclude=dl380 - {"blr-esx-01", "blr-esx-03"})
    for host in ("blr-esx-01", "blr-esx-03"):
        c = check(stat, host)
        assert c["verdict"] == INCONCLUSIVE and c["p_value"] is None and "insufficient controls" in c["reason"]
    assert check(stat, "blr-esx-21")["verdict"] == PASS  # the DL360 still has 19 cohort peers
    assert stat["verdict"] == PASS and stat["score"] == 100 and not stat["regressions"]
    assert {w["asset"] for w in stat["warnings"]} == {"blr-esx-01", "blr-esx-03"}


# ------------------------------------------------------------------- scenarios
def test_demo_regression_fails_with_tiny_p(tmp_path):
    sv, r, ex, stat = run_canary(tmp_path, "on")
    assert r["state"]["status"] == "rolled_back"  # the existing fixed-threshold story is unchanged
    assert ex["regressions"][0]["message"] == "NIC latency 0.17 -> 0.68 ms (3.9x)"
    c = check(stat, "blr-esx-01")
    assert c["verdict"] == FAIL and c["p_value"] < 1e-6 and c["effect"] > 3.5
    assert c["basis"] == "cohort" and c["n_control_hosts"] == 15 and c["n_canary"] == 10
    assert check(stat, "blr-esx-01", "rx_drop_rate")["verdict"] == FAIL
    assert check(stat, "blr-esx-03")["verdict"] == PASS and check(stat, "blr-esx-21")["verdict"] == PASS
    assert stat["verdict"] == FAIL and stat["score"] == 67
    assert {g["asset"] for g in stat["regressions"]} == {"blr-esx-01"}
    # read over MCP tools with an explicit window that ends at the wave, not at the rollback
    assert stat["windows"] == {"pre": [-15, 0], "post": {h: [70, 79] for h in ex["assets"]}, "wave": [0, 79]}
    assert sv.twin.clock_min > ex["t_end_min"] and len(stat["evidence"]) == 80
    assert "blr-esx-01 FAIL" in summary(stat)


def test_subtle_regression_passes_the_2x_rule_but_fails_statistically(tmp_path):
    sv, r, ex, stat = run_canary(tmp_path, "subtle")
    # the fixed rule alone would wave it through...
    assert PostValidationAgent(sv).compare(ex["pre"], ex["post"], ex["during"])["passed"]
    # ...but the workflow merges the statistical verdict, so the canary is rolled back instead of reaching the fleet gate
    assert ex["result"] == "regression" and r["state"]["status"] == "rolled_back" and r["interrupt"] is None
    assert {g["asset"] for g in ex["regressions"]} == {"blr-esx-21"} and ex["canary_stats"]["verdict"] == FAIL
    c = check(stat, "blr-esx-21")
    assert c["verdict"] == FAIL and c["p_value"] < 1e-4 and 1.2 < c["effect"] < 1.5
    assert c["cohort"] == "DL360 Gen11 · NIC BCM57414 230.x" and c["n_control_hosts"] == 19
    assert check(stat, "blr-esx-21", "rx_drop_rate")["verdict"] == FAIL
    assert check(stat, "blr-esx-01")["verdict"] == PASS and check(stat, "blr-esx-03")["verdict"] == PASS
    assert [g["asset"] for g in stat["regressions"]] == ["blr-esx-21", "blr-esx-21"]


def test_common_mode_backup_false_alarms_a_tight_threshold_but_passes_statistically(tmp_path):
    sv, r, ex, stat = run_canary(tmp_path, "backup")
    post = PostValidationAgent(sv)
    assert post.compare(ex["pre"], ex["post"], ex["during"])["passed"]
    sv.policy.data["golden_signals"]["nic_latency_ratio_max"] = 1.3
    tight = post.compare(ex["pre"], ex["post"], ex["during"])
    assert {g["asset"] for g in tight["regressions"]} == {"blr-esx-01", "blr-esx-03", "blr-esx-21"}  # every canary host
    assert stat["verdict"] == PASS and stat["score"] == 100
    for host in ex["assets"]:
        c = check(stat, host)
        assert c["canary_ratio"] > 1.3 and c["control_ratio"] > 1.3  # the peers slowed down too
        assert abs(c["effect"] - 1) < 0.1
    # the band shows the canary inside its peers' range while the backup runs
    rows = [b for b in stat["band"]["blr-esx-01"]["nic_latency_ms"] if b["t_min"] >= 72]
    assert rows and all(b["control_p10"] > 1.2 and b["control_p10"] * 0.9 <= b["canary"] <= b["control_p90"] * 1.1 for b in rows)


# ------------------------------------------------------------------ twin/tools
def test_scenarios_and_windowed_series(sv):
    assert parse_scenario("on") == {"regression"} and parse_scenario("off") == set()
    assert parse_scenario("subtle+backup") == {"subtle", "backup"} and parse_scenario(False) == set()
    with pytest.raises(ValueError):
        parse_scenario("chaos")
    assert sv.twin.scenarios == {"regression"} and sv.twin.faults_enabled
    sv.twin.advance(30)
    res, _ = sv.bus.call("t", "telemetry.get_metric_series", asset="blr-esx-05", metric="nic_latency_ms", start_t=-3, end_t=4)
    assert [s["t_min"] for s in res] == list(range(-3, 5))
    capped, _ = sv.bus.call("t", "telemetry.get_metric_series", asset="blr-esx-05", metric="rx_drop_rate", start_t=28, end_t=99)
    assert [s["t_min"] for s in capped] == [28, 29, 30] and {s["value"] for s in capped} == {0.0001}
    last, _ = sv.bus.call("t", "telemetry.get_metric_series", asset="blr-esx-05", metric="nic_latency_ms", minutes=5)
    assert [s["t_min"] for s in last] == [26, 27, 28, 29, 30]
    # the backup event raises every host's latency by 40%, only while it runs
    def lat(t):
        return {h: sv.twin.server_signals(h, t)["nic_latency_ms"] for h in ("blr-esx-05", "blr-esx-30")}

    sv.twin.set_scenario("off")
    quiet = {t: lat(t) for t in (10, 100, 200)}
    sv.twin.set_scenario("backup")
    assert lat(10) == quiet[10] and lat(200) == quiet[200]
    assert all(math.isclose(v, 1.4 * quiet[100][h], rel_tol=1e-3) for h, v in lat(100).items())
    sv.twin.faults_enabled = True
    assert sv.twin.scenarios == {"backup", "regression"}


def test_windowed_series_over_mcp_matches_inproc(tmp_path, sv):
    mcp_sv = make_services(tmp_path / "mcp", transport="mcp")
    args = dict(asset="blr-esx-12", metric="nic_latency_ms", start_t=-12, end_t=-4)
    a, _ = mcp_sv.bus.call("t", "telemetry.get_metric_series", **args)
    b, _ = sv.bus.call("t", "telemetry.get_metric_series", **args)
    assert a == b and len(a) == 9
