import pytest
from conftest import INTENT, make_services

from blastradius.agents import IntakeAgent, PlannerAgent, RiskAgent, TopologyAgent, VerifierAgent
from blastradius.constraints import check_plan, wave_impact
from blastradius.optimizer import _Model, describe, objective_weights, optimize, regrounded
from blastradius.policy import Policy
from blastradius.solver import solve

ITER = 1500  # enough to converge on the canonical scenario; tests pass a generous time budget so runs are deterministic


@pytest.fixture(scope="module")
def scenario(tmp_path_factory):
    sv = make_services(tmp_path_factory.mktemp("opt"))
    topo, _ = TopologyAgent(sv).run()
    out = IntakeAgent(sv).run(INTENT)
    cr, targets = out["change_request"], out["targets"]
    risk = RiskAgent(sv).run(targets, cr["components"], topo)
    waves, _ = PlannerAgent(sv).solver_plan(cr, targets, risk, topo)
    plan = {"waves": waves, "rationale": "", "self_confidence": None}
    return {"sv": sv, "topo": topo, "cr": cr, "targets": targets, "risk": risk, "plan": plan}


def run(s, plan=None, **kw):
    kw = {"iterations": ITER, "time_budget_s": 60, **kw}
    return optimize(plan or s["plan"], s["targets"], s["topo"], s["risk"], s["sv"].policy, s["cr"]["components"],
                    s["cr"]["window"]["duration_minutes"], s["risk"]["deferred"], **kw)


def check(s, plan, targets=None):
    t = targets or s["targets"]["servers"] + s["targets"]["switches"]
    return check_plan(plan, s["topo"], t, s["cr"]["components"], s["sv"].policy, s["cr"]["window"]["duration_minutes"])


def wave_of(plan, asset):
    return next(i for i, w in enumerate(plan["waves"], 1) if asset in w["assets"])


@pytest.fixture(scope="module")
def result(scenario):
    return run(scenario, seed=5)


def test_optimised_plan_is_feasible_and_scores_better(scenario, result):
    assert result["status"] == "improved"
    assert check(scenario, result["plan"])["ok"] and result["check"]["ok"]
    b, a = result["before"], result["after"]
    assert a["J"] < b["J"] and a["exposure"] < b["exposure"]
    assert a["duration_min"] <= b["duration_min"] and a["waves"] <= b["waves"]  # greedy is already at the minimum
    # the riskiest asset (tor-r1-a, carrying the single-homed tier-0 host) moves from right after the canary to later
    assert wave_of(scenario["plan"], "tor-r1-a") == 2 and wave_of(result["plan"], "tor-r1-a") > 3
    row = next(c for c in result["changes"] if c["asset"] == "tor-r1-a")
    assert row["validated_before_pct"][1] > row["validated_before_pct"][0]
    assert result["moves"] and all(m["kind"] in ("move", "swap", "move_switch", "reorder", "split", "merge") for m in result["moves"])
    assert result["stats"]["stopped_by"] == "iterations"
    assert describe(result).startswith("optimiser: J ") and "tor-r1-a wave 2 -> " in describe(result)


def test_canary_fixed_peers_separated_single_homed_host_rides_with_its_switch(scenario, result):
    p, t = result["plan"], scenario["topo"]
    assert p["waves"][0] == scenario["plan"]["waves"][0]
    assert wave_of(p, "tor-r1-a") != wave_of(p, "tor-r1-b")
    assert wave_of(p, "blr-esx-07") == wave_of(p, "tor-r1-a")
    for w in p["waves"][1:]:
        sws = [a for a in w["assets"] if a in t.switches]
        assert not any(t.peer_of(s) in sws for s in sws)


def test_deterministic_for_a_seed(scenario, result):
    again = run(scenario, seed=5)
    assert again["plan"]["waves"] == result["plan"]["waves"] and again["after"] == result["after"]
    assert [m["detail"] for m in again["moves"]] == [m["detail"] for m in result["moves"]]
    other = run(scenario, seed=11)
    assert other["status"] == "improved" and check(scenario, other["plan"])["ok"]


def test_time_budget_is_respected_and_result_stays_feasible(scenario):
    res = run(scenario, iterations=10 ** 6, time_budget_s=0.3)
    assert res["stats"]["stopped_by"] == "time_budget"
    assert res["stats"]["elapsed_s"] < 0.3 + 0.5
    assert check(scenario, res["plan"])["ok"] and res["after"]["J"] <= res["before"]["J"]
    assert "stopped by the time cap after" in describe(res)


def test_iterations_not_the_clock_decide_the_plan(scenario, monkeypatch):
    """The policy's time budget is only a safety cap: a machine five times slower gets the same plan."""
    import time

    import blastradius.optimizer as opt

    def default():
        return optimize(scenario["plan"], scenario["targets"], scenario["topo"], scenario["risk"], scenario["sv"].policy,
                        scenario["cr"]["components"], 480, scenario["risk"]["deferred"],
                        time_budget_s=float(scenario["sv"].policy.get("optimizer.time_budget_s")))

    fast = default()
    real = time.perf_counter
    monkeypatch.setattr(opt.time, "perf_counter", lambda: 5 * real())
    slow = default()
    assert fast["stats"]["stopped_by"] == slow["stats"]["stopped_by"] == "iterations"
    assert fast["plan"]["waves"] == slow["plan"]["waves"] and check(scenario, fast["plan"])["ok"]
    assert "time cap" not in describe(fast)


def test_objective_breakdown_matches_its_definition(scenario, result):
    w = result["weights"]
    for e in (result["before"], result["after"]):
        j = e["duration_min"] + w["w_brs"] * e["sum_brs"] + w["w_exposure"] * e["exposure"] + w["w_waves"] * e["waves"]
        assert abs(j - e["J"]) < 0.01 + w["w_brs"] * 0.05 + w["w_exposure"] * 0.0005
    pol = Policy({**scenario["sv"].policy.data, "optimizer": {"w_exposure": 0, "w_waves": 100}})
    res = optimize(scenario["plan"], scenario["targets"], scenario["topo"], scenario["risk"], pol,
                   scenario["cr"]["components"], 480, iterations=300, time_budget_s=60)
    assert res["weights"]["w_exposure"] == 0 and res["after"]["terms"]["exposure"] == 0
    assert res["after"]["waves"] <= res["before"]["waves"]


def test_closed_form_brs_matches_the_simulation(scenario, result):
    # The search scores outage-free waves without simulating them; that shortcut must be exact.
    s = scenario
    model = _Model(s["topo"], s["sv"].policy, s["cr"]["components"], 480, {}, objective_weights(s["sv"].policy))
    for p in (s["plan"], result["plan"]):
        for w in p["waves"]:
            w = {"assets": w["assets"], "evacuate": w.get("evacuate", [])}
            assert model.rules(w)["brs"] == wave_impact(w, s["topo"], s["sv"].policy)["brs"]


def test_deferred_hosts_stay_deferred(scenario):
    s = scenario
    deferred = ["blr-esx-02", "blr-esx-05", "blr-esx-12"]
    scores = {a: r["score"] for a, r in s["risk"]["assets"].items()}
    servers = [h for h in s["targets"]["servers"] if h not in deferred]
    waves = solve(servers, s["targets"]["switches"], s["topo"], scores, s["sv"].policy, s["cr"]["components"], 480)
    res = optimize({"waves": waves, "rationale": ""}, s["targets"], s["topo"], s["risk"], s["sv"].policy,
                   s["cr"]["components"], 480, [{"asset": d} for d in deferred], iterations=600, time_budget_s=60)
    assert res["status"] == "improved" and res["after"]["J"] < res["before"]["J"]
    assert check_plan(res["plan"], s["topo"], s["targets"]["servers"] + s["targets"]["switches"], s["cr"]["components"],
                      s["sv"].policy, 480, deferred)["ok"]
    assert not set(deferred) & {a for w in res["plan"]["waves"] for a in w["assets"]}


def test_infeasible_input_is_returned_unchanged(scenario):
    naive = {"waves": [{"name": "w1", "assets": ["tor-r1-a", "tor-r1-b", "blr-esx-01", "blr-esx-21"]},
                       {"name": "w2", "assets": [f"blr-esx-{i:02d}" for i in [*range(2, 21), *range(22, 41)]]}],
             "rationale": "naive"}
    res = run(scenario, plan=naive)
    assert res["status"] == "infeasible_input" and res["plan"] is naive and not res["improved"] and not res["moves"]


def test_no_improvement_returns_the_input_plan(scenario):
    s = scenario
    plan = {"waves": [{"name": "Wave 1 - canary", "assets": ["blr-esx-21", "blr-esx-01", "blr-esx-03"], "evacuate": []},
                      {"name": "Wave 2 - hosts", "assets": ["blr-esx-02", "blr-esx-22"], "evacuate": []}], "rationale": ""}
    targets = ["blr-esx-21", "blr-esx-01", "blr-esx-03", "blr-esx-02", "blr-esx-22"]
    assert check(s, plan, targets)["ok"]
    res = optimize(plan, targets, s["topo"], s["risk"], s["sv"].policy, s["cr"]["components"], 480,
                   iterations=300, time_budget_s=60)
    assert res["status"] == "no_improvement" and res["plan"] is plan and res["after"] == res["before"]
    assert describe(res).startswith("optimiser kept the plan (no improvement")


def test_non_target_single_homed_host_stays_evacuated_with_its_switch(scenario):
    s = scenario
    servers = [h for h in s["targets"]["servers"] if h != "blr-esx-07"]
    targets = servers + s["targets"]["switches"]
    waves = solve(servers, s["targets"]["switches"], s["topo"], {}, s["sv"].policy, s["cr"]["components"], 480)
    res = optimize({"waves": waves, "rationale": ""}, targets, s["topo"], s["risk"], s["sv"].policy,
                   s["cr"]["components"], 480, iterations=ITER, time_budget_s=60)
    assert res["status"] == "improved" and check(s, res["plan"], targets)["ok"]
    w = res["plan"]["waves"][wave_of(res["plan"], "tor-r1-a") - 1]
    assert "blr-esx-07" in w["evacuate"] and not any("blr-esx-07" in x["evacuate"] for x in res["plan"]["waves"] if x is not w)


def test_verifier_passes_on_the_optimised_plan(scenario, result):
    s = scenario
    plan = regrounded(result["plan"], s["topo"], s["targets"], s["sv"].policy, s["cr"]["components"], s["risk"]["deferred"])
    assert f"about {result['after']['duration_min']} minutes" in plan["rationale"]
    ver = VerifierAgent(s["sv"]).run(plan, s["cr"], s["topo"], s["risk"])
    assert ver["passed"] and ver["counts"].get("Contradicted", 0) == 0
