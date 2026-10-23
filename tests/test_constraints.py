from blastradius.constraints import check_plan
from blastradius.solver import solve

SERVERS = [f"blr-esx-{i:02d}" for i in range(1, 41)]
SWITCHES = ["tor-r1-a", "tor-r1-b"]
COMPS = ["iLO 6", "System ROM", "Switch OS"]


def codes(res):
    return {v["code"] for v in res["violations"]}


def test_naive_plan_is_rejected(topo, sv):
    naive = {"waves": [
        {"name": "w1", "assets": SWITCHES + ["blr-esx-01", "blr-esx-21"]},
        {"name": "w2", "assets": SERVERS[1:11] + SERVERS[21:31]},
        {"name": "w3", "assets": SERVERS[11:20] + SERVERS[31:40]},
    ]}
    res = check_plan(naive, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480)
    assert not res["ok"]
    assert {"REDUNDANT_PAIR", "PLANNED_OUTAGE", "CANARY_FIRST", "CLUSTER_CAPACITY", "WAVE_SIZE"} <= codes(res)
    assert res["impacts"][0]["brs"] > 99


def test_switch_without_its_single_homed_host_is_an_outage(topo, sv):
    plan = {"waves": [{"name": "c", "assets": ["blr-esx-03"]}, {"name": "x", "assets": ["tor-r1-a"]}]}
    res = check_plan(plan, topo, ["blr-esx-03", "tor-r1-a"], COMPS, sv.policy, 480)
    outage = [v for v in res["violations"] if v["code"] == "PLANNED_OUTAGE"]
    assert outage and "payments-db-01" in outage[0]["message"]


def test_solver_plan_satisfies_every_constraint(topo, sv):
    waves = solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    res = check_plan({"waves": waves}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480)
    assert res["ok"], res["violations"]
    where = {a: i for i, w in enumerate(waves) for a in w["assets"]}
    assert where["tor-r1-a"] != where["tor-r1-b"]
    assert where["blr-esx-07"] == where["tor-r1-a"]
    assert len(waves[0]["assets"]) <= int(sv.policy.get("planning.canary_max_assets")) and not set(waves[0]["assets"]) & set(SWITCHES)
    assert res["canary_coverage"]["ok"]


def test_solver_evacuates_non_target_single_homed_host(topo, sv):
    servers = [s for s in SERVERS if s != "blr-esx-07"]
    waves = solve(servers, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    res = check_plan({"waves": waves}, topo, servers + SWITCHES, COMPS, sv.policy, 480)
    assert res["ok"], res["violations"]
    w = next(w for w in waves if "tor-r1-a" in w["assets"])
    assert "blr-esx-07" in w["evacuate"]


def test_planner_facts_never_make_a_deferred_host_look_schedulable(topo, sv):
    from blastradius.solver import grounded_rationale, plan_facts

    targets = {"servers": SERVERS, "switches": SWITCHES}
    facts = plan_facts(topo, targets, sv.policy, COMPS)
    assert [s["server"] for s in facts["single_homed_on_targets"]] == ["blr-esx-07"] and facts["evacuate_with_switch"] == []
    facts = plan_facts(topo, targets, sv.policy, COMPS, deferred=["blr-esx-07"])
    assert facts["single_homed_on_targets"] == []
    assert [(s["server"], s["up_links"], s["reason"]) for s in facts["evacuate_with_switch"]] == [("blr-esx-07", ["tor-r1-a"], "deferred")]
    # what a planner following the facts produces: the deferred host is evacuated with its switch, not upgraded
    servers = [s for s in SERVERS if s != "blr-esx-07"]
    waves = solve(servers, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    res = check_plan({"waves": waves}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480, ["blr-esx-07"])
    assert res["ok"], res["violations"]
    text = grounded_rationale(waves, facts, COMPS, res["total_duration_min"])
    assert "blr-esx-07 is single-homed and is evacuated in the same wave as tor-r1-a." in text and "scheduled in the same wave" not in text


def test_window_is_enforced(topo, sv):
    waves = solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    res = check_plan({"waves": waves}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 60)
    assert "WINDOW" in codes(res)


def test_coverage(topo, sv):
    res = check_plan({"waves": [{"name": "c", "assets": ["blr-esx-03", "blr-esx-03"]}]}, topo,
                     ["blr-esx-03", "blr-esx-04"], COMPS, sv.policy, 480)
    msgs = " ".join(v["message"] for v in res["violations"] if v["code"] == "COVERAGE")
    assert "more than once" in msgs and "not scheduled" in msgs


def test_evacuate_holds_only_scheduled_targets_or_hosts_single_homed_to_the_waves_switch(topo, sv):
    deferred = ["blr-esx-07", "blr-esx-01"]  # blr-esx-07 is single-homed to tor-r1-a; blr-esx-01 is dual-homed
    waves = solve([s for s in SERVERS if s not in deferred], SWITCHES, topo, {}, sv.policy, COMPS, 480)
    res = check_plan({"waves": waves}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480, deferred)
    assert res["ok"], res["violations"]  # a deferred host may still be evacuated for its switch
    k = next(i for i, w in enumerate(waves) if "tor-r1-a" in w["assets"])
    assert "blr-esx-07" in waves[k]["evacuate"]

    def stray(edit):
        plan = [dict(w, evacuate=list(w["evacuate"])) for w in waves]
        edit(plan)
        res = check_plan({"waves": plan}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480, deferred)
        return [a for x in res["violations"] if x["code"] == "COVERAGE" and "evacuates" in x["message"] for a in x["assets"]]

    assert stray(lambda p: p[k]["evacuate"].append("blr-esx-01")) == ["blr-esx-01"]  # deferred, not needed for the switch
    other = next(i for i in range(1, len(waves)) if i != k and "tor-r1-a" not in waves[i]["assets"])
    assert stray(lambda p: (p[k]["evacuate"].remove("blr-esx-07"), p[other]["evacuate"].append("blr-esx-07"))) == ["blr-esx-07"]
    # a host outside the change request
    servers = SERVERS[:20]
    waves = solve(servers, [], topo, {}, sv.policy, COMPS, 480)
    waves[1]["evacuate"] = ["blr-esx-21"]
    res = check_plan({"waves": waves}, topo, servers, COMPS, sv.policy, 480)
    assert [v["assets"] for v in res["violations"] if v["code"] == "COVERAGE"] == [["blr-esx-21"]]


def test_empty_plan_and_empty_wave_are_rejected(topo, sv):
    for plan in ({"waves": []}, {"waves": [{"name": "w1", "assets": []}]}):
        res = check_plan(plan, topo, [], COMPS, sv.policy, 480)
        assert not res["ok"] and "EMPTY_PLAN" in codes(res)
    plan = {"waves": [{"name": "c", "assets": ["blr-esx-03"]}, {"name": "gap", "assets": []}]}
    res = check_plan(plan, topo, ["blr-esx-03"], COMPS, sv.policy, 480)
    assert not res["ok"] and codes(res) == {"EMPTY_WAVE"}


def test_no_eligible_canary_host_gets_a_one_asset_canary(topo, sv):
    """Switch-only, single tier-0 host, or tier-0 hosts with their switches: no low-tier dual-homed canary exists."""
    from blastradius.solver import grounded_rationale, plan_facts

    for servers, switches, canary in (([], SWITCHES, ["tor-r1-b"]), ([], ["tor-r2-a"], ["tor-r2-a"]),
                                      (["blr-esx-07"], [], ["blr-esx-07"]), (["blr-esx-07"], SWITCHES, ["tor-r1-b"])):
        waves = solve(servers, switches, topo, {}, sv.policy, COMPS, 480)
        res = check_plan({"waves": waves}, topo, servers + switches, COMPS, sv.policy, 480)
        assert res["ok"], (servers, switches, res["violations"])
        assert waves[0]["assets"] == canary and res["canary_fallback"] == canary[0]
        facts = plan_facts(topo, {"servers": servers, "switches": switches}, sv.policy, COMPS)
        assert facts["no_eligible_canary"]
        assert "no tier-0 or tier-1 workloads" not in grounded_rationale(waves, facts, COMPS, res["total_duration_min"])
    # still one asset only: both members of the pair, or a switch plus a host, is not a canary
    for wave1 in (SWITCHES, ["tor-r1-b", "blr-esx-07"]):
        res = check_plan({"waves": [{"name": "c", "assets": wave1, "evacuate": []}]}, topo, wave1, COMPS, sv.policy, 480)
        assert any(v["code"] == "CANARY_FIRST" and "one-asset canary" in v["message"] for v in res["violations"])
    # with an eligible host the usual rule holds and the rationale's canary sentence is true
    waves = solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    facts = plan_facts(topo, {"servers": SERVERS, "switches": SWITCHES}, sv.policy, COMPS)
    assert not facts["no_eligible_canary"] and check_plan({"waves": waves}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480)["canary_fallback"] is None
    assert "no tier-0 or tier-1 workloads" in grounded_rationale(waves, facts, COMPS, 165)
