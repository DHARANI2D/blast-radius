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
