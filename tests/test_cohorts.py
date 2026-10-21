from blastradius.cohorts import build, coverage, risk_ranked_canary, select_canary
from blastradius.constraints import check_plan
from blastradius.solver import solve

SERVERS = [f"blr-esx-{i:02d}" for i in range(1, 41)]
SWITCHES = ["tor-r1-a", "tor-r1-b"]
COMPS = ["iLO 6", "System ROM", "Switch OS"]


def test_cohorts_split_on_model_and_untouched_firmware(topo):
    cohorts = build(SERVERS, topo.servers, COMPS)
    sizes = {c["label"]: len(c["hosts"]) for c in cohorts}
    assert sizes == {"DL360 Gen11 · NIC BCM57414 230.x": 20, "DL380 Gen11 · NIC BCM57414 229.x": 16,
                     "DL380 Gen11 · NIC BCM57414 230.x": 4}
    # components being changed do not split cohorts (iLO drift on DL360s is irrelevant here)
    assert len(build(SERVERS, topo.servers, ["iLO 6", "System ROM", "NIC BCM57414"])) == 2


def test_cohort_canary_covers_every_cohort_and_risk_ranked_does_not(topo, sv):
    cohorts = build(SERVERS, topo.servers, COMPS)
    canary = select_canary(SERVERS, topo, {}, sv.policy, COMPS)
    assert coverage(canary, cohorts, topo, sv.policy)["ok"]
    for h in canary:  # canary hosts stay safe: no tier-0/1 workloads, not single-homed
        assert (topo.most_critical_tier(h) or 3) >= 2 and h != "blr-esx-07"
    naive = risk_ranked_canary(SERVERS, topo, {h: 0 if h in ("blr-esx-03", "blr-esx-11", "blr-esx-21") else 5 for h in SERVERS}, sv.policy)
    cov = coverage(naive, cohorts, topo, sv.policy)
    assert not cov["ok"] and [m["label"] for m in cov["missing"]] == ["DL380 Gen11 · NIC BCM57414 229.x"]


def test_constraint_rejects_canary_that_misses_a_cohort(topo, sv):
    waves = solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    ok = check_plan({"waves": waves}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480)
    assert ok["ok"], ok["violations"]
    bad = [dict(w) for w in waves]
    nic229 = {h for h in SERVERS if topo.servers[h]["firmware"]["NIC BCM57414"].startswith("229.")}
    moved = [h for h in bad[0]["assets"] if h in nic229]
    bad[0] = dict(bad[0], assets=[h for h in bad[0]["assets"] if h not in nic229])
    bad[-1] = dict(bad[-1], assets=bad[-1]["assets"] + moved)
    res = check_plan({"waves": bad}, topo, SERVERS + SWITCHES, COMPS, sv.policy, 480)
    assert any(v["code"] == "CANARY_COVERAGE" and "229.x" in v["message"] for v in res["violations"])


def test_verifier_checks_cohort_claim_against_inventory(sv, topo):
    from blastradius.agents import IntakeAgent, RiskAgent, VerifierAgent

    from conftest import INTENT

    out = IntakeAgent(sv).run(INTENT)
    risk = RiskAgent(sv).run(out["targets"], out["change_request"]["components"], topo)
    waves = solve(SERVERS, SWITCHES, topo, {}, sv.policy, COMPS, 480)
    v = VerifierAgent(sv)
    claim = {"text": "The canary covers all 3 configuration cohorts.", "type": "canary_covers_cohorts", "args": {"cohorts": 3}}
    ctx = {"plan": {"waves": waves}, "cr": out["change_request"], "topo": topo, "target_versions": risk["target_versions"]}
    assert v.check(claim, ctx)[0] == "Supported"
    one_cohort = [dict(waves[0], assets=["blr-esx-21"])] + waves[1:]
    label, why, ev = v.check(claim, dict(ctx, plan={"waves": one_cohort}))
    assert label == "Contradicted" and "229.x" in why and ev


def test_evacuation_is_simulated_per_vm_not_by_aggregate_memory(topo, sv):
    from blastradius.constraints import impact_kwargs

    # Aggregate memory says PROD-BLR-07 can lose 7 hosts, but payments-db-01 (256 GB) needs 256 GB free on ONE host.
    assert topo.cluster_capacity("PROD-BLR-07")["max_hosts_down"] >= 4
    imp = topo.simulate([], ["blr-esx-11", "blr-esx-16", "blr-esx-20", "blr-esx-07"], **impact_kwargs(sv.policy))
    assert "payments-db-01" in imp["impacted_vms"] and "256 GB" in imp["impact_reasons"]["payments-db-01"]
    # Evacuating the big host first leaves room for it.
    imp = topo.simulate([], ["blr-esx-07", "blr-esx-11"], **impact_kwargs(sv.policy))
    assert not imp["impacted_vms"]
