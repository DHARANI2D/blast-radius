import random
import time
from collections import Counter
from itertools import product

import pytest

from conftest import make_services
from blastradius import premortem as pm
from blastradius.agents import RiskAgent, TopologyAgent
from blastradius.policy import Policy
from blastradius.solver import solve

SERVERS = [f"blr-esx-{i:02d}" for i in range(1, 41)]
SWITCHES = ["tor-r1-a", "tor-r1-b"]
COMPS = ["iLO 6", "System ROM", "Switch OS"]
NAIVE = {"waves": [
    {"name": "w1", "assets": SWITCHES + ["blr-esx-01", "blr-esx-21"]},
    {"name": "w2", "assets": SERVERS[1:11] + SERVERS[21:31]},
    {"name": "w3", "assets": SERVERS[11:20] + SERVERS[31:40]},
]}


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    sv = make_services(tmp_path_factory.mktemp("premortem"))
    topo, _ = TopologyAgent(sv).run()
    risk = RiskAgent(sv).run({"servers": SERVERS, "switches": SWITCHES}, COMPS, topo)
    scores = {a: r["score"] for a, r in risk["assets"].items()}
    plan = {"waves": solve(SERVERS, SWITCHES, topo, scores, sv.policy, COMPS, 480)}
    return sv, topo, risk, plan


def with_premortem(policy: Policy, **over) -> Policy:
    return Policy({**policy.data, "premortem": over})


def subsets(probs):
    for bits in product((0, 1), repeat=len(probs)):
        w = 1.0
        for b, p in zip(bits, probs):
            w *= p if b else 1 - p
        yield tuple(i for i, b in enumerate(bits) if b), w


def test_samplers_are_exact():
    probs = [0.1, 0.3, 0.05, 0.2]
    none, one, more = pm._split(probs)
    exact = dict(subsets(probs))
    assert none == pytest.approx(exact[()])
    assert one == pytest.approx([exact[(i,)] for i in range(4)])
    assert more == pytest.approx(sum(w for s, w in exact.items() if len(s) >= 2))

    rng, n = random.Random(3), 40000
    two = pm._TwoPlus(list(range(4)), probs)
    got = Counter(tuple(two(rng)) for _ in range(n))
    for s, w in exact.items():
        expected = w / more if len(s) >= 2 else 0.0
        assert abs(got[s] / n - expected) < 0.01, s
    got = Counter(tuple(pm._at_least_one(rng, list(range(4)), probs, 1 - none)) for _ in range(n))
    for s, w in exact.items():
        assert abs(got[s] / n - (w / (1 - none) if s else 0.0)) < 0.01, s


def test_simcache_matches_simulate(lab):
    sv, topo, _, _ = lab
    sim = pm.SimCache(topo, sv.policy)
    kw = pm.impact_kwargs(sv.policy)
    rng = random.Random(7)
    switches, hosts = sorted(topo.switches), sorted(topo.servers)
    for i in range(60):
        down = frozenset(rng.sample(switches, rng.choice([0, 0, 1, 1, 2, 3])))
        maint = tuple(rng.sample(hosts, rng.choice([0, 1, 2, 5, 8, 12])))
        direct = set(topo.simulate(down, list(maint), **kw)["impacted_vms"])
        assert sim.lost(down, maint) == direct, (down, maint)
    # both paths ran: some placements needed simulate, others were proven by the shortcut
    placed = sum(1 for _, _, sub in sim.cache if sub)
    assert len(sim._net) < sim.calls < len(sim._net) + placed


def test_deterministic_with_seed(lab):
    sv, topo, risk, plan = lab
    a = pm.premortem(plan, topo, risk, sv.policy, COMPS, samples=200, seed=11)
    b = pm.premortem(plan, topo, risk, sv.policy, COMPS, samples=200, seed=11)
    shared = pm.SimCache(topo, sv.policy)
    pm.premortem(NAIVE, topo, risk, sv.policy, COMPS, samples=200, seed=11, sim=shared)  # warm memo
    c = pm.premortem(plan, topo, risk, sv.policy, COMPS, samples=200, seed=11, sim=shared)
    a.pop("simulate_calls"), b.pop("simulate_calls"), c.pop("simulate_calls")
    assert a == b == c
    d = pm.premortem(plan, topo, risk, sv.policy, COMPS, samples=200, seed=12)
    assert abs(d["p_tier0_loss"] - a["p_tier0_loss"]) < 4 * (a["p_tier0_loss_se"] + d["p_tier0_loss_se"]) + 1e-9


def test_naive_plan_with_both_vsx_members_is_a_certain_tier0_loss(lab):
    sv, topo, risk, _ = lab
    res = pm.premortem(NAIVE, topo, risk, sv.policy, COMPS, samples=300)
    w1 = res["waves"][0]
    assert res["p_tier0_loss"] == 1.0 and w1["p_tier0_loss"] == 1.0
    assert w1["planned_vms_lost"] == len(topo.vms) and w1["p95_vms_lost"] == len(topo.vms)
    assert w1["top_scenarios"][0]["events"] == [] and w1["top_scenarios"][0]["probability"] == 1.0
    assert res["p_completes_in_window"] == 0.0


def test_solver_plan_has_small_nonzero_tier0_risk(lab):
    sv, topo, risk, plan = lab
    res = pm.premortem(plan, topo, risk, sv.policy, COMPS)
    assert 0 < res["p_tier0_loss"] < 0.02
    assert all(0 < w["p_tier0_loss"] < 0.005 and w["planned_vms_lost"] == 0 for w in res["waves"])
    assert res["p_tier0_loss_without_change"] < res["p_tier0_loss"]
    assert res["p95_vms_lost"] == 0 and res["expected_vms_lost"] < 2
    # the classic pre-mortem story: the VSX peer fails while its partner is upgrading
    wave = next(w for w in res["waves"] if "tor-r1-a" in w["assets"])
    stories = wave["top_scenarios"] + [wave["worst_scenario"]]
    peer = next(s for s in stories if s["events"] == [["during", "tor-r1-b"]])
    assert peer["scenario"] == "if tor-r1-b fails while tor-r1-a is upgrading"
    assert peer["vms_lost"] == len(topo.vms) and peer["attributable_to_change"]
    rate = pm.DEFAULTS["background_failure_per_hour"]["switch"] * wave["duration_min"] / 60
    assert peer["probability"] == pytest.approx(rate, rel=0.05)


def test_raising_base_probabilities_raises_tier0_risk(lab):
    sv, topo, risk, plan = lab
    base = pm.DEFAULTS["base_failure_prob"]
    sim = pm.SimCache(topo, sv.policy)
    runs = [pm.premortem(plan, topo, risk, with_premortem(sv.policy, base_failure_prob={k: v * f for k, v in base.items()}),
                         COMPS, samples=500, sim=sim) for f in (0.5, 1, 2, 4)]
    for lo, hi in zip(runs, runs[1:]):
        assert hi["p_tier0_loss"] >= lo["p_tier0_loss"]
        assert all(h["p_tier0_loss"] >= w["p_tier0_loss"] for w, h in zip(lo["waves"], hi["waves"]))
        assert hi["p_completes_in_window"] < lo["p_completes_in_window"]
    assert runs[-1]["p_tier0_loss"] > runs[0]["p_tier0_loss"]


def test_full_plan_runs_within_two_seconds(lab):
    sv, topo, risk, plan = lab
    assert len(plan["waves"]) >= 5
    t = time.perf_counter()
    res = pm.premortem(plan, topo, risk, sv.policy, COMPS)  # cold memo, 2000 samples per wave
    assert time.perf_counter() - t < 2.0
    assert res["simulate_calls"] < 400


def test_assumptions_are_returned_and_shown(lab):
    sv, topo, risk, plan = lab
    pol = with_premortem(sv.policy, background_failure_per_hour={"switch": 0.002}, repair_hours={"server": 3})
    cmp = pm.compare({"naive": NAIVE, "accepted": plan}, topo, risk, pol, COMPS, samples=300)
    a = cmp["assumptions"]
    assert a["measured"] is False and "not from measured failure rates" in a["note"]
    assert a["background_failure_per_hour"] == {"server": 0.001, "switch": 0.002}
    assert a["repair_hours"] == {"server": 3.0, "switch": 4.0}
    naive, accepted = cmp["rows"]
    assert naive["p_tier0_loss"] == 1.0 > accepted["p_tier0_loss"] > 0
    res = cmp["results"]["accepted"]
    lines = pm.card_lines(res)
    assert "assumption-driven" in lines[0] and lines[-1].startswith("Assumptions:")
    assert len(lines) == len(plan["waves"]) + 2
    view = pm.card_view(res)
    assert view["assumptions"]["measured"] is False and len(view["waves"]) == len(plan["waves"])
