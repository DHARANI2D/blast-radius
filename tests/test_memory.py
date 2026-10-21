import json
import threading

import pytest

from blastradius import offline_llm
from blastradius.memory import PlanningMemory, as_prompt, covers, uncovered
from blastradius.workflow import Engine
from conftest import drive, make_services

PAIR = "REDUNDANT_PAIR:tor-r1-a|tor-r1-b"
CVE = "fixes_cve:System ROM:U54 v2.32:SYN-CVE-2026-1105"
# The mistakes the offline stand-in's naive attempt 1 makes on the canonical change.
NAIVE = ("REDUNDANT_PAIR", "CLUSTER_CAPACITY", "CANARY_COVERAGE", "fixes_cve")


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        self.t += 1
        return self.t


@pytest.fixture(scope="module")
def failed_run(tmp_path_factory):
    """One canonical offline run: attempt 1 is rejected, attempt 2 passes."""
    sv = make_services(tmp_path_factory.mktemp("mem"))
    eng = Engine(sv)
    r, _ = drive(eng)
    st = eng.state(r["run_id"])
    assert not st["attempts"][0]["passed"] and st["attempts"][-1]["passed"]
    return r["run_id"], st, sv.runs[r["run_id"]]["topo"]


def learned(failed_run, mem=None):
    run_id, st, topo = failed_run
    mem = mem or PlanningMemory(None, clock=Clock())
    a = st["attempts"][0]
    return mem, {r["key"]: r for r in mem.learn(run_id, a["feedback"], a, topo)}


def test_rules_from_a_real_rejected_attempt(failed_run):
    _, rules = learned(failed_run)
    assert {PAIR, CVE, "CLUSTER_CAPACITY:PROD-BLR-07", "CLUSTER_CAPACITY:PROD-BLR-08", "CANARY_COVERAGE",
            "PLANNED_OUTAGE:storage:alletra-mp-blr-01", "CANARY_FIRST:size", "pair_safe_together:tor-r1-a|tor-r1-b",
            "all_dual_homed:PROD-BLR-07", "no_known_issues:iLO 6:1.64", "cluster_capacity:PROD-BLR-07"} <= set(rules)

    pair = rules[PAIR]["guidance"]
    assert pair.startswith("Never put tor-r1-a and tor-r1-b in the same wave") and "VSX pair" in pair
    assert "alletra-mp-blr-01" in pair and "504 VMs" in pair
    cve = rules[CVE]["guidance"]
    assert cve.startswith("Do not claim System ROM U54 v2.32 fixes SYN-CVE-2026-1105")
    assert "SYN-CVE-2026-2201" in cve and "ADV-SYN-2026-017" in cve and "iLO 6 1.66" in cve
    cap = rules["CLUSTER_CAPACITY:PROD-BLR-07"]
    assert cap["args"]["limit"] == 5 and "at most 5" in cap["guidance"] and "capacity allows 7" in cap["guidance"]
    assert "NIC BCM57414 230.x" in rules["CANARY_COVERAGE"]["guidance"]
    assert rules["PLANNED_OUTAGE:storage:alletra-mp-blr-01"]["args"]["root_cause"] == "storage_unreachable"
    assert "blr-esx-07" in rules["all_dual_homed:PROD-BLR-07"]["subject"]["assets"]
    assert rules[CVE]["subject"]["components"] == ["System ROM"]

    for r in rules.values():
        assert r["hits"] == 1 and r["evidence"] and r["source"] in ("constraints", "verifier")
        assert r["source_run"] == failed_run[0] and r["first_seen"] == r["last_seen"]
    assert all(e.startswith(failed_run[0] + "/EV-") for e in rules[CVE]["evidence"])


def test_passed_attempt_teaches_nothing(failed_run):
    run_id, st, topo = failed_run
    mem = PlanningMemory(None)
    assert mem.learn(run_id, None, st["attempts"][-1], topo) == []
    assert mem.rules() == []


def test_dedupe_increments_hits_and_keeps_first_seen(failed_run):
    mem, first = learned(failed_run)
    _, again = learned(failed_run, mem)
    assert set(first) == set(again) and len(mem.rules()) == len(first)
    assert again[PAIR]["hits"] == 2 and again[PAIR]["first_seen"] == first[PAIR]["first_seen"]
    assert again[PAIR]["last_seen"] > first[PAIR]["last_seen"]


def test_persistence_round_trip_and_clear(failed_run, tmp_path):
    path = tmp_path / "planning_memory.json"
    mem, rules = learned(failed_run, PlanningMemory(path))
    mem.record_run("r1", False, 2, 0)
    other = PlanningMemory(path)  # e.g. a Streamlit rerun with fresh Services
    assert {r["key"] for r in other.rules()} == set(rules)
    assert other.stats()["runs"] == 1
    assert json.loads(path.read_text())["rules"][PAIR]["guidance"] == rules[PAIR]["guidance"]
    other.clear()
    assert mem.rules() == [] and mem.stats()["runs"] == 0


def test_retrieval_is_scoped_to_the_change(failed_run):
    mem, _ = learned(failed_run)
    blr08 = mem.retrieve({"components": ["iLO 6", "System ROM"], "target_clusters": ["PROD-BLR-08"]},
                         {"servers": [f"blr-esx-{i}" for i in range(21, 41)], "switches": []})
    keys = [r["key"] for r in blr08]
    assert keys[0] in ("CLUSTER_CAPACITY:PROD-BLR-08", "PLANNED_OUTAGE:capacity:PROD-BLR-08")
    assert PAIR not in keys or keys.index(PAIR) > keys.index("CLUSTER_CAPACITY:PROD-BLR-08")
    assert not any("PROD-BLR-07" in k for k in keys)
    assert CVE in keys and "CANARY_COVERAGE" in keys and "CANARY_FIRST:network" not in keys

    _, st, _ = failed_run
    full = mem.retrieve(st["change_request"], st["targets"])
    assert len(full) == 12 and covers(full, *NAIVE) and covers(full, "REDUNDANT_PAIR", assets=["tor-r1-b"])
    assert [r["key"] for r in full].index(PAIR) < [r["key"] for r in full].index("CANARY_COVERAGE")

    r2 = mem.retrieve({"components": ["Switch OS"]}, {"servers": [], "switches": ["tor-r2-a", "tor-r2-b"]})
    assert {r["key"] for r in r2} == {"CANARY_FIRST:size", "CANARY_FIRST:network", "WAVE_SIZE"}


def test_ranking_prefers_hits_then_recency(failed_run):
    mem, _ = learned(failed_run)
    run_id, st, topo = failed_run
    a = st["attempts"][0]
    only = [v for v in a["constraints"]["violations"] if v["code"] == "CLUSTER_CAPACITY" and "PROD-BLR-08" in v["message"]]
    mem.learn("run-2", None, {**a, "constraints": {**a["constraints"], "violations": only}, "verification": {"claims": []}}, topo)
    keys = [r["key"] for r in mem.retrieve({"components": []}, {"servers": ["blr-esx-30"]}, topo=topo)]
    assert keys[:2] == ["CLUSTER_CAPACITY:PROD-BLR-08", "PLANNED_OUTAGE:capacity:PROD-BLR-08"]


def test_prompt_and_covers(failed_run):
    mem, rules = learned(failed_run)
    text = as_prompt([rules[PAIR], rules[CVE]])
    assert text.count("\n- ") == 2 and PAIR in text and "Never put tor-r1-a" in text
    assert as_prompt([]) == ""
    assert covers([rules[CVE]], "fixes_cve") and not covers([rules[CVE]], "fixes_cve", "REDUNDANT_PAIR")
    assert covers([rules["PLANNED_OUTAGE:storage:alletra-mp-blr-01"]], "PLANNED_OUTAGE:storage")
    assert not covers([rules[PAIR]], "REDUNDANT_PAIR", assets=["tor-r2-a"]) and not covers([rules[PAIR]])
    assert uncovered([rules[CVE]], NAIVE) == ["REDUNDANT_PAIR", "CLUSTER_CAPACITY", "CANARY_COVERAGE"]


def test_stats_and_concurrent_writers(tmp_path):
    path = tmp_path / "m.json"
    mems = [PlanningMemory(path), PlanningMemory(path)]
    mems[0].record_run("a", False, 2, 0)
    mems[1].record_run("b", True, 1, 9)
    mems[1].record_run("b", True, 1, 12)  # same run recorded twice: replaced, not double-counted
    s = mems[0].stats()
    assert s["runs"] == 2 and s["first_attempt_pass_rate"] == 0.5 and s["avg_attempts"] == 1.5
    assert s["with_memory"]["first_attempt_pass_rate"] == 1.0 and s["without_memory"]["first_attempt_pass_rate"] == 0.0

    threads = [threading.Thread(target=lambda i=i: [mems[i % 2].record_run(f"t{i}-{j}", True, 1, 1) for j in range(5)])
               for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert PlanningMemory(path).stats()["runs"] == 2 + 30


def test_memory_conditioned_second_run_passes_on_attempt_one(tmp_path, monkeypatch):
    """Simulates the integration: the offline planner plans like a corrected model on attempt 1
    only when its retrieved rules already warn against the naive mistakes."""
    sv = make_services(tmp_path)
    mem, eng = PlanningMemory.from_services(sv), Engine(sv)
    retrieved: list[int] = []
    naive_planner = offline_llm.planner

    def planner(ctx):
        rules = mem.retrieve({"components": ctx["components"]},
                             {"servers": ctx["target_servers"], "switches": ctx["target_switches"],
                              "clusters": sorted(set(ctx["server_cluster"].values()))})
        retrieved.append(len(rules))
        return naive_planner(dict(ctx, naive_first=not covers(rules, *NAIVE)) if ctx["attempt"] == 1 else ctx)

    monkeypatch.setattr(offline_llm, "planner", planner)
    results = []
    for _ in range(2):
        retrieved.clear()
        r, _ = drive(eng)
        st = eng.state(r["run_id"])
        for a in st["attempts"]:
            mem.learn(r["run_id"], a.get("feedback"), a, sv.runs[r["run_id"]]["topo"])
        mem.record_run(r["run_id"], st["attempts"][0]["passed"], len(st["attempts"]), retrieved[0])
        results.append((st["attempts"][0]["passed"], len(st["attempts"]), retrieved[0]))
        sv.reset_lab(forget_lessons=False)  # "New run": keep the rollback lesson, restore the twin

    assert results[0] == (False, 2, 0)
    assert results[1][:2] == (True, 1) and results[1][2] > 0
    s = mem.stats()
    assert s["first_attempt_pass_rate"] == 0.5 and s["with_memory"]["first_attempt_pass_rate"] == 1.0
    assert s["without_memory"]["first_attempt_pass_rate"] == 0.0 and s["rules"] >= 15
