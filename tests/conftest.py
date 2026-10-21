import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blastradius.services import Services  # noqa: E402
from blastradius.workflow import Engine  # noqa: E402

INTENT = ("Upgrade iLO 6 and System ROM on clusters PROD-BLR-07 and PROD-BLR-08 and the ToR switch pair "
          "to the latest baseline this Saturday 10pm")


def make_services(tmp_path, transport="inproc", faults=True):
    sv = Services.create(tool_transport=transport, faults_enabled=faults, ledger_path=":memory:",
                         runtime_dir=tmp_path / "runtime", llm_mode="offline")
    sv.reset_lab(forget_lessons=True)
    return sv


@pytest.fixture
def sv(tmp_path):
    return make_services(tmp_path)


@pytest.fixture
def engine(sv):
    return Engine(sv)


@pytest.fixture
def topo(sv):
    from blastradius.agents import TopologyAgent

    t, _ = TopologyAgent(sv).run()
    return t


def drive(engine, intent=INTENT, fleet_approvers=("asha.ops", "ravi.net"), canary="approve"):
    """Run to completion, answering every approval gate."""
    r = engine.start(intent)
    gates = []
    while r["interrupt"]:
        scope = r["interrupt"]["scope"]
        gates.append(r["interrupt"])
        if scope == "canary":
            r = engine.resume(r["run_id"], {"decision": canary, "approver": "asha.ops"})
        elif scope == "fleet":
            r = engine.resume(r["run_id"], {"decision": "approve", "approvers": list(fleet_approvers)})
        else:
            r = engine.resume(r["run_id"], {"decision": "abort", "approver": "test"})
    return r, gates
