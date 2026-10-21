import pytest

from blastradius.agents.executor import ExecutionHalted, ExecutorAgent
from blastradius.mcp_layer import ToolCallError


def test_write_tool_refuses_without_approval(sv):
    with pytest.raises(ToolCallError) as exc:
        sv.bus.call("rogue", "compute.apply_firmware", server="blr-esx-03", component="iLO 6", version="1.64",
                    run_id="r1", approval_token="forged")
    assert "not part of an approved wave" in str(exc.value)
    assert sv.twin.servers["blr-esx-03"]["firmware"]["iLO 6"] == "1.58"
    rec = sv.evidence.get(exc.value.evidence_id)
    assert rec["ok"] is False and rec["args"]["approval_token"] == "***"


def test_token_is_scoped_to_asset_and_action(sv):
    sv.authority.grant("r1", ["blr-esx-03"], ["compute.apply_firmware"])
    tok = sv.authority.token("r1", "blr-esx-03", "compute.apply_firmware")
    res, _ = sv.bus.call("executor", "compute.apply_firmware", server="blr-esx-03", component="iLO 6", version="1.64",
                         run_id="r1", approval_token=tok)
    assert res["current"] == "1.64"
    with pytest.raises(ToolCallError):
        sv.bus.call("executor", "compute.apply_firmware", server="blr-esx-04", component="iLO 6", version="1.64",
                    run_id="r1", approval_token=tok)


def test_kill_switch_halts_execution(sv, topo, monkeypatch):
    monkeypatch.setenv("BR_KILL_SWITCH", "on")
    sv.authority.grant("r1", ["blr-esx-03"], ["virt.enter_maintenance"])
    with pytest.raises(ExecutionHalted):
        ExecutorAgent(sv).run_wave("r1", 1, {"name": "w", "assets": ["blr-esx-03"]}, ["iLO 6"], {"blr-esx-03": {"iLO 6": "1.64"}}, topo)


def test_policy_allow_list(sv):
    from blastradius.policy import PolicyViolation

    with pytest.raises(PolicyViolation):
        sv.guard.check("knowledge.record_incident", "blr-esx-03", {"blr-esx-03"})
    with pytest.raises(PolicyViolation):
        sv.guard.check("compute.apply_firmware", "blr-esx-04", {"blr-esx-03"})


def test_redaction_removes_secrets(sv):
    out = sv.policy.redact("api_key=abc123 contact ops@example.com")
    assert "abc123" not in out and "ops@example.com" not in out
