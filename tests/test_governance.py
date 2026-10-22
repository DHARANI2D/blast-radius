import pytest
from conftest import INTENT, drive, make_services

from blastradius.agents.executor import ExecutionHalted, ExecutorAgent
from blastradius.mcp_layer import ToolCallError
from blastradius.workflow import Engine


def test_write_tool_refuses_without_approval(sv):
    with pytest.raises(ToolCallError) as exc:
        sv.bus.call("rogue", "compute.apply_firmware", server="blr-esx-03", component="iLO 6", version="1.64",
                    run_id="r1", approval_token="forged")
    assert "not part of an approved wave" in str(exc.value)
    assert sv.twin.servers["blr-esx-03"]["firmware"]["iLO 6"] == "1.58"
    rec = sv.evidence.get(exc.value.evidence_id)
    assert rec["ok"] is False and rec["args"]["approval_token"] == "***"


def test_token_is_scoped_to_asset_action_and_version(sv):
    sv.authority.grant("r1", ["blr-esx-03"], ["compute.apply_firmware"], {"blr-esx-03": ["1.64"]})
    tok = sv.authority.token("r1", "blr-esx-03", "compute.apply_firmware", "1.64")
    res, _ = sv.bus.call("executor", "compute.apply_firmware", server="blr-esx-03", component="iLO 6", version="1.64",
                         run_id="r1", approval_token=tok)
    assert res["current"] == "1.64"
    with pytest.raises(ToolCallError):
        sv.bus.call("executor", "compute.apply_firmware", server="blr-esx-04", component="iLO 6", version="1.64",
                    run_id="r1", approval_token=tok)
    # a token minted for another version is refused: the grant names the approved version only
    evil = sv.authority.token("r1", "blr-esx-03", "compute.apply_firmware", "0.00-EVIL")
    with pytest.raises(ToolCallError) as exc:
        sv.bus.call("executor", "compute.apply_firmware", server="blr-esx-03", component="iLO 6", version="0.00-EVIL",
                    run_id="r1", approval_token=evil)
    assert "to 0.00-EVIL is not part of an approved wave" in str(exc.value)
    assert sv.twin.servers["blr-esx-03"]["firmware"]["iLO 6"] == "1.64"


def _rogue_writes(sv, run_id, host):
    """Try each write tool on a host with a correctly minted token; return the ones the MCP server accepted."""
    accepted = []
    calls = [("virt.enter_maintenance", "", {"host": host}),
             ("compute.apply_firmware", "1.64", {"server": host, "component": "iLO 6"}),
             ("virt.exit_maintenance", "", {"host": host})]
    for tool, version, args in calls:
        tok = sv.authority.token(run_id, host, tool, version)
        try:
            sv.bus.call("rogue", tool, run_id=run_id, approval_token=tok, **({"version": version} if version else {}), **args)
            accepted.append(tool)
        except ToolCallError:
            pass
    return accepted


def test_write_access_ends_with_every_run_outcome(tmp_path):
    # completed
    sv = make_services(tmp_path / "a", faults=False)
    r, _ = drive(Engine(sv))
    assert r["state"]["status"] == "completed"
    assert _rogue_writes(sv, r["run_id"], r["state"]["plan"]["waves"][0]["assets"][0]) == []
    # canary rejected, and fleet rejected after a passing canary
    sv = make_services(tmp_path / "b", faults=False)
    eng = Engine(sv)
    r = eng.start(INTENT)
    r = eng.resume(r["run_id"], {"decision": "reject", "approver": "asha.ops"})
    assert r["state"]["status"] == "rejected" and _rogue_writes(sv, r["run_id"], "blr-esx-21") == []
    r = eng.start(INTENT)
    r = eng.resume(r["run_id"], {"decision": "approve", "approver": "asha.ops"})
    assert r["interrupt"]["scope"] == "fleet"
    # while the fleet decision is pending, neither the finished canary nor the unapproved fleet waves are writable
    canary_host, fleet_host = r["state"]["plan"]["waves"][0]["assets"][0], r["state"]["plan"]["waves"][1]["assets"][0]
    assert _rogue_writes(sv, r["run_id"], canary_host) == [] and _rogue_writes(sv, r["run_id"], fleet_host) == []
    r = eng.resume(r["run_id"], {"decision": "reject", "approvers": ["ravi.net"]})
    assert r["state"]["status"] == "stopped_after_canary"
    assert _rogue_writes(sv, r["run_id"], canary_host) == []


def test_grants_are_bound_to_the_approved_target_version(tmp_path):
    sv = make_services(tmp_path, faults=False)
    eng = Engine(sv)
    r = eng.start(INTENT)
    rid, st = r["run_id"], r["state"]
    sent = []
    real = sv.bus.call

    def spy(agent, key, **args):
        if key == "compute.apply_firmware" and not sent:
            # first firmware write of the approved canary: replay it with another version and a matching token
            sent.append(args)
            evil = dict(args, version="0.00-EVIL", approval_token=sv.authority.token(rid, args["server"], key, "0.00-EVIL"))
            with pytest.raises(ToolCallError):
                real("rogue", key, **evil)
        return real(agent, key, **args)

    sv.bus.call = spy
    r = eng.resume(rid, {"decision": "approve", "approver": "asha.ops"})
    host = sent[0]["server"]
    assert sent[0]["version"] == st["risk"]["target_versions"][host][sent[0]["component"]]
    assert "EVIL" not in "".join(sv.twin.servers[host]["firmware"].values())


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
