import pytest
from conftest import INTENT, drive, make_services

from blastradius.agents import TopologyAgent
from blastradius.agents.executor import ExecutionHalted, ExecutorAgent
from blastradius.agents.rollback import RollbackAgent
from blastradius.mcp_layer import ToolCallError
from blastradius.workflow import MAINTENANCE_ACTIONS, Engine


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


def test_redaction_is_json_aware_and_covers_common_secret_forms(sv):
    import json

    secrets = {"password": "S1", "aws_secret_access_key": "S2", "client_secret": "S3", "api_token": 12345}
    intent = ('creds {"password": "S4"} secret_key=S5 private_key=S6 Authorization: Bearer S7.x the pwd is S8 '
              'api-token "S9"; -----BEGIN RSA PRIVATE KEY-----\nS10\n-----END RSA PRIVATE KEY----- Upgrade PROD-BLR-07')
    prompt = json.dumps({"ilo": secrets, "intent": intent})
    out = sv.policy.redact(prompt)
    back = json.loads(out)  # still valid JSON
    assert not any(f"S{i}" in out for i in range(1, 11)) and "12345" not in out
    assert back["ilo"] == {k: "[REDACTED]" for k in secrets}
    assert back["intent"].startswith('creds {"password": "[REDACTED]"} secret_key=[REDACTED]') and "PROD-BLR-07" in back["intent"]
    # the same redaction reaches the wire on the chat_tools path
    from blastradius.llm import OpenAICompatClient

    sent = []
    llm = OpenAICompatClient("http://llm.invalid", "k", "m", "openai", "", 5, sv.policy.redact)
    llm._request = lambda body: sent.append(body) or {"content": "ok"}
    llm.chat_tools("investigator", [{"role": "user", "content": prompt}], [])
    assert json.loads(sent[0]["messages"][0]["content"]) == back


def test_kill_switch_mid_wave_keeps_the_record_of_applied_writes(tmp_path, monkeypatch):
    sv = make_services(tmp_path, faults=False)
    monkeypatch.delenv("BR_KILL_SWITCH", raising=False)
    real = sv.bus.call

    def spy(agent, key, **args):
        res = real(agent, key, **args)
        if key == "compute.apply_firmware":
            monkeypatch.setenv("BR_KILL_SWITCH", "on")  # the operator hits the kill switch after the first flash
        return res

    sv.bus.call = spy
    r, _ = drive(Engine(sv))
    st, rep = r["state"], r["state"]["report"]
    assert st["status"] == "halted" and "kill switch" in st["halt_reason"]
    part = st["executions"][-1]
    assert part["result"] == "halted" and len(part["firmware_changes"]) == 1
    host = part["firmware_changes"][0]["asset"]
    assert sorted(part["in_maintenance"]) == sorted(sv.twin.maintenance)  # nothing could write, so the hosts stay put
    halted = [e["payload"] for e in sv.ledger.entries(r["run_id"]) if e["event"] == "halted"][0]
    assert halted["firmware_changes"] == part["firmware_changes"] and len(halted["actions"]) == len(part["actions"])
    assert rep["halt_reason"] == st["halt_reason"] and rep["partial_wave"]["firmware_changes"] == part["firmware_changes"]
    assert rep["waves"][0]["result"] == "halted"
    steps = rep["manual_steps"]
    assert any(s.startswith(f"{host}: revert iLO 6") for s in steps)
    assert all(any(s.startswith(f"{h}: exit maintenance") for s in steps) for h in part["in_maintenance"])


def test_tool_error_mid_wave_rolls_back_the_partial_wave(tmp_path, monkeypatch):
    sv = make_services(tmp_path, faults=False)
    monkeypatch.delenv("BR_KILL_SWITCH", raising=False)
    before = {h: dict(s["firmware"]) for h, s in sv.twin.servers.items()}
    real = sv.twin.apply_firmware
    flashed = []

    def flaky(server, component, version):
        if flashed and server != flashed[0]:
            raise RuntimeError("iLO did not answer")  # the second host's first flash fails
        flashed.append(server)
        return real(server, component, version)

    sv.twin.apply_firmware = flaky
    r, _ = drive(Engine(sv))
    st = r["state"]
    assert st["status"] == "rolled_back" and "iLO did not answer" in st["halt_reason"]
    part = st["executions"][-1]
    assert part["result"] == "halted" and {c["asset"] for c in part["firmware_changes"]} == {flashed[0]}
    assert {x["asset"] for x in st["rollback"]["reverted"]} == {flashed[0]}
    assert sv.twin.servers[flashed[0]]["firmware"] == before[flashed[0]]
    assert sv.twin.maintenance == set()  # the partial wave's hosts were returned to service
    assert st["report"]["halt_reason"] == st["halt_reason"] and st["report"]["manual_steps"] == []


def test_rollback_of_a_switch_wave_re_evacuates_the_hosts_the_wave_evacuated(tmp_path):
    sv = make_services(tmp_path, faults=False)
    topo, _ = TopologyAgent(sv).run()
    host, sw = "blr-esx-07", "tor-r1-a"  # blr-esx-07 is single-homed to tor-r1-a
    sv.authority.grant("r1", [host], MAINTENANCE_ACTIONS)
    sv.authority.grant("r1", [sw], ["network.upgrade_switch_os"], {sw: ["10.14.1000"]})
    ex = ExecutorAgent(sv).run_wave("r1", 2, {"name": "w", "assets": [sw], "evacuate": [host]}, ["Switch OS"],
                                    {sw: {"Switch OS": "10.14.1000"}}, topo)
    sv.authority.grant("r1", [sw], ["network.upgrade_switch_os"], {sw: [ex["firmware_changes"][0]["from"]]})
    evacuated_at_revert = []
    real = sv.twin.upgrade_switch_os

    def spy(switch, version, hold_down=True):
        evacuated_at_revert.append(host in sv.twin.maintenance)
        return real(switch, version, hold_down=hold_down)

    sv.twin.upgrade_switch_os = spy
    rb = RollbackAgent(sv).run("r1", ex, topo)
    assert evacuated_at_revert == [True] and host not in sv.twin.maintenance
    assert [(a["tool"], a["asset"]) for a in rb["actions"]] == [("virt.enter_maintenance", host), ("revert", sw),
                                                                ("virt.exit_maintenance", host)]


def test_rollback_writes_pass_the_policy_guard_and_honour_the_kill_switch(tmp_path, monkeypatch):
    sv = make_services(tmp_path)  # faults on: the canary regresses and needs a rollback
    monkeypatch.delenv("BR_KILL_SWITCH", raising=False)
    real = ExecutorAgent.run_wave

    def run_wave(self, *a, **k):
        out = real(self, *a, **k)
        monkeypatch.setenv("BR_KILL_SWITCH", "on")  # engaged after the canary ran, before its rollback
        return out

    monkeypatch.setattr(ExecutorAgent, "run_wave", run_wave)
    writes = []
    call = sv.bus.call
    sv.bus.call = lambda agent, key, **a: (writes.append(key) if agent == "rollback" and "approval_token" in a else None) or call(agent, key, **a)
    r, _ = drive(Engine(sv))
    st = r["state"]
    assert writes == []  # not one rollback write while the kill switch is engaged
    assert st["status"] == "halted" and st["halt_reason"].startswith("rollback blocked: kill switch engaged")
    assert st["rollback"]["reverted"] == [] and "lesson" not in st
    changes = st["executions"][0]["firmware_changes"]
    steps = st["report"]["manual_steps"]
    assert len(steps) == len(changes) and all(f"revert {c['component']} {c['to']} -> {c['from']}" in " ".join(steps) for c in changes)
    assert "rollback_blocked" in [e["event"] for e in sv.ledger.entries(r["run_id"])]


def test_record_incident_is_a_token_gated_write_that_never_overwrites_another_run(tmp_path):
    sv = make_services(tmp_path)
    assert "knowledge.record_incident" in sv.bus.describe()["write_tools"]
    r, _ = drive(Engine(sv))
    lesson = r["state"]["lesson"]
    assert [i["id"] for i in sv.kb.learned] == [lesson["id"]]  # the reporter recorded it with a token after the rollback
    poisoned = {**lesson, "kind": "note"}  # would drop the DEFERRED protection for the affected hosts
    with pytest.raises(ToolCallError):
        sv.bus.call("rogue", "knowledge.record_incident", incident=poisoned, run_id=r["run_id"], approval_token="")
    tok = sv.authority.token(r["run_id"], lesson["id"], "knowledge.record_incident")
    with pytest.raises(ToolCallError):  # the run has ended: its grant is gone
        sv.bus.call("rogue", "knowledge.record_incident", incident=poisoned, run_id=r["run_id"], approval_token=tok)
    sv.authority.grant("other-run", [lesson["id"]], ["knowledge.record_incident"])
    tok = sv.authority.token("other-run", lesson["id"], "knowledge.record_incident")
    with pytest.raises(ToolCallError) as exc:
        sv.bus.call("rogue", "knowledge.record_incident", incident=poisoned, run_id="other-run", approval_token=tok)
    assert "cannot be overwritten" in str(exc.value)
    assert sv.kb.learned[0]["kind"] == lesson["kind"]


def test_a_host_already_in_maintenance_is_left_in_maintenance(tmp_path):
    sv = make_services(tmp_path)  # faults on: the canary is executed and then rolled back
    sv.twin.enter_maintenance("blr-esx-21")  # a repair in progress, set outside BlastRadius
    r, _ = drive(Engine(sv))
    st = r["state"]
    w1 = st["executions"][0]
    assert "blr-esx-21" in w1["assets"] and w1["already_in_maintenance"] == ["blr-esx-21"]
    assert ("virt.exit_maintenance", "blr-esx-21") not in [(a["tool"], a["asset"]) for a in w1["actions"]]
    assert st["status"] == "rolled_back"
    assert ("virt.exit_maintenance", "blr-esx-21") not in [(a["tool"], a["asset"]) for a in st["rollback"]["actions"]]
    assert sv.twin.maintenance == {"blr-esx-21"}  # every other canary host was returned to service
