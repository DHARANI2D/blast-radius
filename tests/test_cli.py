from blastradius import cli


def _parsed(monkeypatch, argv, cmd):
    seen = {}
    monkeypatch.setattr(cli, cmd, lambda args: seen.setdefault("args", args) and 0)
    cli.main(argv)
    return seen["args"]


def test_redteam_forwards_the_extractor(monkeypatch):
    import blastradius.redteam as rt

    got = {}
    monkeypatch.setattr(rt, "main", lambda argv: got.setdefault("argv", argv) and 0)
    cli.main(["redteam", "--extractor", "configured", "--no-paraphrases"])
    assert got["argv"][got["argv"].index("--extractor") + 1] == "configured"


def test_env_sets_demo_and_a2a_defaults_and_a_flag_wins(monkeypatch):
    monkeypatch.setenv("BR_FAULTS", "off")
    monkeypatch.setenv("BR_TOOL_TRANSPORT", "inproc")
    a = _parsed(monkeypatch, ["demo"], "cmd_demo")
    assert (a.faults, a.transport) == ("off", "inproc")
    assert _parsed(monkeypatch, ["a2a-serve"], "cmd_a2a_serve").transport == "inproc"
    a = _parsed(monkeypatch, ["demo", "--faults", "subtle", "--transport", "mcp"], "cmd_demo")
    assert (a.faults, a.transport) == ("subtle", "mcp")
    monkeypatch.delenv("BR_FAULTS")
    monkeypatch.delenv("BR_TOOL_TRANSPORT")
    a = _parsed(monkeypatch, ["demo"], "cmd_demo")
    assert (a.faults, a.transport) == ("on", "mcp")


def test_optimised_order_line_only_when_the_risk_ranked_canary_misses(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BR_RUNTIME_DIR", str(tmp_path / "rt"))
    monkeypatch.delenv("BR_FAULTS", raising=False)
    line = "With the optimiser's risk-aware ordering alone, a missed canary"
    # subtle: the risk-ranked canary contains blr-esx-21 and catches it in wave 1, so nothing was missed
    cli.main(["demo", "--faults", "subtle", "--auto-approve", "--reset", "--transport", "inproc"])
    out = capsys.readouterr().out
    assert "Avoided $0" in out and line not in out
    cli.main(["demo", "--faults", "on", "--auto-approve", "--reset", "--transport", "inproc"])
    assert line in capsys.readouterr().out
