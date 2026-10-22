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
