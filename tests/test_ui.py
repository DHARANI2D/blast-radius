"""Control Tower (ui/app.py) driven headless with Streamlit's AppTest."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from conftest import INTENT  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "ui" / "app.py")
sys.path.insert(0, str(Path(APP).parent))


@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("BR_RUNTIME_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("BR_TOOL_TRANSPORT", "inproc")
    monkeypatch.setenv("BR_FAULTS", "on")
    monkeypatch.setenv("BR_LLM_MODE", "offline")
    monkeypatch.setenv("BR_KILL_SWITCH", "off")

    def make():
        at = AppTest.from_file(APP, default_timeout=180)
        at.run()
        return at

    return make


def click(at, label):
    next(b for b in at.button if b.label == label).click().run()
    assert not at.exception, [e.message for e in at.exception]
    return at


def analyse(at, intent=None):
    if intent:
        at.text_area[0].set_value(intent)
    return click(at, "Analyse change")


def header(at):
    return {m.label: m.value for m in at.metric[:5]}


def widget(items, label):
    return next(w for w in items if w.label == label)


def test_defaults_follow_env_and_controls_lock_while_a_run_is_in_flight(ui, monkeypatch):
    monkeypatch.setenv("BR_FAULTS", "subtle")
    at = ui()
    transport, scenario = widget(at.sidebar.radio, "Tool transport"), widget(at.sidebar.selectbox, "Fault scenario")
    assert (transport.value, scenario.value) == ("inproc", "subtle")
    assert not transport.disabled and not scenario.disabled
    analyse(at)  # waiting at the canary gate: switching would re-seed the twin and drop the run
    transport, scenario = widget(at.sidebar.radio, "Tool transport"), widget(at.sidebar.selectbox, "Fault scenario")
    assert transport.disabled and scenario.disabled
    assert any("Locked while a change is in flight" in c.value for c in at.sidebar.caption)


def test_empty_plan_and_runs_without_telemetry_render(ui):
    at = analyse(ui(), "Upgrade System ROM on PROD-BLR-99 this Saturday 10pm")
    # nothing in the inventory matches: the run ends at intake with no plan, gate or writes, and still renders
    assert "plan" not in at.session_state["run"]["state"] and at.session_state["run"]["interrupt"] is None
    assert header(at)["Status"] == "escalated"
    # a wave with no sampled servers and a canary judge with no host to pick
    at = analyse(at, INTENT)
    click(at, "Approve and sign")
    ex = at.session_state["run"]["state"]["executions"][0]
    ex["series"] = {}
    ex["canary_stats"].update(band={}, hosts={})
    at.run()
    assert not at.exception, [e.message for e in at.exception]
    # with no samples the live-signals chart is skipped (or captioned), never a crash
    assert not any(m.value.startswith("##### Live golden signals") for m in at.markdown) or any("No server telemetry" in c.value for c in at.caption)


def test_header_status_trust_and_cost_labels(ui):
    at = analyse(ui(), "hello")
    h = header(at)
    assert h["Status"] == "escalated"
    assert "Trust Score" not in h and h["Trust Score (last rejected attempt)"] == "-"  # no plan was ever proposed
    assert h["Est. cost avoided (illustrative)"] == "-"  # no replay ran
    at.session_state["run"]["state"]["avoided_cost_usd"] = 0.0
    at.run()
    assert header(at)["Est. cost avoided (illustrative)"] == "$0"


def test_verifier_label_animation_overlay_and_stale_injection(ui, monkeypatch):
    import time

    at = analyse(ui())
    assert widget(at.radio, "Overlay").value == "Attempt 1 · wave 1 impact"  # attempt 1 was rejected
    # the Verifier is never called an independent model when it is not one
    labels = [m.value for m in at.markdown if m.value.startswith("**Verifier**")]
    assert labels and all("independent agent" in v and "offline stand-in" in v for v in labels)
    assert not any("independent model" in m.value for m in at.markdown)
    click(at, "Inject and verify")
    assert at.session_state["inj"]["sentence"]
    # approving animates the live-signal chart once, in a handful of frames
    sleeps, real_sleep = [], time.sleep
    monkeypatch.setattr(time, "sleep", lambda s: (sleeps.append(s) if s >= 0.01 else None, real_sleep(s))[1])  # skip AppTest's polls
    click(at, "Approve and sign")
    assert header(at)["Status"] == "rolled back"
    assert 0 < len(sleeps) <= 20 and sum(sleeps) < 1
    sleeps.clear()
    at.run()
    assert not sleeps
    # New run: the injection belonged to the previous plan
    click(at, "New run")
    assert "inj" not in at.session_state
    at = analyse(at)
    assert "inj" not in at.session_state and not any("Injected (red-team test" in m.value for m in at.markdown)
    # the learning re-run passes attempt 1: open on the plan, and never a red "0 VMs lose service incl. tier-0" banner
    assert at.session_state["run"]["state"]["attempts"][0]["passed"]
    overlay = widget(at.radio, "Overlay")
    assert overlay.value == "Approved plan · waves"
    overlay.set_value("Attempt 1 · wave 1 impact").run()
    banner = next(m.value for m in at.markdown if "<b>Wave 1" in m.value)
    assert "br-banner-green" in banner and "no VMs lose service" in banner and "tier-0" not in banner


def test_redteam_panel_names_the_extractor(ui, monkeypatch):
    import blastradius.redteam as rt

    calls = []
    fake = {"extractor": "offline-verifier", "headline": {
        "typed_caught": 9, "typed_false": 10, "typed_catch_ci": [0.6, 0.98], "typed_dangerous_misses": 0, "typed_false_blocks": 0,
        "typed_true": 5, "plan_mutations_detected": 4, "plan_mutations": 4, "extraction_canonical": 1.0, "extraction_dev": 0.9,
        "extraction_held_out": 0.8, "injections_caught": 8, "injections": 8}}
    monkeypatch.setattr(rt, "run_benchmark", lambda sv, seed=7, extractor="offline": calls.append(extractor) or fake)
    monkeypatch.setattr(rt, "format_markdown", lambda res: "report")
    at = analyse(ui())
    click(at, "Run benchmark (about 5 s)")
    assert calls == ["offline"]
    assert any("Measured with the offline extractor `offline-verifier`" in c.value for c in at.caption)


def test_risk_heat_uses_the_policy_high_risk_threshold(topo):
    from graph_view import build_dot

    risk = {"tor-r1-a": {"score": 75}}
    assert "#dc2626" in _node_line(build_dot(topo, "risk", risk=risk, high_risk=70), "tor-r1-a")
    assert "#dc2626" not in _node_line(build_dot(topo, "risk", risk=risk, high_risk=80), "tor-r1-a")


def _node_line(dot, name):
    return next(line for line in dot.splitlines() if line.strip().startswith(f'"{name}"') and "fillcolor" in line)
