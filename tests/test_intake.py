from conftest import INTENT

from blastradius.agents import IntakeAgent


def test_resolves_tor_pair_and_expands_clusters(sv):
    out = IntakeAgent(sv).run("Upgrade iLO and ROM on PROD-BLR-07 and the ToR switch pair on Sunday 9pm for 4 hours")
    cr, t = out["change_request"], out["targets"]
    assert t["switches"] == ["tor-r1-a", "tor-r1-b"]
    assert len(t["servers"]) == 20 and all(sv.twin.servers[s]["cluster"] == "PROD-BLR-07" for s in t["servers"])
    assert cr["components"] == ["iLO 6", "System ROM", "Switch OS"]
    assert cr["window"] == {"day": "Sunday", "start": "21:00", "duration_minutes": 240}


def test_explicit_servers_only(sv):
    out = IntakeAgent(sv).run("Update System ROM on blr-esx-03 and blr-esx-21 tonight")
    assert out["targets"] == {"servers": ["blr-esx-03", "blr-esx-21"], "switches": []}
    assert out["change_request"]["components"] == ["System ROM"]


def _model_says(sv, monkeypatch, **fields):
    """A live intake model whose answer differs from the offline stand-in in the given fields."""
    orig = sv.llm.complete_json

    def cj(role, *a, **k):
        out = orig(role, *a, **k)
        if role == "intake":
            for f, v in fields.items():
                setattr(out, f, v(getattr(out, f)) if callable(v) else v)
        return out

    monkeypatch.setattr(sv.llm, "complete_json", cj)


def test_names_are_matched_ignoring_case_and_dropped_names_are_warnings(sv, monkeypatch):
    _model_says(sv, monkeypatch, target_clusters=lambda cs: [c.lower() for c in cs] + ["PROD-BLR-99"],
                target_servers=["BLR-ESX-03"], summary="anything the model wrote")
    out = IntakeAgent(sv).run(INTENT)
    cr, t = out["change_request"], out["targets"]
    assert cr["target_clusters"] == ["PROD-BLR-07", "PROD-BLR-08"] and cr["target_servers"] == ["blr-esx-03"]
    assert len(t["servers"]) == 40 and t["switches"] == ["tor-r1-a", "tor-r1-b"]
    assert out["warnings"][0] == "Dropped unknown clusters: ['PROD-BLR-99']" and out["warnings"][0] in cr["notes"]
    # the summary is rebuilt from the targets that will actually change
    assert cr["summary"].endswith("on PROD-BLR-07, PROD-BLR-08, blr-esx-03, tor-r1-a, tor-r1-b")


def test_ambiguous_tor_pair_is_resolved_deterministically_with_an_assumption_note(sv, monkeypatch):
    out = IntakeAgent(sv).run(INTENT)
    assert out["targets"]["switches"] == ["tor-r1-a", "tor-r1-b"]
    note = out["warnings"][0]
    assert note.startswith("Assumption") and "Chose tor-r1-a/tor-r1-b, the pair of PROD-BLR-07" in note
    assert "not included: tor-r2-a/tor-r2-b (PROD-BLR-08)" in note and note in out["change_request"]["notes"]
    # a live model that leaves the switches out (or takes every pair) gets the same answer
    for model_switches in ([], ["tor-r1-a", "tor-r1-b", "tor-r2-a", "tor-r2-b"]):
        _model_says(sv, monkeypatch, target_switches=model_switches)
        assert IntakeAgent(sv).run(INTENT)["targets"]["switches"] == ["tor-r1-a", "tor-r1-b"]
        monkeypatch.undo()
    # naming the order the other way round picks the other pair; asking for every pair takes both
    flipped = IntakeAgent(sv).run(INTENT.replace("PROD-BLR-07 and PROD-BLR-08", "PROD-BLR-08 and PROD-BLR-07"))
    assert flipped["targets"]["switches"] == ["tor-r2-a", "tor-r2-b"]
    both = IntakeAgent(sv).run(INTENT.replace("the ToR switch pair", "both ToR pairs"))
    assert both["targets"]["switches"] == ["tor-r1-a", "tor-r1-b", "tor-r2-a", "tor-r2-b"] and not both["warnings"]
