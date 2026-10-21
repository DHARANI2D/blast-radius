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
