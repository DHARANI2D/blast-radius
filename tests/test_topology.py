from blastradius.constraints import impact_kwargs


def test_graph_spans_all_domains(topo):
    kinds = topo.summary()["by_kind"]
    assert kinds["server"] == 40 and kinds["switch"] == 6 and kinds["array"] == 1
    assert kinds["cluster"] == 2 and kinds["vm"] > 400 and kinds["service"] >= 5


def test_detects_single_homed_host_from_lldp(topo):
    sh = topo.single_homed()
    assert [s["server"] for s in sh] == ["blr-esx-07"]
    assert sh[0]["up_links"] == ["tor-r1-a"]
    assert sh[0]["dead_ports"] == ["tor-r1-b 1/1/7"]


def test_both_r1_tors_down_cuts_storage_for_other_cluster(topo, sv):
    imp = topo.simulate(["tor-r1-a", "tor-r1-b"], [], **impact_kwargs(sv.policy))
    assert imp["arrays_unreachable"] == ["alletra-mp-blr-01"]
    # Rack R2 hosts keep their network but lose their datastores.
    assert "blr-esx-30" in imp["storage_lost_servers"]
    assert {"payments-db-01", "payments-db-02"} <= set(imp["critical_vms"])
    assert imp["brs"] > 99


def test_single_switch_failure_exposes_hidden_dependency(topo, sv):
    imp = topo.simulate(["tor-r1-a"], [], **impact_kwargs(sv.policy))
    assert imp["isolated_servers"] == ["blr-esx-07"]
    assert imp["critical_vms"] == ["payments-db-01"]
    assert topo.simulate(["tor-r1-b"], [], **impact_kwargs(sv.policy))["impacted_vms"] == []


def test_evacuating_the_single_homed_host_removes_the_impact(topo, sv):
    imp = topo.simulate(["tor-r1-a"], ["blr-esx-07"], **impact_kwargs(sv.policy))
    assert imp["impacted_vms"] == []
    assert imp["migrated_vms"] > 0


def test_capacity_limit(topo, sv):
    cap = topo.cluster_capacity("PROD-BLR-07")
    assert 5 <= cap["max_hosts_down"] <= 9
    hosts = [f"blr-esx-{i:02d}" for i in range(1, 1 + cap["max_hosts_down"] + 2)]
    imp = topo.simulate([], hosts, **impact_kwargs(sv.policy))
    assert imp["capacity_shortfall_gb"]
