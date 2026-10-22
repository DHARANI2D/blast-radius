import pytest

from conftest import make_services

from blastradius.mcp_layer import ToolCallError


@pytest.fixture
def mcp_sv(tmp_path):
    return make_services(tmp_path, transport="mcp")


def test_servers_expose_tools_over_mcp(mcp_sv):
    tools = mcp_sv.bus.list_mcp_tools("compute")
    assert {"list_servers", "get_server", "apply_firmware"} <= set(tools)
    assert set(mcp_sv.bus.describe()["servers"]) == {"compute", "network", "virt", "telemetry", "knowledge"}


def test_mcp_results_match_inproc(mcp_sv, sv):
    a, _ = mcp_sv.bus.call("t", "network.get_lldp_neighbors", switch="tor-r1-b")
    b, _ = sv.bus.call("t", "network.get_lldp_neighbors", switch="tor-r1-b")
    assert a == b
    s, _ = mcp_sv.bus.call("t", "compute.get_server", name="blr-esx-07")
    assert s["name"] == "blr-esx-07"


def test_mcp_write_denial_message_survives_transport(mcp_sv):
    with pytest.raises(ToolCallError) as exc:
        mcp_sv.bus.call("rogue", "virt.enter_maintenance", host="blr-esx-03", run_id="x", approval_token="nope")
    assert "not part of an approved wave" in str(exc.value)


def test_closing_the_bus_stops_its_event_loop_thread(mcp_sv):
    thread = mcp_sv.bus._loop.thread
    assert thread.is_alive()
    mcp_sv.bus.close()
    assert not thread.is_alive()
