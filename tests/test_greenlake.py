"""GreenLake MCP adapter against an in-process stand-in for the real gl-mcp devices server.

The fake mirrors greenlake-devices-mcp 1.1.2 (github.com/HewlettPackard/gl-mcp,
src/devices/greenlake_devices_mcp/tools/implementations/getdevicesv1.py): tool name
``getdevicesv1``, parameters filter / filter_tags / sort / select / limit (default 2000) /
offset, and a list holding one envelope {"success": true, "result": {"items", "count",
"offset", "total"}}; failures come back as {"success": false, "httpStatusCode", ...}.
Item fields follow models/base.py DeviceDetail. No live GreenLake call is made here.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any

import pytest
from mcp.server.mcpserver import Context, MCPServer
from pydantic import Field

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blastradius import greenlake  # noqa: E402
from blastradius.config import Settings  # noqa: E402

SELECTABLE = {"application", "archived", "assignedState", "createdAt", "dedicatedPlatformWorkspace", "deviceName",
              "deviceType", "id", "location", "macAddress", "model", "partNumber", "region", "secondaryName",
              "serialNumber", "subscription", "tags", "tenantWorkspaceId", "type", "updatedAt", "warranty"}
GL_ENV = ("GREENLAKE_CLIENT_ID", "GREENLAKE_CLIENT_SECRET", "GREENLAKE_WORKSPACE_ID", "GREENLAKE_API_BASE_URL",
          "MCP_TOOL_MODE", "BR_GL_MCP_URL", "BR_GL_MCP_CMD", "BR_GL_MCP_CWD", "BR_GL_MCP_DEVICES_TOOL",
          "BR_GL_MCP_FILTER", "BR_GL_MCP_PAGE_SIZE", "BR_GL_MCP_MAX_PAGES", "BR_GL_MCP_TIMEOUT_S")


def twin_servers() -> list[dict]:
    return json.loads(Path(Settings().twin_file).read_text())["compute"]["servers"]


def _device(serial: str, model: str, part: str, dtype: str = "COMPUTE", subs: int = 1, archived: bool = False) -> dict:
    return {
        "id": f"gl-{serial.lower()}", "type": "devices/device", "serialNumber": serial, "model": model,
        "partNumber": part, "deviceType": dtype, "deviceName": None, "assignedState": "ASSIGNED_TO_SERVICE",
        "archived": archived, "macAddress": "00:00:00:00:00:00", "region": "eu-central",
        "subscription": [{"id": f"sub-{serial.lower()}-{i}", "resourceUri": f"/subscriptions/v1/subscriptions/sub-{i}"}
                         for i in range(subs)],
        "warranty": {"country": "IN", "currentSupportLevel": {"serviceLevel": "Foundation Care NBD", "endDate": 1830297600}},
        "tags": {}, "createdAt": "2025-01-01T00:00:00Z", "updatedAt": "2026-09-01T00:00:00Z",
    }


def inventory() -> list[dict]:
    """Six twin hosts (one with drifted model, one unsubscribed, one archived) plus non-twin devices."""
    servers = twin_servers()
    devs = []
    for i, s in enumerate(servers[:6]):
        model = s["model"].replace("HPE ", "")
        if i == 1:
            model = "ProLiant DL360 Gen11"  # inventory says DL360, twin says DL380
        devs.append(_device(s["serialNumber"], model, "P52534-B21", subs=0 if i == 2 else 1, archived=i == 3))
    devs += [_device("CN12KXY001", "Aruba CX 8325", "JL624A", "NETWORK"),
             _device("CZ2A0B0001", "HPE Alletra Storage MP", "S1R33A", "STORAGE"),
             _device("MXQ0000999", "ProLiant DL325 Gen11", "P54199-B21")]
    return devs


def _eq_filter(expr: str | None, items: list[dict]) -> list[dict]:
    for prop, value in re.findall(r"(\w+) eq '([^']*)'", expr or ""):
        items = [d for d in items if str(d.get(prop)) == value]
    return items


def fake_devices_server(items: list[dict] | None = None, *, fail: dict | None = None, reject_select: bool = False,
                        dynamic: bool = False, calls: list | None = None):
    """MCPServer whose tools mirror gl-mcp's devices server (static or dynamic tool mode)."""
    items = inventory() if items is None else items
    calls = [] if calls is None else calls
    srv = MCPServer("devices-mcp")

    def respond(filter, filter_tags, sort, select, limit, offset) -> list[dict[str, Any]]:
        calls.append({"filter": filter, "filter_tags": filter_tags, "select": select, "limit": limit, "offset": offset})
        if fail:
            return [fail]
        limit, offset = int(limit if limit is not None else 2000), int(offset or 0)
        if limit < 1:
            return [{"success": False, "error": "validation_error", "message": "'limit' must be an integer"}]
        fields = [f.strip() for f in select.split(",")] if select else None
        if fields and (reject_select or set(fields) - SELECTABLE):
            return [{"success": False, "httpStatusCode": 400, "errorCode": "HPE_GL_ERROR_BAD_REQUEST",
                     "message": "Bad Request: select", "debugId": "dbg-1"}]
        matched = _eq_filter(filter, items)
        page = matched[offset:offset + limit]
        if fields:
            page = [{k: v for k, v in d.items() if k in fields} for d in page]
        return [{"success": True, "result": {"items": page, "count": len(page), "offset": offset, "total": len(matched)}}]

    if dynamic:
        @srv.tool(name="list_endpoints", description="Discover available API endpoints")
        async def list_endpoints(ctx: Context, pattern: str | None = None) -> list[dict[str, Any]]:
            return [{"success": True, "endpoints": [{"endpoint": "GET:/devices/v1/devices", "summary": "getdevicesv1"}]}]

        @srv.tool(name="invoke_dynamic_tool", description="Executes any devices API endpoint dynamically")
        async def invoke_dynamic_tool(ctx: Context, endpoint_identifier: str, parameters: dict[str, Any] | None = None,
                                      validate_schema: bool = True) -> list[dict[str, Any]]:
            p = parameters or {}
            [env] = respond(p.get("filter"), p.get("filter-tags"), p.get("sort"), p.get("select"), p.get("limit"), p.get("offset"))
            if not env["success"]:
                return [env]
            return [{"success": True, "endpoint_identifier": endpoint_identifier,
                     "request": {"url": "/devices/v1/devices", "method": "GET", "query_params": p}, "response": env["result"]}]
        return srv

    @srv.tool(name="getdevicesv1", description="With this API, you can: Retrieve a list of devices managed in a workspace.")
    async def getdevicesv1(
        ctx: Context,
        filter: Annotated[str | None, Field(description="OData filter, e.g. deviceType eq 'COMPUTE'")] = None,
        filter_tags: Annotated[str | None, Field(description="OData filter on tags")] = None,
        sort: Annotated[str | None, Field(description="e.g. serialNumber,macAddress desc")] = None,
        select: Annotated[str | None, Field(description="comma separated properties")] = None,
        limit: Annotated[int | str | None, Field(description="default 2000", default=2000)] = 2000,
        offset: Annotated[int | str | None, Field(description="zero-based offset")] = None,
    ) -> list[dict[str, Any]]:
        return respond(filter, filter_tags, sort, select, limit, offset)

    @srv.tool(name="getdevicebyidv1", description="Get details on a specific device by passing its resourceId.")
    async def getdevicebyidv1(ctx: Context, id: str) -> list[dict[str, Any]]:
        hit = [d for d in items if d["id"] == id]
        return [{"success": True, "result": hit[0]}] if hit else [{"success": False, "httpStatusCode": 404, "message": "Not Found"}]

    return srv


@pytest.fixture
def clean_env(monkeypatch):
    for k in GL_ENV:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def cfg(**kw) -> SimpleNamespace:
    base = dict(gl_mcp_url="", gl_mcp_cmd="", gl_mcp_devices_tool="", gl_mcp_page_size=4, gl_mcp_timeout_s=20.0)
    return SimpleNamespace(**{**base, **kw})


def test_serial_matching_and_device_facts(clean_env):
    servers = twin_servers()
    out = greenlake.enrich_from_greenlake(cfg(), servers, target=fake_devices_server())
    assert out["ok"] and out["tool"] == "getdevicesv1" and out["tool_mode"] == "static"
    assert out["devices_seen"] == 9 and out["total_reported"] == 9
    assert out["matched_twin_servers"] == 6 and out["unmatched_twin_servers"] == len(servers) - 6
    names = [m["twin"] for m in out["matches"]]
    assert names == [s["name"] for s in servers[:6]]
    first = out["matches"][0]
    assert first["serial"] == servers[0]["serialNumber"] and first["model_agrees"] is True
    assert first["subscriptions"] == [f"sub-{servers[0]['serialNumber'].lower()}-0"]
    assert first["support_level"] == "Foundation Care NBD" and first["part_number"] == "P52534-B21"
    assert out["flags"] == {"model_mismatch": [servers[1]["name"]], "no_subscription": [servers[2]["name"]],
                            "archived": [servers[3]["name"]]}


def test_pagination_follows_offset_and_total(clean_env):
    calls: list = []
    out = greenlake.list_devices(cfg(gl_mcp_page_size=4), target=fake_devices_server(calls=calls))
    assert out["ok"] and out["pages"] == 3 and out["devices_seen"] == 9 and not out["truncated"]
    assert [(c["offset"], c["limit"]) for c in calls] == [(0, 4), (4, 4), (8, 4)]
    assert set(calls[0]["select"].split(",")) <= SELECTABLE and "serialNumber" in calls[0]["select"]
    capped = greenlake.list_devices(cfg(gl_mcp_page_size=4, gl_mcp_max_pages=2), target=fake_devices_server())
    assert capped["ok"] and capped["pages"] == 2 and capped["devices_seen"] == 8 and capped["truncated"]


def test_filter_and_dynamic_tool_mode(clean_env):
    calls: list = []
    out = greenlake.list_devices(cfg(gl_mcp_filter="deviceType eq 'COMPUTE'"), target=fake_devices_server(calls=calls))
    assert out["devices_seen"] == 7 and calls[0]["filter"] == "deviceType eq 'COMPUTE'"
    dyn = greenlake.enrich_from_greenlake(cfg(), twin_servers(), target=fake_devices_server(dynamic=True))
    assert dyn["ok"] and dyn["tool_mode"] == "dynamic" and dyn["tool"] == "invoke_dynamic_tool"
    assert dyn["matched_twin_servers"] == 6 and dyn["pages"] == 3


def test_serial_normalisation_and_synthetic_note():
    devices = [greenlake._device_facts({"serialNumber": " syn1r001 ", "model": "ProLiant DL380 Gen11"})]
    res = greenlake.match_devices([{"name": "blr-esx-01", "serialNumber": "SYN1R001", "model": "HPE ProLiant DL380 Gen11"}], devices)
    assert res["matched_twin_servers"] == 1 and res["matches"][0]["model_agrees"] is True
    other = fake_devices_server(items=[_device("MXQ0000999", "ProLiant DL325 Gen11", "P54199-B21")])
    out = greenlake.enrich_from_greenlake(cfg(), twin_servers(), target=other)
    assert out["ok"] and out["matched_twin_servers"] == 0 and "synthetic serials" in out["note"]


def test_failures_are_reported_not_raised(clean_env):
    assert greenlake.enrich_from_greenlake(cfg(), twin_servers()) == {
        "enabled": False, "note": "gl-mcp not configured (set BR_GL_MCP_CMD or BR_GL_MCP_URL)"}
    denied = {"success": False, "httpStatusCode": 401, "errorCode": "HPE_GL_ERROR_UNAUTHORIZED", "message": "Unauthorized"}
    out = greenlake.enrich_from_greenlake(cfg(), twin_servers(), target=fake_devices_server(fail=denied))
    assert out["enabled"] and out["ok"] is False and "401" in out["error"] and "Unauthorized" in out["error"]
    out = greenlake.enrich_from_greenlake(cfg(gl_mcp_devices_tool="list_devices"), twin_servers(), target=fake_devices_server())
    assert out["ok"] is False and "getdevicesv1" in out["error"]
    out = greenlake.enrich_from_greenlake(cfg(gl_mcp_cmd="/nonexistent/greenlake-devices-mcp"), twin_servers())
    assert out["ok"] is False and out["transport"] == "stdio" and out["error"]
    retried = greenlake.list_devices(cfg(), target=fake_devices_server(reject_select=True))
    assert retried["ok"] and retried["devices_seen"] == 9 and retried["notes"]


def test_topology_agent_survives_broken_greenlake(tmp_path, clean_env):
    from conftest import make_services

    from blastradius.agents import TopologyAgent

    sv = make_services(tmp_path)
    sv.settings.gl_mcp_cmd = "/nonexistent/greenlake-devices-mcp"
    topo, summary = TopologyAgent(sv).run()
    assert summary["greenlake"]["ok"] is False and summary["greenlake"]["transport"] == "stdio"
    assert summary["by_kind"]["server"] == 40 and summary["by_kind"]["vm"] == 504


def test_stdio_launch_forwards_greenlake_env(clean_env, tmp_path):
    """Real stdio subprocess: the fake answers 401 unless GREENLAKE_* reached it, like the real server."""
    clean_env.setenv("GREENLAKE_CLIENT_ID", "cid")
    clean_env.setenv("GREENLAKE_CLIENT_SECRET", "s3cret")
    clean_env.setenv("GREENLAKE_WORKSPACE_ID", "ws-1")
    cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} serve-fake"
    out = greenlake.enrich_from_greenlake(cfg(gl_mcp_cmd=cmd, gl_mcp_page_size=2000, gl_mcp_timeout_s=60.0), twin_servers())
    assert out["ok"], out
    assert out["transport"] == "stdio" and out["matched_twin_servers"] == 6 and out["pages"] == 1


def test_doctor_reports_readiness_without_leaking_secrets(clean_env):
    rep = greenlake.doctor(Settings())
    assert rep["configured"] is False and rep["ready"] is False and rep["network_calls"] == 0
    assert rep["command"] == ["python", "-m", "greenlake_devices_mcp"] and rep["tool"] == "getdevicesv1"
    assert any("BR_GL_MCP_CMD" in p for p in rep["problems"])
    clean_env.setenv("BR_GL_MCP_CMD", f"{sys.executable} -m json.tool")
    clean_env.setenv("GREENLAKE_CLIENT_ID", "client-abc")
    clean_env.setenv("GREENLAKE_CLIENT_SECRET", "very-secret-value")
    rep = greenlake.doctor(Settings())
    assert rep["transport"] == "stdio" and rep["launcher"] and rep["env"]["GREENLAKE_CLIENT_SECRET"] == "set"
    assert rep["env"]["GREENLAKE_WORKSPACE_ID"] == "missing" and not rep["ready"]
    assert "GREENLAKE_CLIENT_SECRET" in rep["forwarded_env"]
    assert "very-secret-value" not in json.dumps(rep) and "client-abc" not in json.dumps(rep)
    clean_env.setenv("GREENLAKE_WORKSPACE_ID", "ws-1")
    assert greenlake.doctor(Settings())["ready"] is True
    clean_env.setenv("BR_GL_MCP_URL", "http://127.0.0.1:9/mcp")
    rep = greenlake.doctor(Settings())
    assert rep["transport"] == "streamable-http" and "stdio only" in rep["note"] and rep["ready"]


if __name__ == "__main__" and sys.argv[1:] == ["serve-fake"]:
    import os

    if all(os.environ.get(k) for k in greenlake.REQUIRED_ENV):
        server = fake_devices_server()
    else:
        server = fake_devices_server(fail={"success": False, "httpStatusCode": 401, "message": "missing GREENLAKE_* env"})
    server.run("stdio")


def test_cli_devices_says_why_nothing_was_listed(monkeypatch, capsys):
    from blastradius.cli import main

    for k in ("BR_GL_MCP_URL", "BR_GL_MCP_CMD"):
        monkeypatch.delenv(k, raising=False)
    assert main(["greenlake", "devices"]) == 1
    assert "gl-mcp not configured" in capsys.readouterr().out
