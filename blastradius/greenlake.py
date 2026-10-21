"""Optional read-only enrichment from the official HPE GreenLake MCP server.

HPE publishes GreenLake MCP servers (github.com/HewlettPackard/gl-mcp) that give
assistants read-only access to GreenLake APIs. When ``BR_GL_MCP_URL`` (Streamable
HTTP) or ``BR_GL_MCP_CMD`` (stdio command) is set, the Topology agent lists the
workspace's devices and matches them to twin servers by serial number.

This adapter has not been run against a live gl-mcp deployment. Tool names are
discovered at runtime; set ``BR_GL_MCP_DEVICES_TOOL`` if discovery picks the
wrong one. Any failure is reported in the topology summary, never raised.
"""

from __future__ import annotations

import asyncio
import json
import shlex

from .config import Settings


def enrich_from_greenlake(settings: Settings, servers: list[dict]) -> dict:
    if not (settings.gl_mcp_url or settings.gl_mcp_cmd):
        return {"enabled": False, "note": "gl-mcp not configured (set BR_GL_MCP_URL or BR_GL_MCP_CMD)"}
    try:
        return asyncio.run(_enrich(settings, servers))
    except Exception as exc:  # noqa: BLE001 - optional integration must never break discovery
        return {"enabled": True, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def _enrich(settings: Settings, servers: list[dict]) -> dict:
    from mcp import Client

    if settings.gl_mcp_url:
        target = settings.gl_mcp_url
    else:
        from mcp import StdioServerParameters

        argv = shlex.split(settings.gl_mcp_cmd)
        target = StdioServerParameters(command=argv[0], args=argv[1:])
    async with Client(target, read_timeout_seconds=30) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
        tool = settings.gl_mcp_devices_tool or next((t for t in tools if "device" in t.lower() and ("list" in t.lower() or "get" in t.lower())), None)
        if not tool:
            return {"enabled": True, "ok": False, "tools": tools, "error": "no device-listing tool found"}
        res = await client.call_tool(tool, {})
        texts = [getattr(c, "text", "") for c in res.content or []]
        devices = []
        for t in texts:
            try:
                parsed = json.loads(t)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                parsed = parsed.get("items") or parsed.get("devices") or [parsed]
            devices.extend(parsed if isinstance(parsed, list) else [])
        serials = {s["serialNumber"] for s in servers}
        matched = [d for d in devices if isinstance(d, dict) and (d.get("serialNumber") or d.get("serial_number")) in serials]
        return {"enabled": True, "ok": True, "tool": tool, "devices_seen": len(devices), "matched_twin_servers": len(matched)}
