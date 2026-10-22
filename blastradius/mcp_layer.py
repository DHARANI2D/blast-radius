"""MCP servers for each domain, and the ToolBus agents use to call them.

With ``transport="mcp"`` (the default) every agent tool call goes through an MCP
client session to the domain's MCP server: JSON-schema validated arguments,
MCP result envelopes, MCP error semantics. ``transport="inproc"`` calls the same
functions directly and exists only to keep unit tests fast.

Each server can also be started on its own over stdio so any MCP client can
inspect it::

    python -m blastradius mcp-serve compute
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from .evidence import EvidenceStore
from .tools import ToolSpec

log = logging.getLogger(__name__)

try:  # MCP Python SDK 2.x
    from mcp import Client as _Client
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError

    MCP_API = 2
except ImportError:  # pragma: no cover - MCP Python SDK 1.x
    try:
        from mcp.server.fastmcp import FastMCP as _Server
        from mcp.server.fastmcp.exceptions import ToolError
        from mcp.shared.memory import create_connected_server_and_client_session

        MCP_API = 1
    except ImportError:
        _Server = None
        ToolError = RuntimeError
        MCP_API = 0

DOMAIN_TITLES = {
    "compute": "BlastRadius Compute MCP (Compute Ops Management shapes)",
    "network": "BlastRadius Network MCP (Aruba Central / Mist shapes)",
    "virt": "BlastRadius Virtualization MCP (Morpheus shapes)",
    "telemetry": "BlastRadius Telemetry MCP (OpsRamp-style golden signals)",
    "knowledge": "BlastRadius Knowledge MCP (release notes, advisories, incidents)",
}


class ToolCallError(RuntimeError):
    def __init__(self, message: str, evidence_id: str):
        super().__init__(message)
        self.evidence_id = evidence_id


def _as_tool_error(fn):
    """Surface domain errors to the MCP client as ToolError (message preserved)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001 - every domain error becomes a tool error
            raise ToolError(str(exc)) from exc

    return wrapper


def build_servers(registry: dict[str, ToolSpec]) -> dict[str, Any]:
    if MCP_API == 0:
        raise RuntimeError("the 'mcp' package is not installed; use BR_TOOL_TRANSPORT=inproc")
    servers: dict[str, Any] = {}
    for spec in registry.values():
        srv = servers.get(spec.domain)
        if srv is None:
            srv = servers[spec.domain] = _Server(spec.domain, instructions=DOMAIN_TITLES.get(spec.domain, ""))
        desc = (spec.description or "").strip()
        srv.add_tool(_as_tool_error(spec.fn), name=spec.name, description=desc)
    return servers


@asynccontextmanager
async def _connect(server):
    if MCP_API == 2:
        async with _Client(server, raise_exceptions=False) as client:
            yield client
    else:  # pragma: no cover
        async with create_connected_server_and_client_session(server._mcp_server) as session:
            yield session


def _decode(result) -> Any:
    is_error = getattr(result, "is_error", None)
    if is_error is None:
        is_error = getattr(result, "isError", False)
    texts = [getattr(c, "text", "") for c in (result.content or [])]
    if is_error:
        raise RuntimeError(" ".join(texts) or "tool error")
    structured = getattr(result, "structured_content", None)
    if structured is None:
        structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict) and set(structured) == {"result"}:
        return structured["result"]
    if structured is not None:
        return structured
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except json.JSONDecodeError:
            return texts[0]
    return [json.loads(t) for t in texts]


class _LoopThread:
    """A private event loop on a daemon thread, so sync agent code can await MCP calls."""

    def __init__(self):
        import threading

        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="blastradius-mcp", daemon=True)
        self.thread.start()

    def run(self, coro, timeout: float = 60):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)


class ToolBus:
    def __init__(self, registry: dict[str, ToolSpec], evidence: EvidenceStore, transport: str = "mcp"):
        self.registry = registry
        self.evidence = evidence
        self.transport = transport if MCP_API else "inproc"
        self.servers = build_servers(registry) if self.transport == "mcp" else {}
        self._loop = _LoopThread() if self.transport == "mcp" else None
        self.calls = 0

    def describe(self) -> dict:
        return {
            "transport": self.transport,
            "mcp_sdk_api": MCP_API,
            "servers": sorted({s.domain for s in self.registry.values()}),
            "tools": sorted(self.registry),
            "write_tools": sorted(k for k, s in self.registry.items() if s.write),
        }

    def close(self) -> None:
        """Stop the event-loop thread (a UI that swaps transports would otherwise leak one per switch)."""
        if self._loop is not None:
            self._loop.stop()
            self._loop = None

    def list_mcp_tools(self, domain: str) -> list[str]:
        if self.transport != "mcp":
            return sorted(s.name for s in self.registry.values() if s.domain == domain)

        async def go():
            async with _connect(self.servers[domain]) as c:
                res = await c.list_tools()
                return sorted(t.name for t in res.tools)

        return self._loop.run(go())

    def _dispatch(self, spec: ToolSpec, args: dict) -> Any:
        if self.transport != "mcp":
            return spec.fn(**args)

        async def go():
            async with _connect(self.servers[spec.domain]) as c:
                return await c.call_tool(spec.name, args)

        # Decode outside the client context so a tool error surfaces as itself,
        # not wrapped in the transport's task-group exception.
        return _decode(self._loop.run(go()))

    def call(self, agent: str, key: str, **args) -> tuple[Any, str]:
        """Call a tool and record the result as evidence. Returns ``(result, evidence_id)``."""
        spec = self.registry.get(key)
        if spec is None:
            raise KeyError(f"unknown tool {key}")
        shown_args = {k: ("***" if k == "approval_token" else v) for k, v in args.items()}
        self.calls += 1
        try:
            result = self._dispatch(spec, args)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).replace(f"Error executing tool {spec.name}: ", "")
            eid = self.evidence.add(agent, key, shown_args, {"error": msg}, ok=False)
            raise ToolCallError(msg, eid) from exc
        eid = self.evidence.add(agent, key, shown_args, result)
        return result, eid


def serve_stdio(domain: str) -> None:  # pragma: no cover - interactive entry point
    from .services import Services

    services = Services.create(tool_transport="mcp")
    server = services.bus.servers[domain]
    server.run("stdio")
