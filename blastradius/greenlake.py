"""Optional read-only enrichment from HPE's official GreenLake devices MCP server.

HPE publishes read-only GreenLake MCP servers in github.com/HewlettPackard/gl-mcp
(Apache-2.0). The one that lists inventory is the devices server: PyPI package
``greenlake-devices-mcp``, started with ``python -m greenlake_devices_mcp`` (or the
``greenlake-devices-mcp`` script). It speaks MCP over stdio only and fetches its own
OAuth2 token from GREENLAKE_CLIENT_ID / _CLIENT_SECRET / _WORKSPACE_ID (plus an
optional GREENLAKE_API_BASE_URL), so those variables must reach the subprocess.

In its default static tool mode the server exposes ``getdevicesv1`` (GET
/devices/v1/devices) with OData ``filter`` / ``filter_tags`` / ``sort``, a comma
separated ``select`` and ``limit`` (default 2000) / ``offset`` paging. Every call
returns one JSON envelope: ``{"success": true, "result": {"items", "count", "offset",
"total"}}`` or ``{"success": false, "httpStatusCode"/"error", "message", ...}``. In
dynamic mode (MCP_TOOL_MODE=dynamic) the same endpoint is reached through
``invoke_dynamic_tool`` and the page sits under ``"response"``.

When BR_GL_MCP_CMD (stdio) or BR_GL_MCP_URL (a Streamable HTTP bridge you run) is
set, the Topology agent pages through the workspace's devices and matches them to
twin servers by serial number, attaching model, part number, subscription and support
facts and flagging drift (model mismatch, no subscription, archived). ``doctor()``
reports readiness without any network call. Failures are returned, never raised:
GreenLake is enrichment, and discovery must not depend on it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import importlib.util
import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass
from typing import Any

DEVICES_TOOL = "getdevicesv1"
DYNAMIC_TOOL = "invoke_dynamic_tool"
DEVICES_ENDPOINT = "GET:/devices/v1/devices"
DEFAULT_CMD = "python -m greenlake_devices_mcp"
DEFAULT_BASE_URL = "https://global.api.greenlake.hpe.com"
REQUIRED_ENV = ("GREENLAKE_CLIENT_ID", "GREENLAKE_CLIENT_SECRET", "GREENLAKE_WORKSPACE_ID")
OPTIONAL_ENV = ("GREENLAKE_API_BASE_URL", "MCP_TOOL_MODE", "GREENLAKE_LOG_LEVEL", "GREENLAKE_FILE_LOGGING",
                "LOG_LEVEL", "HTTP_TIMEOUT", "HTTP_RETRIES")
# The server reaches GreenLake with httpx, which honours these.
NETWORK_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
               "SSL_CERT_FILE", "SSL_CERT_DIR")
SECRET_ENV = {"GREENLAKE_CLIENT_ID", "GREENLAKE_CLIENT_SECRET"}
# All are in getdevicesv1's documented selectable properties; an unknown one is an HTTP 400.
SELECT = ("id", "serialNumber", "model", "partNumber", "deviceType", "deviceName", "assignedState",
          "archived", "subscription", "warranty", "updatedAt")


class GreenLakeError(RuntimeError):
    pass


@dataclass(frozen=True)
class GLConfig:
    url: str = ""
    cmd: str = ""
    cwd: str = ""
    tool: str = ""
    filter: str = ""
    page_size: int = 2000
    max_pages: int = 10
    timeout_s: float = 60.0

    @property
    def transport(self) -> str | None:
        return "streamable-http" if self.url else "stdio" if self.cmd else None


def _setting(settings: Any, attr: str, env: str, default: Any = "") -> Any:
    """Settings attribute first (once config.py grows the field), then the env var, then the default."""
    value = getattr(settings, attr, None)
    if value in (None, ""):
        value = os.environ.get(env, "").strip()
    if value in (None, ""):
        return default
    if isinstance(default, (int, float)):
        try:
            return type(default)(value)
        except (TypeError, ValueError):
            return default
    return value


def load_config(settings: Any) -> GLConfig:
    return GLConfig(
        url=_setting(settings, "gl_mcp_url", "BR_GL_MCP_URL"),
        cmd=_setting(settings, "gl_mcp_cmd", "BR_GL_MCP_CMD"),
        cwd=_setting(settings, "gl_mcp_cwd", "BR_GL_MCP_CWD"),
        tool=_setting(settings, "gl_mcp_devices_tool", "BR_GL_MCP_DEVICES_TOOL"),
        filter=_setting(settings, "gl_mcp_filter", "BR_GL_MCP_FILTER"),
        page_size=max(1, min(2000, _setting(settings, "gl_mcp_page_size", "BR_GL_MCP_PAGE_SIZE", 2000))),
        max_pages=max(1, _setting(settings, "gl_mcp_max_pages", "BR_GL_MCP_MAX_PAGES", 10)),
        timeout_s=_setting(settings, "gl_mcp_timeout_s", "BR_GL_MCP_TIMEOUT_S", 60.0),
    )


def forwarded_env() -> dict[str, str]:
    """Variables passed to the stdio subprocess (the MCP SDK otherwise passes only HOME/PATH/...)."""
    return {k: os.environ[k] for k in REQUIRED_ENV + OPTIONAL_ENV + NETWORK_ENV if os.environ.get(k)}


def build_target(cfg: GLConfig) -> Any:
    """What mcp.Client should connect to: a URL, or StdioServerParameters for the configured command."""
    if cfg.url:
        return cfg.url
    from mcp import StdioServerParameters

    argv = shlex.split(cfg.cmd)
    return StdioServerParameters(command=argv[0], args=argv[1:], env=forwarded_env() or None, cwd=cfg.cwd or None)


# --------------------------------------------------------------------------- doctor


def doctor(settings: Any) -> dict:
    """Configuration readiness for the gl-mcp devices server. Local checks only, no network call."""
    cfg = load_config(settings)
    argv = shlex.split(cfg.cmd or DEFAULT_CMD)
    base = os.environ.get("GREENLAKE_API_BASE_URL") or DEFAULT_BASE_URL
    env = {k: ("set" if os.environ.get(k) else "missing") for k in REQUIRED_ENV}
    env["GREENLAKE_API_BASE_URL"] = os.environ.get("GREENLAKE_API_BASE_URL") or f"(unset, server default {DEFAULT_BASE_URL})"
    env["MCP_TOOL_MODE"] = os.environ.get("MCP_TOOL_MODE") or "(unset, server default static)"
    problems: list[str] = []
    report: dict[str, Any] = {
        "configured": cfg.transport is not None, "transport": cfg.transport, "network_calls": 0,
        "server": "greenlake-devices-mcp (github.com/HewlettPackard/gl-mcp, src/devices, Apache-2.0)",
        "tool": cfg.tool or DEVICES_TOOL, "dynamic_mode_tool": DYNAMIC_TOOL,
        "arguments": {"limit": cfg.page_size, "offset": "0, +count per page", "select": ",".join(SELECT),
                      **({"filter": cfg.filter} if cfg.filter else {})},
        "max_pages": cfg.max_pages, "timeout_s": cfg.timeout_s,
        "greenlake_endpoints": [f"{base}/devices/v1/devices", f"{base}/authorization/v2/oauth2/<GREENLAKE_WORKSPACE_ID>/token"],
    }
    if cfg.transport is None:
        problems.append(f"not configured: set BR_GL_MCP_CMD='{DEFAULT_CMD}' (stdio) or BR_GL_MCP_URL")
    if cfg.transport == "streamable-http":
        report["url"] = cfg.url
        report["note"] = ("the gl-mcp devices server ships stdio only (server/app.py runs transport='stdio'); "
                          "BR_GL_MCP_URL must be your own Streamable HTTP bridge, which holds the GREENLAKE_* credentials")
    else:
        launcher = shutil.which(argv[0])
        report.update(command=argv, cwd=cfg.cwd or None, launcher=launcher, env=env,
                      forwarded_env=sorted(k for k in forwarded_env()))
        if cfg.transport == "stdio" or not cfg.transport:
            problems += [f"{k} is not set (the server needs it to obtain an OAuth2 token)" for k in REQUIRED_ENV if env[k] == "missing"]
        if cfg.transport == "stdio" and not launcher:
            problems.append(f"launcher '{argv[0]}' not found on PATH")
        if argv[1:3] == ["-m", "greenlake_devices_mcp"] and not cfg.cwd:
            installed = importlib.util.find_spec("greenlake_devices_mcp") is not None
            report["package_installed_here"] = installed
            if not installed:
                problems.append("greenlake_devices_mcp is not importable by this interpreter: pip install greenlake-devices-mcp")
    report["problems"] = problems
    report["ready"] = cfg.transport is not None and not problems
    return report


# --------------------------------------------------------------------------- fetching


def _envelopes(result: Any) -> list[dict]:
    """The JSON objects a gl-mcp tool returned (structured content first, then text blocks)."""
    texts = [getattr(c, "text", "") for c in (getattr(result, "content", None) or [])]
    if getattr(result, "is_error", None) or getattr(result, "isError", False):
        raise GreenLakeError(" ".join(texts) or "tool error")
    structured = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        body = structured["result"] if set(structured) == {"result"} else structured
        found = body if isinstance(body, list) else [body]
        if any(isinstance(e, dict) for e in found):
            return [e for e in found if isinstance(e, dict)]
    out: list[dict] = []
    for text in texts:
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue
        out.extend(p for p in (parsed if isinstance(parsed, list) else [parsed]) if isinstance(p, dict))
    return out


def _page(envelope: dict) -> dict:
    if "items" in envelope:  # a bare page, e.g. from a bridge that unwraps the envelope
        return envelope
    for key in ("result", "response"):
        if isinstance(envelope.get(key), dict):
            return envelope[key]
    raise GreenLakeError(f"unexpected response shape: keys {sorted(envelope)}")


def _failure(envelope: dict) -> str:
    status = envelope.get("httpStatusCode") or envelope.get("error") or "error"
    return f"GreenLake {status}: {envelope.get('message') or envelope.get('errorCode') or 'request failed'}"


def _device_facts(d: dict) -> dict:
    warranty = d.get("warranty") if isinstance(d.get("warranty"), dict) else {}
    level = warranty.get("currentSupportLevel") if isinstance(warranty.get("currentSupportLevel"), dict) else {}
    subs = d.get("subscription") if isinstance(d.get("subscription"), list) else []
    return {
        "serial": str(d.get("serialNumber") or d.get("serial_number") or d.get("serial") or "").strip(),
        "gl_id": d.get("id"),
        "model": d.get("model"),
        "part_number": d.get("partNumber"),
        "device_type": d.get("deviceType"),
        "device_name": d.get("deviceName"),
        "assigned_state": d.get("assignedState"),
        "archived": bool(d.get("archived")),
        "subscriptions": [s.get("id") for s in subs if isinstance(s, dict) and s.get("id")],
        "support_level": level.get("serviceLevel") or level.get("contractLevel"),
        "support_end": level.get("endDate"),
    }


async def _call_page(client: Any, mode: str, tool: str, args: dict) -> dict:
    if mode == "dynamic":
        params = {("filter-tags" if k == "filter_tags" else k): v for k, v in args.items()}
        res = await client.call_tool(DYNAMIC_TOOL, {"endpoint_identifier": DEVICES_ENDPOINT, "parameters": params})
    else:
        res = await client.call_tool(tool, args)
    envelopes = _envelopes(res)
    if not envelopes:
        raise GreenLakeError(f"{tool} returned no JSON object")
    return envelopes[0]


async def _fetch(client: Any, cfg: GLConfig) -> dict:
    names = [t.name for t in (await client.list_tools()).tools]
    tool = cfg.tool or DEVICES_TOOL
    mode = "static" if tool in names else "dynamic" if DYNAMIC_TOOL in names and not cfg.tool else None
    if mode is None:
        raise GreenLakeError(f"device-listing tool '{tool}' not offered; server tools: {names}")
    select, offset, pages, total, notes = ",".join(SELECT), 0, 0, None, []
    devices: list[dict] = []
    error = None
    while pages < cfg.max_pages:
        args: dict[str, Any] = {"limit": cfg.page_size, "offset": offset}
        if select:
            args["select"] = select
        if cfg.filter:
            args["filter"] = cfg.filter
        envelope = await _call_page(client, mode, tool, args)
        if envelope.get("success") is False:
            if select and pages == 0 and envelope.get("httpStatusCode") == 400:
                select = ""
                notes.append("select rejected with HTTP 400; retried without select")
                continue
            if pages == 0:
                raise GreenLakeError(_failure(envelope))
            error = f"page {pages + 1}: {_failure(envelope)}"
            break
        page = _page(envelope)
        items = [d for d in page.get("items") or [] if isinstance(d, dict)]
        devices.extend(items)
        pages += 1
        total = page.get("total", total)
        count = int(page.get("count") or len(items))
        offset += count
        if not items or (total is not None and offset >= int(total)) or (total is None and count < cfg.page_size):
            break
    truncated = error is None and pages >= cfg.max_pages and (total is None or offset < int(total))
    return {"tool": DYNAMIC_TOOL if mode == "dynamic" else tool, "tool_mode": mode, "pages": pages,
            "total_reported": total, "truncated": truncated, "error": error, "notes": notes, "devices": devices}


def _run(coro: Any) -> Any:
    """asyncio.run, also from code that already has a running loop (e.g. inside a UI callback)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        return pool.submit(asyncio.run, coro).result()


async def _list(cfg: GLConfig, target: Any) -> dict:
    from mcp import Client

    async def go():
        async with Client(target, read_timeout_seconds=cfg.timeout_s) as client:
            return await _fetch(client, cfg)

    return await asyncio.wait_for(go(), timeout=cfg.timeout_s)


def list_devices(settings: Any, *, target: Any = None) -> dict:
    """Read-only device inventory from gl-mcp. ``target`` overrides the configured server (tests)."""
    cfg = load_config(settings)
    if target is None and cfg.transport is None:
        return {"enabled": False, "note": "gl-mcp not configured (set BR_GL_MCP_CMD or BR_GL_MCP_URL)"}
    transport = "injected" if target is not None else cfg.transport
    try:
        fetched = _run(_list(cfg, target if target is not None else build_target(cfg)))
    except Exception as exc:  # noqa: BLE001 - optional integration must never break discovery
        return {"enabled": True, "ok": False, "transport": transport, "error": _describe(exc)}
    devices = [_device_facts(d) for d in fetched.pop("devices")]
    return {"enabled": True, "ok": fetched["error"] is None, "transport": transport, **fetched,
            "devices_seen": len(devices), "devices": devices}


def _describe(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup) and exc.exceptions:  # anyio task groups wrap the real cause
        return _describe(exc.exceptions[0])
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "TimeoutError: gl-mcp did not answer in time"
    return f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- matching


def _norm_serial(s: Any) -> str:
    return re.sub(r"\s+", "", str(s or "")).upper()


def _model_agrees(twin_model: str | None, gl_model: str | None) -> bool | None:
    if not twin_model or not gl_model:
        return None
    a, b = (re.sub(r"[^a-z0-9]+", " ", m.lower()).replace("hpe ", "").strip() for m in (twin_model, gl_model))
    return a in b or b in a


def match_devices(servers: list[dict], devices: list[dict]) -> dict:
    """Join twin servers to GreenLake device facts by normalised serial number."""
    by_serial = {_norm_serial(d.get("serial")): d for d in devices if d.get("serial")}
    matches = []
    for s in servers:
        d = by_serial.get(_norm_serial(s.get("serialNumber")))
        if d is None:
            continue
        matches.append({"twin": s.get("name"), "cluster": s.get("cluster"), "twin_model": s.get("model"),
                        **d, "model_agrees": _model_agrees(s.get("model"), d.get("model"))})
    return {
        "matched_twin_servers": len(matches),
        "unmatched_twin_servers": len(servers) - len(matches),
        "matches": matches,
        "flags": {
            "model_mismatch": [m["twin"] for m in matches if m["model_agrees"] is False],
            "no_subscription": [m["twin"] for m in matches if not m["subscriptions"]],
            "archived": [m["twin"] for m in matches if m["archived"]],
        },
    }


def enrich_from_greenlake(settings: Any, servers: list[dict], *, target: Any = None) -> dict:
    """Topology-agent hook: list GreenLake devices and match them to twin servers. Never raises."""
    try:
        listed = list_devices(settings, target=target)
        if not listed.get("enabled") or "devices" not in listed:
            return listed
        devices = listed.pop("devices")
        out = {**listed, **match_devices(servers, devices)}
        if devices and not out["matched_twin_servers"]:
            out["note"] = ("no twin serial found in this workspace; the seeded twin uses synthetic serials "
                           "(SYN...), so a real workspace matches only after the twin is loaded from real inventory")
        return out
    except Exception as exc:  # noqa: BLE001 - optional integration must never break discovery
        return {"enabled": True, "ok": False, "error": _describe(exc)}
