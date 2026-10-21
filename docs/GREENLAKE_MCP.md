# HPE GreenLake MCP (gl-mcp) in BlastRadius

BlastRadius can enrich its topology with one **read-only** call path into HPE GreenLake:
HPE's official devices MCP server from
[github.com/HewlettPackard/gl-mcp](https://github.com/HewlettPackard/gl-mcp). The Topology
agent lists the workspace's devices and joins them to twin servers by serial number. The
adapter is `blastradius/greenlake.py`; it is optional and every failure is reported in the
topology summary instead of being raised.

> **Status:** no live GreenLake call has been made from BlastRadius. There were no
> GreenLake credentials while this was built. The adapter is tested against an in-process
> MCP server and a stdio subprocess that copy the real server's tool name, parameters and
> response envelope (`tests/test_greenlake.py`). The steps below are what a credential
> holder runs to make the first real call.

## What the real server offers

Source read: gl-mcp at commit `83dc9ca`, devices server `greenlake-devices-mcp` 1.1.2.

| Fact | Value | Source file in gl-mcp |
|---|---|---|
| Server for inventory | `src/devices`, PyPI `greenlake-devices-mcp` | `src/devices/pyproject.toml`, `src/devices/server.json` |
| Launch | `python -m greenlake_devices_mcp` or the `greenlake-devices-mcp` script | `src/devices/greenlake_devices_mcp/__main__.py`, `pyproject.toml` `[project.scripts]` |
| Transport | stdio only (`mcp.run(transport="stdio")`) | `src/devices/greenlake_devices_mcp/server/app.py`, `server.json` |
| Required env | `GREENLAKE_CLIENT_ID`, `GREENLAKE_CLIENT_SECRET`, `GREENLAKE_WORKSPACE_ID` | `src/devices/greenlake_devices_mcp/config/settings.py` |
| Optional env | `GREENLAKE_API_BASE_URL` (default `https://global.api.greenlake.hpe.com`), `MCP_TOOL_MODE` (`static` or `dynamic`), `GREENLAKE_LOG_LEVEL`, `GREENLAKE_FILE_LOGGING`, `HTTP_TIMEOUT`, `HTTP_RETRIES` | `config/settings.py`, `config/logging.py`, `src/devices/README.md` |
| Auth | OAuth2 client credentials against `{base}/authorization/v2/oauth2/{workspace}/token` | `config/settings.py` (`token_issuer_url`) |
| List tool (static mode) | `getdevicesv1` (GET `/devices/v1/devices`) with `filter`, `filter_tags`, `sort`, `select` (comma-separated string), `limit` (default 2000), `offset` | `tools/implementations/getdevicesv1.py` |
| List tool (dynamic mode) | `invoke_dynamic_tool(endpoint_identifier="GET:/devices/v1/devices", parameters={...})` | `tools/implementations/invoke_dynamic_tool.py`, `tools/registry.py` |
| Success envelope | one item: `{"success": true, "result": {"items", "count", "offset", "total"}}` (dynamic mode puts the page under `"response"`) | `getdevicesv1.py`, `models/base.py` `DevicesGetResponse` |
| Failure envelope | `{"success": false, "httpStatusCode" or "error", "errorCode", "message", "debugId"}` | `getdevicesv1.py` |
| Device fields | `id`, `serialNumber`, `model`, `partNumber`, `deviceType`, `deviceName`, `assignedState`, `archived`, `subscription` (list of `{id, resourceUri}`), `warranty` (`currentSupportLevel.serviceLevel`, `endDate`), `tags`, `updatedAt`, ... | `models/base.py` `DeviceDetail`, `ResponseSubscription`, `ResponseWarranty` |
| Rate limit, permissions | 160 requests/min per workspace; needs view permission for Devices and Subscription service | tool description in `getdevicesv1.py`, `server.json` |

## How BlastRadius calls it

1. Starts the configured command over stdio with the MCP Python SDK 2.x `Client` and
   **forwards the `GREENLAKE_*`, `MCP_TOOL_MODE`, logging and proxy variables**. The SDK passes
   only `HOME`, `PATH`, `SHELL` and a few others to a stdio child by default, so without this
   the server gets no credentials (the previous adapter had this bug).
2. Uses `getdevicesv1` when listed, otherwise `invoke_dynamic_tool` (dynamic mode).
3. Pages with `limit`/`offset` until `offset >= total` (at most `BR_GL_MCP_MAX_PAGES` pages) and
   asks only for the fields it maps through `select`. If the API rejects `select` with HTTP 400,
   it retries once without it.
4. Normalises serials (case, whitespace), joins them to the twin's `serialNumber`, and flags
   drift: GreenLake model differs from the twin, no subscription, archived.

## Make one genuine read-only call

```bash
# 1. Install the official server (same interpreter BlastRadius uses, or any python on PATH)
pip install greenlake-devices-mcp          # Apache-2.0, pulls mcp>=1.23, httpx, pydantic-settings

# 2. GreenLake API client credentials for the workspace (view access to Devices and Subscription)
export GREENLAKE_CLIENT_ID=...
export GREENLAKE_CLIENT_SECRET=...
export GREENLAKE_WORKSPACE_ID=...
export GREENLAKE_API_BASE_URL=https://global.api.greenlake.hpe.com   # optional, this is the default

# 3. Point BlastRadius at it (stdio)
export BR_GL_MCP_CMD="python -m greenlake_devices_mcp"
# optional:
export BR_GL_MCP_FILTER="deviceType eq 'COMPUTE'"   # OData filter passed through as-is
export BR_GL_MCP_PAGE_SIZE=2000                     # 1..2000
export BR_GL_MCP_MAX_PAGES=10
export BR_GL_MCP_TIMEOUT_S=60

# 4. Check readiness: local checks only, no network call
python -m blastradius greenlake doctor
#    until that CLI command is wired in:
python -c "import json; from blastradius.config import Settings; from blastradius.greenlake import doctor; print(json.dumps(doctor(Settings()), indent=2))"

# 5. The real call: lists devices (read-only GET /devices/v1/devices through gl-mcp)
python -c "import json; from blastradius.config import Settings; from blastradius.greenlake import list_devices; r = list_devices(Settings()); r['devices'] = r.get('devices', [])[:5]; print(json.dumps(r, indent=2))"
```

`doctor()` shows which `GREENLAKE_*` variables are set or missing (never their values), the
argv to be launched and whether its launcher is on `PATH`, whether `greenlake_devices_mcp`
can be imported, the tool and arguments to be sent, and the two GreenLake endpoints the
server will contact (useful for firewall allow-lists).

### All `BR_GL_MCP_*` settings

| Variable | Default | Meaning |
|---|---|---|
| `BR_GL_MCP_CMD` | unset | stdio command, e.g. `python -m greenlake_devices_mcp` or `uv run python -m greenlake_devices_mcp` |
| `BR_GL_MCP_CWD` | unset | working directory for the command (a gl-mcp `src/devices` checkout; its `.env` is read from there) |
| `BR_GL_MCP_URL` | unset | Streamable HTTP URL instead of stdio. gl-mcp itself ships stdio only, so this must be a bridge you run, and the bridge holds the credentials |
| `BR_GL_MCP_DEVICES_TOOL` | `getdevicesv1` | override the tool name (disables the dynamic-mode fallback) |
| `BR_GL_MCP_FILTER` | unset | OData `filter`, e.g. `deviceType eq 'COMPUTE'` |
| `BR_GL_MCP_PAGE_SIZE` | `2000` | `limit` per call |
| `BR_GL_MCP_MAX_PAGES` | `10` | page cap, which keeps the call well under 160 requests/min |
| `BR_GL_MCP_TIMEOUT_S` | `60` | timeout for the whole listing |

From a source checkout instead of PyPI: `BR_GL_MCP_CMD="uv run python -m greenlake_devices_mcp"` and
`BR_GL_MCP_CWD=/path/to/gl-mcp/src/devices` (after `uv sync` there).

## What the Topology agent shows

`TopologyAgent.run()` puts the result under `summary["greenlake"]`:

- not configured: `{"enabled": false, "note": "gl-mcp not configured (...)"}`
- failure (bad credentials, missing package, timeout): `{"enabled": true, "ok": false, "transport": "stdio", "error": "GreenLakeError: GreenLake 401: ..."}`. Discovery carries on without it.
- success: `transport`, `tool`, `tool_mode`, `pages`, `devices_seen`, `total_reported`,
  `truncated`, `matched_twin_servers`, `unmatched_twin_servers`, `matches` (per twin host:
  GreenLake id, model, part number, device type, subscription ids, support level and end
  date, `model_agrees`) and `flags` (`model_mismatch`, `no_subscription`, `archived`).

The seeded twin uses synthetic serials (`SYN1R001` ...), so a real workspace matches **0**
twin hosts. The summary says so in `note`. Matches are meaningful once the twin is loaded
from real inventory, or for the drift flags on real serials.

## License

gl-mcp is licensed under the **Apache License 2.0** (`LICENSE` at the repository root and
`src/devices/LICENSE`; `pyproject.toml` declares `Apache-2.0`; source files carry
"(c) Copyright 2026 Hewlett Packard Enterprise Development LP"). BlastRadius does not vendor
or copy gl-mcp code. It launches the separately installed package as a subprocess and talks
to it over MCP.
