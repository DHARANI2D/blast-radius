"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("BR_DATA_DIR", str(ROOT / "data"))))
    policy_file: Path = field(default_factory=lambda: Path(_env("BR_POLICY_FILE", str(ROOT / "policy" / "policy.yaml"))))
    runtime_dir: Path = field(default_factory=lambda: Path(_env("BR_RUNTIME_DIR", str(ROOT / "runtime"))))

    # LLM endpoint. "offline" uses deterministic stand-ins so the demo and the
    # tests run without network access. "openai" talks to any OpenAI-compatible
    # chat-completions endpoint (NVIDIA NIM on HPE Private Cloud AI, or a
    # ChatHPE / GenAI Hub gateway); "azure" uses the Azure OpenAI URL scheme.
    llm_mode: str = field(default_factory=lambda: _env("BR_LLM_MODE", "offline"))
    llm_base_url: str = field(default_factory=lambda: _env("BR_LLM_BASE_URL"))
    llm_api_key: str = field(default_factory=lambda: _env("BR_LLM_API_KEY"))
    llm_model: str = field(default_factory=lambda: _env("BR_LLM_MODEL", "approved-model"))
    llm_api_version: str = field(default_factory=lambda: _env("BR_LLM_API_VERSION", "2024-10-21"))
    llm_timeout_s: float = field(default_factory=lambda: float(_env("BR_LLM_TIMEOUT_S", "60")))
    # The Verifier should not share the Planner's blind spots: point it at a
    # different model when one is available. Defaults to the planner model
    # with a separate prompt and temperature 0.
    verifier_model: str = field(default_factory=lambda: _env("BR_VERIFIER_MODEL"))
    verifier_base_url: str = field(default_factory=lambda: _env("BR_VERIFIER_BASE_URL"))
    verifier_api_key: str = field(default_factory=lambda: _env("BR_VERIFIER_API_KEY"))

    # Tool transport: "mcp" routes every agent tool call through an MCP client
    # session; "inproc" calls the same tool functions directly (faster tests).
    tool_transport: str = field(default_factory=lambda: _env("BR_TOOL_TRANSPORT", "mcp"))

    # Fault injection for the demo. BR_FAULTS = on (canary regression), off, subtle (a 1.3x
    # regression the fixed threshold misses), backup (a slowdown on every host), or a
    # '+' combination such as on+backup. faults_enabled is kept for callers that pass a bool.
    fault_scenario: str = field(default_factory=lambda: _env("BR_FAULTS", "on").lower())
    faults_enabled: bool = field(default_factory=lambda: _env("BR_FAULTS", "on").lower() in ("1", "on", "true", "yes"))

    # Secret used to sign approvals, write-tool tokens and reports (HMAC-SHA256).
    signing_key: str = field(default_factory=lambda: _env("BR_SIGNING_KEY", "blastradius-demo-key-change-me"))

    # Optional: official HPE GreenLake MCP server (HewlettPackard/gl-mcp) for
    # read-only inventory enrichment. Either a Streamable HTTP URL or a
    # command line that starts the server over stdio.
    gl_mcp_url: str = field(default_factory=lambda: _env("BR_GL_MCP_URL"))
    gl_mcp_cmd: str = field(default_factory=lambda: _env("BR_GL_MCP_CMD"))
    gl_mcp_devices_tool: str = field(default_factory=lambda: _env("BR_GL_MCP_DEVICES_TOOL"))

    @property
    def twin_file(self) -> Path:
        return self.data_dir / "twin" / "pod_blr1.json"

    @property
    def knowledge_dir(self) -> Path:
        return self.data_dir / "knowledge"

    @property
    def offline(self) -> bool:
        return self.llm_mode == "offline"
