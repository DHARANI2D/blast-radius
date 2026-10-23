"""Domain tools exposed to agents over MCP.

Each domain module returns ``ToolSpec`` objects whose functions carry full type
hints, so the MCP SDK can derive JSON schemas from them. The same functions are
registered on the MCP servers (``blastradius.mcp_layer``) and, for fast tests,
can be called in-process.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..approval import ApprovalAuthority
from ..knowledge import KnowledgeBase
from ..twin import Twin


class ToolDenied(RuntimeError):
    """A write tool refused the call (missing or invalid approval token)."""


@dataclass
class ToolContext:
    twin: Twin
    kb: KnowledgeBase
    authority: ApprovalAuthority

    def require(self, token: str, run_id: str, asset: str, action: str, version: str = "") -> None:
        ok, why = self.authority.check(token, run_id, asset, action, version)
        if not ok:
            raise ToolDenied(why)


@dataclass
class ToolSpec:
    domain: str          # MCP server the tool lives on: compute, network, virt, telemetry, knowledge
    name: str            # tool name on that server
    fn: Callable
    write: bool = False
    description: str = ""

    @property
    def key(self) -> str:
        return f"{self.domain}.{self.name}"


def build_registry(ctx: ToolContext) -> dict[str, ToolSpec]:
    from . import compute, knowledge_tools, network, telemetry, virtualization

    specs: list[ToolSpec] = []
    for mod in (compute, network, virtualization, telemetry, knowledge_tools):
        specs.extend(mod.tools(ctx))
    return {s.key: s for s in specs}
