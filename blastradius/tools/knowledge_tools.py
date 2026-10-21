"""Knowledge tools: release notes, advisories, incidents (RAG over BM25)."""

from __future__ import annotations

from . import ToolContext, ToolSpec


def tools(ctx: ToolContext) -> list[ToolSpec]:
    kb = ctx.kb

    def search(query: str, k: int = 5) -> list[dict]:
        """Full-text search over release notes, advisories and incident reviews."""
        return kb.search(query, k)

    def get_release_notes(component: str, version: str) -> dict:
        """Structured release notes for one firmware version (security fixes, known issues, install notes)."""
        rn = kb.release_note(component, version)
        return rn if rn else {"found": False, "component": component, "version": version}

    def list_advisories(component: str = "", version: str = "", cve: str = "") -> list[dict]:
        """Security/field advisories, optionally filtered by component, affected version or CVE."""
        return kb.advisories_for(component or None, version or None, cve or None)

    def list_incidents(component: str = "", version: str = "", model: str = "") -> list[dict]:
        """Past incidents (including ones BlastRadius learned from rollbacks)."""
        if component and version:
            return kb.incidents_for(component, version, model or None)
        return kb.all_incidents()

    def record_incident(incident: dict) -> dict:
        """WRITE (knowledge base only). Store a lesson learned from a failed change."""
        return kb.add_learned_incident(incident)

    return [
        ToolSpec("knowledge", "search", search, description=search.__doc__),
        ToolSpec("knowledge", "get_release_notes", get_release_notes, description=get_release_notes.__doc__),
        ToolSpec("knowledge", "list_advisories", list_advisories, description=list_advisories.__doc__),
        ToolSpec("knowledge", "list_incidents", list_incidents, description=list_incidents.__doc__),
        ToolSpec("knowledge", "record_incident", record_incident, description=record_incident.__doc__),
    ]
