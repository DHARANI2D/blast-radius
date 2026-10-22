"""Pydantic schemas for everything an LLM produces. Outputs that do not validate are rejected."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

COMPONENTS = ("iLO 6", "System ROM", "Switch OS")

CLAIM_TYPES = (
    "fixes_cve",          # args: component, version, cve
    "no_known_issues",    # args: component, version, model?
    "pair_safe_together",  # args: a, b
    "pair_staggered",     # args: a, b
    "all_dual_homed",     # args: cluster
    "dual_homed",         # args: server
    "single_homed",       # args: server
    "cluster_capacity",   # args: cluster, hosts
    "per_wave_cap",       # args: hosts
    "canary_safe",        # args: -
    "canary_covers_cohorts",  # args: cohorts?
    "no_planned_outage",  # args: -
    "install_order",      # args: first, second
    "in_window",          # args: minutes
    "freeform",           # args: -
)


class MaintenanceWindow(BaseModel):
    day: str = "Saturday"
    start: str = "22:00"
    duration_minutes: int = Field(480, ge=30, le=24 * 60)


class ChangeRequest(BaseModel):
    summary: str
    target_clusters: list[str] = []
    target_servers: list[str] = []
    target_switches: list[str] = []
    components: list[str]
    baseline: str = "latest"
    window: MaintenanceWindow = MaintenanceWindow()
    notes: list[str] = []

    @field_validator("components")
    @classmethod
    def _known_components(cls, v: list[str]) -> list[str]:
        bad = [c for c in v if c not in COMPONENTS]
        if bad:
            raise ValueError(f"unknown components {bad}; allowed {COMPONENTS}")
        if not v:
            raise ValueError("at least one component is required")
        return v


class Wave(BaseModel):
    name: str
    assets: list[str]
    evacuate: list[str] = []
    rationale: str = ""


class Plan(BaseModel):
    waves: list[Wave]
    rationale: str
    self_confidence: int | None = Field(None, ge=0, le=100)


class Explanation(BaseModel):
    """The planner's re-explanation of the optimiser's waves (the waves themselves are not echoed back)."""
    rationale: str
    self_confidence: int | None = Field(None, ge=0, le=100)


class ExtractedClaim(BaseModel):
    text: str
    type: str = "freeform"
    args: dict = {}

    @field_validator("type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        return v if v in CLAIM_TYPES else "freeform"


class ClaimList(BaseModel):
    claims: list[ExtractedClaim]


class Judgement(BaseModel):
    label: Literal["Supported", "Contradicted", "Unverifiable"]
    explanation: str
    evidence: list[str] = []
