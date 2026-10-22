"""Wiring: one object that holds the twin, tools, ledger, LLM clients and policy."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .approval import ApprovalAuthority
from .config import Settings
from .evidence import EvidenceStore
from .knowledge import KnowledgeBase
from .ledger import Ledger
from .llm import LLMClient, make_llm
from .mcp_layer import ToolBus
from .memory import PlanningMemory
from .policy import Policy, PolicyGuard
from .tools import ToolContext, build_registry
from .twin import Twin


@dataclass
class Services:
    settings: Settings
    policy: Policy
    twin: Twin
    kb: KnowledgeBase
    authority: ApprovalAuthority
    ledger: Ledger
    evidence: EvidenceStore
    bus: ToolBus
    llm: LLMClient
    verifier_llm: LLMClient
    guard: PolicyGuard
    runs: dict = field(default_factory=dict)  # run_id -> in-memory context (dependency graph)
    memory: PlanningMemory | None = None      # planning rules learned from rejected attempts

    @classmethod
    def create(cls, settings: Settings | None = None, ledger_path: str | None = None, **overrides) -> "Services":
        settings = settings or Settings()
        if overrides:
            settings = replace(settings, **overrides)
        policy = Policy.load(settings.policy_file)
        # An explicit faults_enabled override (tests, UI toggle) wins over the BR_FAULTS scenario.
        explicit_bool = "faults_enabled" in overrides and "fault_scenario" not in overrides
        twin = Twin(settings.twin_file, faults_enabled=settings.faults_enabled,
                    scenario=None if explicit_bool else settings.fault_scenario)
        kb = KnowledgeBase(settings.knowledge_dir, settings.runtime_dir)
        authority = ApprovalAuthority(settings.signing_key)
        ledger = Ledger(ledger_path if ledger_path is not None else settings.runtime_dir / "ledger.sqlite", settings.signing_key)
        evidence = EvidenceStore()
        registry = build_registry(ToolContext(twin=twin, kb=kb, authority=authority))
        bus = ToolBus(registry, evidence, transport=settings.tool_transport)
        llm, verifier_llm = make_llm(settings, policy)
        sv = cls(settings, policy, twin, kb, authority, ledger, evidence, bus, llm, verifier_llm, PolicyGuard(policy))
        sv.memory = PlanningMemory.from_services(sv)
        return sv

    def reset_lab(self, forget_lessons: bool = True) -> None:
        """Restore the twin to its seeded state (and optionally forget learned incidents)."""
        self.twin.reset()
        if forget_lessons:
            self.kb.clear_learned()
            self.memory.clear()
