"""Policy loading and the execution-time policy guard."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml


class Policy:
    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, path: Path) -> "Policy":
        return cls(yaml.safe_load(path.read_text()))

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def tier_weight(self, tier: int) -> float:
        w = self.get("impact.tier_weights", {})
        return float(w.get(tier, w.get(str(tier), 1)))

    def redact(self, text: str) -> str:
        """Mask secrets and e-mail addresses. A pattern's ``keep`` group (the key and its quotes) survives, so a
        redacted JSON prompt stays valid JSON."""
        def mask(m: re.Match) -> str:
            keep = m.groupdict().get("keep") or ""
            # A bare JSON value under a secret key ("api_token": 12345) gets a quoted mask, so the JSON stays valid.
            return keep + ('"[REDACTED]"' if re.search(r'(?<!\\)"\s*:\s*$', keep) else "[REDACTED]")

        for pat in self.get("redaction.patterns", []):
            text = re.sub(pat, mask, text)
        return text


class PolicyViolation(RuntimeError):
    pass


class PolicyGuard:
    """Checks every write before it reaches an MCP write tool.

    The MCP servers re-check the approval token themselves; this guard adds the
    allow-list, scope, rate and kill-switch checks on the agent side.
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        self.actions_this_wave = 0

    def kill_switch_on(self) -> bool:
        env = self.policy.get("execution.kill_switch_env", "BR_KILL_SWITCH")
        return os.environ.get(env, "").lower() in ("1", "on", "true", "yes")

    def new_wave(self) -> None:
        self.actions_this_wave = 0

    def check(self, tool: str, asset: str, approved_assets: set[str]) -> None:
        if self.kill_switch_on():
            raise PolicyViolation("kill switch engaged: all write actions are blocked")
        allowed = set(self.policy.get("execution.allowed_write_tools", []))
        if tool not in allowed:
            raise PolicyViolation(f"{tool} is not on the write allow-list")
        if asset not in approved_assets:
            raise PolicyViolation(f"{asset} is not in the approved scope of the current wave")
        limit = int(self.policy.get("execution.max_actions_per_wave", 100))
        if self.actions_this_wave >= limit:
            raise PolicyViolation(f"rate limit: more than {limit} write actions in one wave")
        self.actions_this_wave += 1
