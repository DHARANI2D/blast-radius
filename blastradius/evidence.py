"""Evidence store: every tool call an agent makes becomes a citable record.

Plans, risk scores and verifier verdicts cite evidence IDs (``EV-0007``), and
the UI links each claim to the exact tool output that supports or contradicts
it.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any


class EvidenceStore:
    def __init__(self):
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._n = 0

    def add(self, agent: str, tool: str, args: dict, result: Any, ok: bool = True) -> str:
        with self._lock:
            self._n += 1
            eid = f"EV-{self._n:04d}"
            self._items[eid] = {
                "id": eid,
                "agent": agent,
                "tool": tool,
                "args": args,
                "ok": ok,
                "result": result,
                "ts": time.time(),
            }
            return eid

    def get(self, eid: str) -> dict | None:
        return self._items.get(eid)

    def all(self) -> list[dict]:
        return list(self._items.values())

    def summary(self, eid: str, limit: int = 400) -> str:
        e = self._items.get(eid)
        if not e:
            return f"{eid}: <missing>"
        res = json.dumps(e["result"], default=str)
        if len(res) > limit:
            res = res[:limit] + "...(truncated)"
        return f"{eid} [{e['agent']}] {e['tool']}({json.dumps(e['args'], default=str)}) -> {res}"

    def __len__(self) -> int:
        return len(self._items)
