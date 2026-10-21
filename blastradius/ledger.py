"""Tamper-evident, hash-chained audit ledger (SQLite).

Every entry stores the SHA-256 of the previous entry, so editing or deleting any
row breaks the chain from that point on. ``verify()`` recomputes the chain.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(prev_hash: str, seq: int, ts: float, run_id: str, actor: str, event: str, payload: str) -> str:
    material = canonical([prev_hash, seq, round(ts, 6), run_id, actor, event, payload])
    return hashlib.sha256(material.encode()).hexdigest()


class Ledger:
    def __init__(self, path: Path | str = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS ledger (
                seq INTEGER PRIMARY KEY,
                ts REAL NOT NULL,
                run_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                event TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )"""
        )
        self._db.commit()

    def head(self) -> tuple[int, str]:
        row = self._db.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def append(self, run_id: str, actor: str, event: str, payload: dict | None = None) -> dict:
        with self._lock:
            seq, prev = self.head()
            seq += 1
            ts = time.time()
            body = canonical(payload or {})
            h = entry_hash(prev, seq, ts, run_id, actor, event, body)
            self._db.execute(
                "INSERT INTO ledger (seq, ts, run_id, actor, event, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                (seq, ts, run_id, actor, event, body, prev, h),
            )
            self._db.commit()
            return {"seq": seq, "ts": ts, "run_id": run_id, "actor": actor, "event": event, "hash": h, "prev_hash": prev}

    def entries(self, run_id: str | None = None) -> list[dict]:
        q = "SELECT seq, ts, run_id, actor, event, payload, prev_hash, hash FROM ledger"
        args: tuple = ()
        if run_id:
            q += " WHERE run_id = ?"
            args = (run_id,)
        rows = self._db.execute(q + " ORDER BY seq", args).fetchall()
        return [
            {"seq": r[0], "ts": r[1], "run_id": r[2], "actor": r[3], "event": r[4],
             "payload": json.loads(r[5]), "prev_hash": r[6], "hash": r[7]}
            for r in rows
        ]

    def verify(self) -> dict:
        """Recompute the whole chain. Returns ``{"ok": bool, "entries": n, "broken_at": seq|None}``."""
        prev = GENESIS
        n = 0
        for seq, ts, run_id, actor, event, payload, prev_hash, h in self._db.execute(
            "SELECT seq, ts, run_id, actor, event, payload, prev_hash, hash FROM ledger ORDER BY seq"
        ):
            n += 1
            if prev_hash != prev or entry_hash(prev, seq, ts, run_id, actor, event, payload) != h:
                return {"ok": False, "entries": n, "broken_at": seq}
            prev = h
        return {"ok": True, "entries": n, "broken_at": None, "head": prev}

    def tamper(self, seq: int, new_payload: dict) -> None:
        """Test/demo helper: overwrite a payload without re-hashing."""
        self._db.execute("UPDATE ledger SET payload = ? WHERE seq = ?", (canonical(new_payload), seq))
        self._db.commit()
