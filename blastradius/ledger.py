"""Tamper-evident, hash-chained audit ledger (SQLite).

Every entry stores an HMAC-SHA256 (key: BR_SIGNING_KEY) over the previous entry's
hash and its own fields, so editing or deleting any row breaks the chain from that
point on, and the chain cannot be recomputed without the key. Every append also
writes a signed head anchor (seq, head) beside the database, so deleting the newest
rows is detected too. ``verify()`` recomputes the chain and checks the anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(key: bytes, prev_hash: str, seq: int, ts: float, run_id: str, actor: str, event: str, payload: str) -> str:
    material = canonical([prev_hash, seq, round(ts, 6), run_id, actor, event, payload])
    return hmac.new(key, material.encode(), hashlib.sha256).hexdigest()


class Ledger:
    def __init__(self, path: Path | str = ":memory:", key: str | None = None):
        if key is None:
            from .config import Settings

            key = Settings().signing_key
        self._key = key.encode()
        self.path = str(path)
        self._anchor: dict | None = None  # in-memory ledgers keep their anchor here
        self.anchor_path = None if self.path == ":memory:" else Path(self.path + ".anchor")
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
            h = entry_hash(self._key, prev, seq, ts, run_id, actor, event, body)
            self._db.execute(
                "INSERT INTO ledger (seq, ts, run_id, actor, event, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                (seq, ts, run_id, actor, event, body, prev, h),
            )
            self._db.commit()
            self._write_anchor(seq, h)
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

    # ------------------------------------------------------------ head anchor
    def _anchor_mac(self, seq: int, head: str) -> str:
        return hmac.new(self._key, f"anchor|{seq}|{head}".encode(), hashlib.sha256).hexdigest()

    def _write_anchor(self, seq: int, head: str) -> None:
        anchor = {"seq": seq, "head": head, "mac": self._anchor_mac(seq, head)}
        if self.anchor_path is None:
            self._anchor = anchor
            return
        tmp = self.anchor_path.with_suffix(".anchor.tmp")
        tmp.write_text(json.dumps(anchor))
        tmp.replace(self.anchor_path)

    def read_anchor(self) -> dict | None:
        if self.anchor_path is None:
            return self._anchor
        try:
            return json.loads(self.anchor_path.read_text())
        except (OSError, ValueError):
            return None

    def verify(self) -> dict:
        """Recompute the keyed chain and check it against the signed head anchor.

        Returns ``{"ok": bool, "entries": n, "broken_at": seq|None}`` plus ``reason`` when it fails: an edited or
        re-chained row (``broken_at`` is its seq), or a missing, forged or newer anchor (rows deleted from the end).
        """
        prev = GENESIS
        n = 0
        last = 0
        for seq, ts, run_id, actor, event, payload, prev_hash, h in self._db.execute(
            "SELECT seq, ts, run_id, actor, event, payload, prev_hash, hash FROM ledger ORDER BY seq"
        ):
            n += 1
            if prev_hash != prev or entry_hash(self._key, prev, seq, ts, run_id, actor, event, payload) != h:
                return {"ok": False, "entries": n, "broken_at": seq, "reason": "entry does not match the keyed chain"}
            prev, last = h, seq
        anchor = self.read_anchor()
        if n and anchor is None:
            return {"ok": False, "entries": n, "broken_at": None, "reason": "head anchor missing"}
        if anchor is not None:
            if not hmac.compare_digest(str(anchor.get("mac", "")), self._anchor_mac(anchor.get("seq", -1), str(anchor.get("head", "")))):
                return {"ok": False, "entries": n, "broken_at": None, "reason": "head anchor signature invalid"}
            if (anchor["seq"], anchor["head"]) != (last, prev):
                return {"ok": False, "entries": n, "broken_at": min(last + 1, anchor["seq"]),
                        "reason": f"head anchor is at seq {anchor['seq']} but the table ends at seq {last}: entries were removed"}
        return {"ok": True, "entries": n, "broken_at": None, "head": prev}

    def tamper(self, seq: int, new_payload: dict) -> None:
        """Test/demo helper: overwrite a payload without re-hashing."""
        self._db.execute("UPDATE ledger SET payload = ? WHERE seq = ?", (canonical(new_payload), seq))
        self._db.commit()
