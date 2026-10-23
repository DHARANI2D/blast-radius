"""Knowledge base: release notes, advisories and incidents, with BM25 retrieval.

Retrieval is plain BM25 so the PoC has no vector-DB dependency; the interface
(``search``) is what a Chroma/pgvector backend would implement in Phase 2.
Incidents learned from BlastRadius rollbacks are persisted to the runtime
directory and merged in, which is how a regression seen once raises the risk
of similar changes later.
"""

from __future__ import annotations

import json
import math
import re
import threading
from collections import Counter
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]*")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class KnowledgeBase:
    def __init__(self, knowledge_dir: Path, runtime_dir: Path | None = None):
        self.dir = knowledge_dir
        self.learned_file = (runtime_dir / "learned_incidents.json") if runtime_dir else None
        self._lock = threading.Lock()
        self.reload()

    def reload(self) -> None:
        with self._lock:
            self.release_notes = json.loads((self.dir / "release_notes.json").read_text())
            self.advisories = json.loads((self.dir / "advisories.json").read_text())
            self.incidents = json.loads((self.dir / "incidents.json").read_text())
            self.learned: list[dict] = []
            if self.learned_file and self.learned_file.exists():
                self.learned = json.loads(self.learned_file.read_text())
            self._index()

    def _docs(self) -> list[dict]:
        docs = []
        for r in self.release_notes:
            docs.append({"id": r["id"], "kind": "release_note", "title": r["title"], "text": r["text"] + " " + r.get("install_notes", "")})
        for a in self.advisories:
            docs.append({"id": a["id"], "kind": "advisory", "title": a["title"], "text": a["text"]})
        for i in self.incidents + self.learned:
            docs.append({"id": i["id"], "kind": "incident", "title": i["title"], "text": i["symptom"] + " " + i.get("lesson", "")})
        return docs

    def _index(self) -> None:
        self.docs = self._docs()
        self._tf = [Counter(tokenize(d["title"] + " " + d["text"])) for d in self.docs]
        self._len = [sum(tf.values()) for tf in self._tf]
        self._avg = sum(self._len) / max(1, len(self._len))
        df: Counter = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = len(self.docs)
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def search(self, query: str, k: int = 5) -> list[dict]:
        k1, b = 1.4, 0.75
        q = tokenize(query)
        scored = []
        for i, tf in enumerate(self._tf):
            s = 0.0
            for t in q:
                if t not in tf:
                    continue
                f = tf[t]
                s += self._idf.get(t, 0) * f * (k1 + 1) / (f + k1 * (1 - b + b * self._len[i] / self._avg))
            if s > 0:
                scored.append((s, i))
        scored.sort(reverse=True)
        return [{**self.docs[i], "score": round(s, 3)} for s, i in scored[:k]]

    # --------------------------------------------------------- structured API
    def release_note(self, component: str, version: str) -> dict | None:
        for r in self.release_notes:
            if r["component"] == component and r["version"] == version:
                return r
        return None

    def advisories_for(self, component: str | None = None, version: str | None = None, cve: str | None = None) -> list[dict]:
        out = []
        for a in self.advisories:
            if component and a["component"] != component:
                continue
            if version and version not in a.get("affected_versions", []):
                continue
            if cve and cve not in a.get("cves", []):
                continue
            out.append(a)
        return out

    def all_incidents(self) -> list[dict]:
        return self.incidents + self.learned

    def incidents_for(self, component: str, version: str, model: str | None = None) -> list[dict]:
        out = []
        for i in self.all_incidents():
            if i.get("component") != component or i.get("version") != version:
                continue
            if model and i.get("models") and model not in i["models"]:
                continue
            out.append(i)
        return out

    def add_learned_incident(self, incident: dict, run_id: str | None = None) -> dict:
        """Store a learned incident. An id another run recorded is never overwritten."""
        with self._lock:
            incident = {**incident, "recorded_by_run": run_id or incident.get("recorded_by_run")}
            prev = next((i for i in self.learned if i["id"] == incident["id"]), None)
            if prev and prev.get("recorded_by_run") != incident["recorded_by_run"]:
                raise ValueError(f"incident {incident['id']} was recorded by run {prev.get('recorded_by_run')}; it cannot be overwritten")
            self.learned = [i for i in self.learned if i["id"] != incident["id"]] + [incident]
            if self.learned_file:
                self.learned_file.parent.mkdir(parents=True, exist_ok=True)
                self.learned_file.write_text(json.dumps(self.learned, indent=1))
            self._index()
            return incident

    def clear_learned(self) -> None:
        with self._lock:
            self.learned = []
            if self.learned_file and self.learned_file.exists():
                self.learned_file.unlink()
            self._index()
