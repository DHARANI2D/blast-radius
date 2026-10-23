"""Planning memory: what the Verifier and the constraint checker taught the planner.

Rollback lessons (reporter.py) stop the *next change* from repeating a bad firmware
combination. This module closes the other half of the loop. When a plan attempt is
rejected, every contradicted claim and every constraint violation becomes a
normalised, reusable rule, keyed so that the same mistake on a later run updates one
rule (``hits`` += 1) instead of adding another:

    REDUNDANT_PAIR:tor-r1-a|tor-r1-b                  (constraint violation + assets)
    CLUSTER_CAPACITY:PROD-BLR-07                       (with the limit that applied)
    PLANNED_OUTAGE:storage:alletra-mp-blr-01           (with the root cause)
    fixes_cve:System ROM:U54 v2.32:SYN-CVE-2026-1105   (claim type + canonical args)

Each rule carries one imperative guidance sentence built from the evidence that
rejected the plan (release-note and advisory ids, simulated outage, capacity limit),
its subject (assets, clusters, components), the source run and evidence ids.

Before planning, ``retrieve`` returns the rules whose subject overlaps the new change,
plus generic rules (canary coverage, wave size) that apply to the kind of assets it
touches, ranked by relevance, then hits, then recency. ``as_prompt`` renders them for
the planner prompt and ``covers`` lets any planner (including the offline stand-in)
ask whether its retrieved rules already warn against a given mistake. ``record_run``
and ``stats`` measure the point of it: the first-attempt pass rate, split by whether
any rules were retrieved.

Rules are guidance, never guardrails: constraints.py and the Verifier still check
every plan. The store is one JSON file in the runtime directory. It is re-read on
every call and written atomically under a per-path lock, so several Services objects
(Streamlit reruns) can share it.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from .topology import Topology

FILE_NAME = "planning_memory.json"
_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _shared_lock(path: Path | None) -> threading.RLock:
    if path is None:
        return threading.RLock()
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(str(path.resolve()), threading.RLock())


def _names(xs: Iterable[str], limit: int = 3) -> str:
    xs = list(xs)
    return ", ".join(xs[:limit]) + ("..." if len(xs) > limit else "")


def _ver(v: Any) -> str:
    return " ".join(str(v).split())


def _slug(text: str, n: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:n]


def _rule(key: str, kind: str, source: str, guidance: str, *, assets: Iterable[str] = (), clusters: Iterable[str] = (),
          components: Iterable[str] = (), needs: str | None = None, args: dict | None = None,
          evidence: Iterable[str] = ()) -> dict:
    return {"key": key, "kind": kind, "source": source, "guidance": guidance,
            "subject": {"assets": sorted(set(assets)), "clusters": sorted(set(clusters)),
                        "components": sorted(set(components)), "needs": needs},
            "args": args or {}, "evidence": list(dict.fromkeys(evidence))}


def _is_generic(rule: dict) -> bool:
    s = rule["subject"]
    return not (s["assets"] or s["clusters"] or s["components"])


# ------------------------------------------------------------ violations
def _impact(cons: dict, wave: int | None) -> dict:
    return next((x for x in cons.get("impacts", []) if x.get("wave") == wave), {})


def _pair_kind(topo: Topology | None, a: str) -> str:
    red = ((topo.switches.get(a) if topo else None) or {}).get("redundancy") or {}
    return f"{red['type']} pair" if red.get("type") else "redundant pair"


def _arrays_behind(topo: Topology | None, switches: set[str], fallback: list[str]) -> list[str]:
    if topo is None:
        return list(fallback)
    return sorted(n for n, arr in topo.arrays.items() if {p["switch"] for p in arr.get("ports", [])} <= switches)


def _outage_tail(imp: dict) -> str:
    n, crit = len(imp.get("impacted_vms", [])), imp.get("critical_vms", [])
    return f"{n} VMs lost service" + (f" (incl. tier-0 {_names(crit)})" if crit else "")


def _from_violation(v: dict, cons: dict, topo: Topology | None, ev: str) -> list[dict]:
    code, wave, msg, assets = v["code"], v.get("wave"), v["message"], list(v.get("assets") or [])
    imp = _impact(cons, wave)
    evidence = [ev + (f"/wave-{wave}" if wave else "")]
    if code == "REDUNDANT_PAIR":
        a, b = sorted(assets[:2])
        arrays = _arrays_behind(topo, {a, b}, imp.get("arrays_unreachable", []))
        why = f"they are a {_pair_kind(topo, a)}" + (f" and storage array {_names(arrays)} is reachable only through them" if arrays else "")
        n = len(imp.get("impacted_vms", []))
        sim = f"; together they took {n} VMs down in simulation" if n else ""
        return [_rule(f"REDUNDANT_PAIR:{a}|{b}", code, "constraints",
                      f"Never put {a} and {b} in the same wave: {why}{sim}.",
                      assets=[a, b], needs="switches", args={"pair": [a, b], "arrays": arrays}, evidence=evidence)]
    if code == "PLANNED_OUTAGE":
        down = imp.get("down_switches", [])
        if imp.get("arrays_unreachable"):
            arr = imp["arrays_unreachable"]
            return [_rule(f"PLANNED_OUTAGE:storage:{'|'.join(arr)}", code, "constraints",
                          f"Keep a storage path to {_names(arr)} up in every wave: wave {wave} took {_names(down, 4)} down "
                          f"together and cut it off; {_outage_tail(imp)}.",
                          assets=down + arr, needs="switches", args={"root_cause": "storage_unreachable", "arrays": arr,
                                                                    "down_switches": down}, evidence=evidence)]
        if imp.get("isolated_servers"):
            iso = imp["isolated_servers"]
            clusters = [topo.servers[h]["cluster"] for h in iso if h in topo.servers] if topo else []
            return [_rule(f"PLANNED_OUTAGE:isolated:{'|'.join(down) or '|'.join(iso)}", code, "constraints",
                          f"Before taking {_names(down) or 'their switches'} down, evacuate or co-schedule {_names(iso)}: "
                          f"they lose every network path with it down; {_outage_tail(imp)} in wave {wave}.",
                          assets=down + iso, clusters=clusters, args={"root_cause": "network_isolation", "isolated": iso,
                                                                     "down_switches": down}, evidence=evidence)]
        if imp.get("capacity_shortfall_gb"):
            return [_rule(f"PLANNED_OUTAGE:capacity:{c}", code, "constraints",
                          f"Take few enough {c} hosts down per wave that every VM can be evacuated (each must fit on one "
                          f"surviving host): wave {wave} left {c} short {gb} GB and {_outage_tail(imp)} in that wave.",
                          clusters=[c], needs="servers", args={"root_cause": "evacuation_capacity", "cluster": c,
                                                               "shortfall_gb": gb}, evidence=evidence)
                    for c, gb in sorted(imp["capacity_shortfall_gb"].items())]
        return [_rule(f"PLANNED_OUTAGE:wave-{_slug(msg, 40)}", code, "constraints", f"Avoid this outage: {msg}.",
                      assets=assets, args={"root_cause": "unknown"}, evidence=evidence)]
    if code == "CLUSTER_CAPACITY":
        m = re.search(r"puts (?P<n>\d+) hosts of (?P<c>\S+) in maintenance; limit is (?P<lim>\d+)", msg)
        if m:
            p = re.search(r"policy (?P<p>\d+), capacity allows (?P<k>\d+)", msg)
            c, lim, n = m["c"], int(m["lim"]), int(m["n"])
            basis = f"policy allows {p['p']} and capacity allows {p['k']}" if p else "that is the cluster limit"
            return [_rule(f"CLUSTER_CAPACITY:{c}", code, "constraints",
                          f"Put at most {lim} {c} hosts (evacuations included) in maintenance per wave: {basis}; "
                          f"a rejected plan put {n} in wave {wave}.",
                          clusters=[c], needs="servers", args={"cluster": c, "limit": lim, "seen": n}, evidence=evidence)]
    if code == "CANARY_FIRST":
        if m := re.search(r"at most (?P<k>\d+) assets \(has (?P<n>\d+)\)", msg):
            return [_rule("CANARY_FIRST:size", code, "constraints",
                          f"Keep the canary (wave 1) to at most {m['k']} assets: a rejected canary had {m['n']}.",
                          args={"limit": int(m["k"])}, evidence=evidence)]
        if "network devices" in msg:
            return [_rule("CANARY_FIRST:network", code, "constraints",
                          f"Canary with servers only and upgrade switches in later waves: a rejected canary included {_names(assets)}.",
                          needs="switches", evidence=evidence)]
        if m := re.search(r"run (?P<tier>tier-\d+) workloads", msg):
            hosts = sorted(assets)
            return [_rule(f"CANARY_FIRST:critical:{'|'.join(hosts)}", code, "constraints",
                          f"Keep {_names(hosts)} out of the canary: {'it runs' if len(hosts) == 1 else 'they run'} {m['tier']} workloads.",
                          assets=hosts, evidence=evidence)]
    if code == "CANARY_COVERAGE":
        cov = cons.get("canary_coverage") or {}
        miss = [f"{x['label']} ({x['size']} hosts)" for x in cov.get("missing", [])]
        detail = (f"a rejected canary covered {cov['covered']}/{cov['total']} cohorts and left {'; '.join(miss)} untested"
                  if cov else msg)
        return [_rule("CANARY_COVERAGE", code, "constraints",
                      f"Build the canary from one eligible host per configuration cohort, largest cohort first: {detail}.",
                      needs="servers", args={"missing": [x["label"] for x in cov.get("missing", [])]}, evidence=evidence)]
    if code == "WAVE_SIZE" and (m := re.search(r"has (?P<n>\d+) assets; policy maximum is (?P<k>\d+)", msg)):
        return [_rule("WAVE_SIZE", code, "constraints",
                      f"Keep every wave to at most {m['k']} assets: a rejected plan had {m['n']} in wave {wave}.",
                      args={"limit": int(m["k"])}, evidence=evidence)]
    if code == "WINDOW" and (m := re.search(r"needs (?P<n>\d+) min; maintenance window is (?P<w>\d+)", msg)):
        return [_rule("WINDOW", code, "constraints",
                      f"Fit the whole plan in the {m['w']}-minute window: a rejected plan needed {m['n']} min.",
                      args={"window_min": int(m["w"])}, evidence=evidence)]
    if code == "COVERAGE":
        sub = "duplicate" if "more than once" in msg else "extra" if "outside" in msg else "missing"
        return [_rule(f"COVERAGE:{sub}", code, "constraints",
                      f"Schedule every target exactly once and nothing outside the change request: {msg}.", evidence=evidence)]
    return [_rule(f"{code}:{_slug(msg, 40)}" if code != "UNKNOWN_ASSET" else code, code, "constraints",
                  f"Avoid {code}: {msg}.", evidence=evidence)]


# ---------------------------------------------------------------- claims
def _mentioned(topo: Topology | None, text: str) -> list[str]:
    if topo is None:
        return []
    return [n for n in list(topo.servers) + list(topo.switches) if re.search(rf"\b{re.escape(n)}\b", text)]


def _from_claim(c: dict, topo: Topology | None, run_id: str) -> dict:
    t, a, why, text = c.get("type", "freeform"), c.get("args") or {}, c.get("explanation", "").strip(), c.get("text", "")
    evidence = [f"{run_id}/{e}" for e in c.get("evidence", [])]
    named = _mentioned(topo, why)
    try:
        if t == "fixes_cve":
            comp, ver, cve = a["component"], _ver(a["version"]), a["cve"].upper()
            return _rule(f"fixes_cve:{comp}:{ver}:{cve}", t, "verifier", f"Do not claim {comp} {ver} fixes {cve}: {why}",
                         components=[comp], args={"component": comp, "version": ver, "cve": cve}, evidence=evidence)
        if t == "no_known_issues":
            comp, ver = a["component"], _ver(a["version"])
            return _rule(f"no_known_issues:{comp}:{ver}", t, "verifier",
                         f"Do not claim {comp} {ver} has no known issues; cite them instead: {why}",
                         components=[comp], args={"component": comp, "version": ver}, evidence=evidence)
        if t in ("pair_safe_together", "pair_staggered"):
            x, y = sorted((a["a"], a["b"]))
            lead = (f"Never claim {x} and {y} are safe to upgrade together" if t == "pair_safe_together"
                    else f"Only claim {x} and {y} are staggered when the waves really separate them")
            return _rule(f"{t}:{x}|{y}", t, "verifier", f"{lead}: {why}", assets=[x, y], args={"a": x, "b": y}, evidence=evidence)
        if t == "all_dual_homed":
            cl = a["cluster"]
            return _rule(f"all_dual_homed:{cl}", t, "verifier", f"Do not claim all hosts in {cl} are dual-homed: {why}",
                         assets=named, clusters=[cl], args={"cluster": cl, "hosts": named}, evidence=evidence)
        if t in ("single_homed", "dual_homed"):
            s = a["server"]
            return _rule(f"{t}:{s}", t, "verifier", f"Do not claim {s} is {t.replace('_', '-')}: {why}",
                         assets=[s] + named, args={"server": s}, evidence=evidence)
        if t == "cluster_capacity":
            cl = a["cluster"]
            m = re.search(r"at most (\d+)", why)
            return _rule(f"cluster_capacity:{cl}", t, "verifier",
                         f"Do not claim {cl} can tolerate {a.get('hosts')} hosts in maintenance: {why}", clusters=[cl],
                         args={"cluster": cl, "max_down": int(m[1]) if m else None}, evidence=evidence)
        if t == "install_order":
            f, s = a["first"], a["second"]
            return _rule(f"install_order:{f}>{s}", t, "verifier", f"Do not claim {f} must be updated before {s}: {why}",
                         components=[f, s], args={"first": f, "second": s}, evidence=evidence)
    except (KeyError, TypeError):
        pass
    if t != "freeform" and t:
        # Plan-wide claims (canary_safe, no_planned_outage, per_wave_cap, in_window, ...): one generic rule per type.
        return _rule(t, t, "verifier", f"Do not claim \"{text}\" unless the plan really satisfies it: {why}",
                     assets=named, evidence=evidence)
    return _rule(f"freeform:{_slug(text)}", "freeform", "verifier", f"Do not assert \"{text}\": {why}", assets=named,
                 evidence=evidence)


# --------------------------------------------------------------- helpers
def covers(rules: Iterable[dict], *kinds: str, assets: Iterable[str] = ()) -> bool:
    """True when, for every kind, some rule warns against it (and, if given, names one of ``assets``).

    A kind is a violation code ("REDUNDANT_PAIR"), a claim type ("fixes_cve") or a key prefix
    ("PLANNED_OUTAGE:storage")."""
    rules, want = list(rules), set(assets)

    def hit(r: dict, kind: str) -> bool:
        if not (r["kind"] == kind or r["key"] == kind or r["key"].startswith(kind + ":")):
            return False
        return not want or bool(want & set(r["subject"]["assets"]))

    return bool(kinds) and all(any(hit(r, k) for r in rules) for k in kinds)


def uncovered(rules: Iterable[dict], kinds: Iterable[str]) -> list[str]:
    rules = list(rules)
    return [k for k in kinds if not covers(rules, k)]


def as_prompt(rules: Iterable[dict]) -> str:
    rules = list(rules)
    if not rules:
        return ""
    head = "Lessons from earlier rejected plans (each was checked against tool evidence; follow them):"
    return "\n".join([head] + [f"- {r['guidance']} [{r['key']}; seen {r['hits']}x]" for r in rules])


# ----------------------------------------------------------------- store
class PlanningMemory:
    """Persistent store of planning rules learned from rejected attempts."""

    def __init__(self, path: Path | str | None = None, max_rules: int = 200, clock: Callable[[], float] = time.time):
        self.path = Path(path) if path is not None else None
        self.max_rules = max_rules
        self._now = clock
        self._lock = _shared_lock(self.path)
        self._data: dict = {"version": 1, "rules": {}, "runs": []}

    @classmethod
    def from_services(cls, sv) -> "PlanningMemory":
        return cls(Path(sv.settings.runtime_dir) / FILE_NAME, max_rules=int(sv.policy.get("memory.max_rules", 200)))

    # ------------------------------------------------------------ storage
    def _load(self) -> dict:
        # Always re-read: the file is small, and another Services object (a Streamlit rerun) may have written it.
        if self.path is None or not self.path.exists():
            return self._data
        try:
            data = json.loads(self.path.read_text())
            self._data = {"version": 1, "rules": dict(data.get("rules", {})), "runs": list(data.get("runs", []))}
        except (OSError, ValueError):
            self._data = {"version": 1, "rules": {}, "runs": []}
        return self._data

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(self._data, indent=1, sort_keys=True, default=str))
        os.replace(tmp, self.path)

    # ------------------------------------------------------------- learn
    def learn(self, run_id: str, feedback: dict | None, attempt: dict, topo: Topology | None = None) -> list[dict]:
        """Turn a rejected attempt into rules. Returns the rules created or updated (with their new hit counts)."""
        if attempt.get("passed"):
            return []
        cons = attempt.get("constraints") or {}
        ev = f"{run_id}/attempt-{attempt.get('attempt', '?')}/constraint_check"
        cands = [r for v in cons.get("violations", []) for r in _from_violation(v, cons, topo, ev)]
        claims = (attempt.get("verification") or {}).get("claims")
        if claims is None:  # no structured verification: fall back to the textual feedback
            claims = [{"type": "freeform", "text": c["claim"], "explanation": c["why"], "label": "Contradicted"}
                      for c in (feedback or {}).get("contradicted_claims", [])]
        cands += [_from_claim(c, topo, run_id) for c in claims if c.get("label") == "Contradicted"]

        merged: dict[str, dict] = {}
        for r in cands:  # the same mistake in two waves of one attempt is one lesson
            if r["key"] in merged:
                m = merged[r["key"]]
                m["evidence"] = list(dict.fromkeys(m["evidence"] + r["evidence"]))
                for f in ("assets", "clusters", "components"):
                    m["subject"][f] = sorted(set(m["subject"][f]) | set(r["subject"][f]))
            else:
                merged[r["key"]] = r
        now = self._now()
        out = []
        with self._lock:
            store = self._load()["rules"]
            for key, r in merged.items():
                old = store.get(key)
                if old:
                    for f in ("assets", "clusters", "components"):
                        r["subject"][f] = sorted(set(old["subject"][f]) | set(r["subject"][f]))
                    r.update(first_seen=old["first_seen"], source_run=old["source_run"], hits=old["hits"] + 1,
                             runs=list(dict.fromkeys(old["runs"] + [run_id]))[-10:],
                             evidence=list(dict.fromkeys(r["evidence"] + old["evidence"]))[:8])
                else:
                    r.update(first_seen=now, source_run=run_id, hits=1, runs=[run_id], evidence=r["evidence"][:8])
                r["last_seen"] = now
                store[key] = r
                out.append(dict(r))
            if len(store) > self.max_rules:
                for key in sorted(store, key=lambda k: (store[k]["hits"], store[k]["last_seen"]))[: len(store) - self.max_rules]:
                    del store[key]
            self._save()
        return out

    # ---------------------------------------------------------- retrieve
    def retrieve(self, change_request: dict, targets: dict, k: int = 12, topo: Topology | None = None) -> list[dict]:
        """Rules relevant to a change: subject overlap (assets 3, clusters 2, components 1) or generic (0.5),
        ranked by relevance, then hits, then recency. Pass ``topo`` (or ``targets["clusters"]``) so that a
        change naming hosts but not clusters still matches cluster-scoped rules."""
        servers = set(targets.get("servers", [])) | set(change_request.get("target_servers", []))
        switches = set(targets.get("switches", [])) | set(change_request.get("target_switches", []))
        clusters = set(change_request.get("target_clusters", [])) | set(targets.get("clusters", []))
        if topo is not None:
            clusters |= {topo.servers[s]["cluster"] for s in servers if s in topo.servers}
        comps = set(change_request.get("components", []))
        kinds = {k_ for k_, xs in (("servers", servers), ("switches", switches)) if xs}

        def relevance(r: dict) -> float:
            s = r["subject"]
            if _is_generic(r):
                return 0.5 if s.get("needs") in (None, *kinds) else 0.0
            return (3.0 * bool(set(s["assets"]) & (servers | switches)) + 2.0 * bool(set(s["clusters"]) & clusters)
                    + 1.0 * bool(set(s["components"]) & comps))

        with self._lock:
            rules = list(self._load()["rules"].values())
        scored = [(relevance(r), r) for r in rules]
        scored = sorted([x for x in scored if x[0] > 0], key=lambda x: (-x[0], -x[1]["hits"], -x[1]["last_seen"], x[1]["key"]))
        return [dict(r, relevance=s) for s, r in scored[:k]]

    # ------------------------------------------------------------- stats
    def record_run(self, run_id: str, first_attempt_passed: bool, attempts: int, rules_retrieved: int) -> None:
        row = {"run_id": run_id, "ts": self._now(), "first_attempt_passed": bool(first_attempt_passed),
               "attempts": int(attempts), "rules_retrieved": int(rules_retrieved)}
        with self._lock:
            data = self._load()
            data["runs"] = [r for r in data["runs"] if r["run_id"] != run_id][-499:] + [row]
            self._save()

    def stats(self, top: int = 5) -> dict:
        with self._lock:
            data = self._load()
            runs, rules = list(data["runs"]), list(data["rules"].values())

        def summary(rs: list[dict]) -> dict:
            n = len(rs)
            passed = sum(r["first_attempt_passed"] for r in rs)
            return {"runs": n, "first_attempt_passed": passed,
                    "first_attempt_pass_rate": round(passed / n, 3) if n else None,
                    "avg_attempts": round(sum(r["attempts"] for r in rs) / n, 2) if n else None}

        ranked = sorted(rules, key=lambda r: (-r["hits"], -r["last_seen"], r["key"]))
        return {**summary(runs),
                "with_memory": summary([r for r in runs if r["rules_retrieved"] > 0]),
                "without_memory": summary([r for r in runs if r["rules_retrieved"] == 0]),
                "rules": len(rules),
                "rules_by_source": {s: sum(1 for r in rules if r["source"] == s) for s in ("constraints", "verifier")},
                "top_rules": [{k: r[k] for k in ("key", "hits", "guidance", "last_seen")} for r in ranked[:top]]}

    def rules(self) -> list[dict]:
        with self._lock:
            return sorted((dict(r) for r in self._load()["rules"].values()), key=lambda r: (-r["hits"], r["key"]))

    def clear(self) -> None:
        with self._lock:
            self._data = {"version": 1, "rules": {}, "runs": []}
            self._save()
