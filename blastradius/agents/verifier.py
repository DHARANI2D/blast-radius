"""Verifier (critic) agent: anti-hallucination gate.

1. A separate model/prompt at temperature 0 splits the Planner's rationale into
   atomic, typed claims.
2. Each typed claim is checked by a deterministic checker that gathers its *own*
   evidence through MCP tools (the Verifier never reuses the Planner's inputs).
   Untyped ("freeform") claims go to an LLM judge that may only cite retrieved
   evidence and defaults to Unverifiable.
3. Trust Score = evidence-weighted share of supported claims, minus a penalty
   per contradicted claim. Safety claims weigh more than factual claims, which
   weigh more than informational ones.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from ..cohorts import build as build_cohorts, coverage
from ..constraints import impact_kwargs, wave_duration
from ..llm import LLMError, load_prompt
from ..mcp_layer import ToolCallError
from ..models import ClaimList, Judgement
from ..offline_llm import _sentences
from ..topology import Topology

SAFETY_RE = re.compile(r"\b(safe(?:ly|ty)?|(?:no|zero) (?:[\w-]+ )?(?:impact|outage|risk|downtime|interruption|disruption|data loss)|"
                       r"without (?:any )?(?:[\w-]+ )?(?:impact\w*|affecting|disrupt\w*|downtime|interrupt\w*|outage|loss)|"
                       r"(?:un|not |never )(?:affected|impacted|disrupted|interrupted)|non-?disruptive\w*|hitless|seamless\w*|"
                       r"concurrent\w*|simultaneous\w*|at once|at the same time|in parallel|"
                       r"redundan\w*|dual[- ]homed|single[- ]homed|"
                       r"fail ?over|capacity|tolerat\w*|outage|isolat\w*|quorum|evacuat\w*|tier[- ]?0|canary|roll ?back|"
                       r"(?:will not|won't|cannot|can't|does not|doesn't|do not|don't) (?:break|fail|disrupt|affect|impact|interrupt))\b", re.I)

CATEGORY = {
    "pair_safe_together": "safety", "pair_staggered": "safety", "all_dual_homed": "safety",
    "dual_homed": "safety", "single_homed": "safety", "cluster_capacity": "safety", "per_wave_cap": "safety",
    "canary_safe": "safety", "no_planned_outage": "safety", "canary_covers_cohorts": "safety",
    "fixes_cve": "factual", "no_known_issues": "factual", "install_order": "factual",
    "in_window": "informational", "freeform": "informational",
}


WORD_RE = re.compile(r"[a-z0-9]+(?:[.\-/][a-z0-9]+)*")
STOPWORDS = {"a", "an", "the", "and", "or", "of", "in", "on", "to", "is", "are", "be", "by", "for", "with", "so", "it", "its",
             "this", "that", "as", "at", "all", "each", "every", "per", "from", "into", "than", "then", "will", "can", "has", "have"}
CVE_RE = re.compile(r"(?:syn-)?cve-\d{4}-\d+", re.I)


def _words(text: str) -> set[str]:
    return {w for w in WORD_RE.findall(text.lower()) if w not in STOPWORDS}


def uncovered_sentences(rationale: str, claims: list[dict]) -> list[str]:
    """Rationale sentences no extracted claim accounts for.

    A claim belongs to a sentence when at least half of its words (text plus arguments) occur in it.
    The sentence is covered when the claims that belong to it name half of its words and every CVE
    it mentions, so an extractor that silently drops a sentence, or half of one, cannot hide it.
    """
    bags = [_words(c["text"] + " " + " ".join(str(v) for v in (c.get("args") or {}).values())) for c in claims]
    out = []
    for s in _sentences(rationale):
        words = _words(s)
        if not words:
            continue
        mine = set().union(*[b for b in bags if b and len(b & words) >= 0.5 * len(b)]) & words
        cves = {x.lower() for x in CVE_RE.findall(s)}
        if len(mine) < 0.5 * len(words) or not cves <= mine:
            out.append(s)
    return out


class VerifierAgent:
    name = "verifier"

    def __init__(self, sv):
        self.sv = sv
        self._cache: dict = {}
        self._judge_errors: list[tuple[str, str]] = []
        self._llm_calls: list[dict] = []

    # ------------------------------------------------------------ helpers
    def call(self, tool: str, **args):
        key = (tool, json.dumps(args, sort_keys=True, default=str))
        if key not in self._cache:
            self._cache[key] = self.sv.bus.call(self.name, tool, **args)
        return self._cache[key]

    def _resolve_version(self, component: str, version) -> str:
        v = str(version).strip()  # a model may write 1.64 as a JSON number
        known = [r["version"] for r in self.sv.kb.release_notes if r["component"] == component]
        for cand in (v, v.lstrip("vV"), v.replace("version ", "")):
            if cand in known:
                return cand
        tail = [k for k in known if k.endswith(v.lstrip("vV"))]
        return tail[0] if tail else v

    def _inventory_name(self, tool: str, name: str) -> tuple[str | None, str]:
        """Resolve a server or cluster name against the (complete) inventory, ignoring case."""
        items, ev = self.call(tool)
        names = {x["name"].lower(): x["name"] for x in items}
        return names.get(str(name).strip().lower()), ev

    def _uplinks(self) -> tuple[dict[str, set[str]], str]:
        lldp, ev = self.call("network.get_lldp_neighbors")
        ups: dict[str, set[str]] = {}
        for p in lldp:
            if p["status"] == "up" and p.get("neighbor"):
                ups.setdefault(p["neighbor"], set()).add(p["switch"])
        return ups, ev

    # ------------------------------------------------------------ checkers
    def check(self, claim: dict, ctx: dict) -> tuple[str, str, list[str]]:
        fn = getattr(self, f"_c_{claim['type']}", None)
        if fn is None or claim["type"] == "freeform":
            return self._c_freeform(claim, ctx)
        try:
            return fn(claim["args"], ctx)
        except ToolCallError as exc:  # one bad claim must not abort the whole verification
            return "Unverifiable", f"evidence could not be gathered ({exc})", [exc.evidence_id]
        except Exception as exc:  # oddly typed or missing arguments: this claim is unchecked, the rest still are
            return "Unverifiable", f"checker could not evaluate: {type(exc).__name__}: {exc}", []

    def _c_fixes_cve(self, a, ctx):
        comp, cve = a["component"], a["cve"]
        ver = self._resolve_version(comp, a["version"])
        rn, e1 = self.call("knowledge.get_release_notes", component=comp, version=ver)
        advs, e2 = self.call("knowledge.list_advisories", cve=cve)
        if rn.get("found") is not False and cve in rn.get("security_fixes", []):
            return "Supported", f"{rn['id']} lists {cve} among its security fixes.", [e1]
        here = [x for x in advs if ((x.get("fixed_in") or {}).get("component"), (x.get("fixed_in") or {}).get("version")) == (comp, ver)]
        if here:
            return "Supported", f"{here[0]['id']} says {cve} is fixed in {comp} {ver}.", [e2]
        elsewhere = [x for x in advs if x.get("fixed_in")]  # each names a different fixed-in component/version
        detail = "; ".join(f"{x['id']} says {cve} is fixed in {x['fixed_in']['component']} {x['fixed_in']['version']}" for x in elsewhere)
        if rn.get("found") is not False and rn.get("security_fixes_complete"):
            msg = f"{rn['id']} lists security fixes {', '.join(rn['security_fixes'])}; {cve} is not among them"
            return "Contradicted", msg + (f". {detail}." if detail else "."), [e1, e2]
        if elsewhere:
            return "Contradicted", detail + ".", [e2]
        return "Unverifiable", f"no release notes or advisory link {comp} {ver} to {cve}.", [e1, e2]

    def _c_no_known_issues(self, a, ctx):
        comp = a["component"]
        ver = self._resolve_version(comp, a["version"])
        rn, e1 = self.call("knowledge.get_release_notes", component=comp, version=ver)
        advs, e2 = self.call("knowledge.list_advisories", component=comp, version=ver)
        incs, e3 = self.call("knowledge.list_incidents", component=comp, version=ver, model=a.get("model", ""))
        issues = [ki["id"] for ki in rn.get("known_issues", [])] + [x["id"] for x in advs] + [i["id"] for i in incs]
        if issues:
            return "Contradicted", f"{comp} {ver} has open issues: {', '.join(issues)}.", [e1, e2, e3]
        if rn.get("found") is False:
            return "Unverifiable", f"no release notes for {comp} {ver}.", [e1]
        return "Supported", f"{rn['id']} lists no known issues and no advisory or incident matches.", [e1, e2, e3]

    def _known_pair(self, a) -> tuple[dict | None, str, str]:
        """Resolve both switch names against the network inventory (unknown names used to crash get_switch)."""
        x, ev = self._inventory_name("network.list_switches", a["a"])
        y, _ = self._inventory_name("network.list_switches", a["b"])
        missing = a["a"] if x is None else a["b"] if y is None else ""
        return (None if missing else {**a, "a": x, "b": y}), ev, missing

    def _c_pair_safe_together(self, a, ctx):
        topo: Topology = ctx["topo"]
        known, e0, missing = self._known_pair(a)
        if known is None:
            return "Contradicted", f"the network inventory has no switch named {missing}.", [e0]
        a = known
        sw, e1 = self.call("network.get_switch", name=a["a"])
        peer = (sw.get("redundancy") or {}).get("peer")
        imp = topo.simulate([a["a"], a["b"]], [], **impact_kwargs(self.sv.policy))
        e2 = self.sv.evidence.add(self.name, "blastradius.simulate", {"down_switches": [a["a"], a["b"]]},
                                  {k: imp[k] for k in ("impacted_vms", "critical_vms", "isolated_servers", "arrays_unreachable", "brs")})
        ev = [e1, e2]
        tv = ctx["target_versions"].get(a["a"], {}).get("Switch OS")
        note = ""
        if tv:
            rn, e3 = self.call("knowledge.get_release_notes", component="Switch OS", version=tv)
            ev.append(e3)
            if "one member at a time" in rn.get("install_notes", ""):
                note = f" {rn['id']}: VSX pairs must be upgraded one member at a time."
        if imp["impacted_vms"]:
            return ("Contradicted", f"{a['a']} and {a['b']} are {'redundant peers' if peer == a['b'] else 'switches'} carrying the same hosts; "
                    f"with both down, {len(imp['impacted_vms'])} VMs lose service (incl. {', '.join(imp['critical_vms'][:3]) or 'none tier-0'}).{note}", ev)
        if note and peer == a["b"]:
            return "Contradicted", note.strip(), ev
        return "Supported", "simulation shows no workload impact with both switches down.", ev

    def _c_pair_staggered(self, a, ctx):
        known, e0, missing = self._known_pair(a)
        if known is None:
            return "Contradicted", f"the network inventory has no switch named {missing}.", [e0]
        a = known
        sw, e1 = self.call("network.get_switch", name=a["a"])
        where = {x: [i for i, w in enumerate(ctx["plan"]["waves"], 1) if x in w["assets"]] for x in (a["a"], a["b"])}
        if not where[a["a"]] or not where[a["b"]]:
            return "Unverifiable", f"plan does not schedule both {a['a']} and {a['b']}.", [e1]
        if set(where[a["a"]]) & set(where[a["b"]]):
            return "Contradicted", f"plan puts {a['a']} and {a['b']} in the same wave.", [e1]
        return "Supported", f"{a['a']} is in wave {where[a['a']][0]}, {a['b']} in wave {where[a['b']][0]}; peer of {a['a']} is {(sw.get('redundancy') or {}).get('peer')}.", [e1]

    def _c_all_dual_homed(self, a, ctx):
        clusters, e1 = self.call("virt.list_clusters")
        ups, e2 = self._uplinks()
        cl = next((c for c in clusters if c["name"].lower() == str(a["cluster"]).strip().lower()), None)
        if not cl:
            return "Contradicted", f"the virtualization inventory has no cluster named {a['cluster']}.", [e1]
        single = [h for h in cl["hosts"] if len(ups.get(h, set())) < 2]
        if single:
            return "Contradicted", f"LLDP shows {', '.join(single)} with fewer than two live uplinks.", [e1, e2]
        return "Supported", f"all {len(cl['hosts'])} hosts have two live uplinks in LLDP.", [e1, e2]

    def _homed(self, server, want_single):
        # A name the inventory does not know has no LLDP neighbours either; without this
        # check a hallucinated host would read as "single-homed" and be Supported.
        name, e0 = self._inventory_name("compute.list_servers", server)
        if name is None:
            return "Contradicted", f"the compute inventory has no server named {server}.", [e0]
        server = name
        ups, ev = self._uplinks()
        n = len(ups.get(server, set()))
        is_single = n < 2
        label = "Supported" if is_single == want_single else "Contradicted"
        return label, f"LLDP shows {n} live uplink(s) for {server}: {', '.join(sorted(ups.get(server, []))) or 'none'}.", [ev]

    def _c_single_homed(self, a, ctx):
        return self._homed(a["server"], True)

    def _c_dual_homed(self, a, ctx):
        return self._homed(a["server"], False)

    def _cluster_max_down(self, cluster: str) -> tuple[int, list[str]]:
        clusters, e1 = self.call("virt.list_clusters")
        vms, e2 = self.call("virt.list_vms", cluster=cluster)
        servers, e3 = self.call("compute.list_servers", cluster=cluster)
        cl = next(c for c in clusters if c["name"] == cluster)
        demand = sum(v["memoryGB"] for v in vms)
        per_host = sum(s["memoryGB"] for s in servers) / max(1, len(servers))
        limit = cl.get("maxMemoryUtilPct", 85) / 100
        max_down = max([k for k in range(len(servers)) if demand <= limit * per_host * (len(servers) - k)], default=0)
        return max_down, [e1, e2, e3]

    def _c_cluster_capacity(self, a, ctx):
        cluster, e0 = self._inventory_name("virt.list_clusters", a["cluster"])
        if cluster is None:  # previously raised StopIteration and aborted the whole verification
            return "Contradicted", f"the virtualization inventory has no cluster named {a['cluster']}.", [e0]
        max_down, ev = self._cluster_max_down(cluster)
        n = int(a["hosts"])
        if n <= max_down:
            return "Supported", f"{cluster} can absorb up to {max_down} hosts in maintenance at its utilisation ceiling.", ev
        return "Contradicted", f"{cluster} can absorb at most {max_down} hosts in maintenance; {n} would overload it.", ev

    def _c_per_wave_cap(self, a, ctx):
        topo: Topology = ctx["topo"]
        worst = 0
        for w in ctx["plan"]["waves"]:
            c = Counter(topo.servers[h]["cluster"] for h in w["assets"] + w.get("evacuate", []) if h in topo.servers)
            worst = max([worst] + list(c.values()))
        servers, e1 = self.call("compute.list_servers")
        if worst <= int(a["hosts"]):
            return "Supported", f"the busiest wave has {worst} hosts of one cluster in maintenance.", [e1]
        return "Contradicted", f"a wave has {worst} hosts of one cluster in maintenance.", [e1]

    def _c_canary_safe(self, a, ctx):
        waves = ctx["plan"]["waves"]
        if not waves:
            return "Unverifiable", "plan has no waves.", []
        topo: Topology = ctx["topo"]
        max_assets = int(self.sv.policy.get("planning.canary_max_assets", 2))
        min_tier = int(self.sv.policy.get("planning.canary_max_tier", 2))
        ev, bad = [], []
        for h in waves[0]["assets"]:
            if h in topo.switches:
                bad.append(f"{h} is a switch")
                continue
            vms, e = self.call("virt.list_vms", host=h)
            ev.append(e)
            crit = [v["name"] for v in vms if v["tier"] < min_tier]
            if crit:
                bad.append(f"{h} runs {', '.join(crit[:3])}")
        if len(waves[0]["assets"]) > max_assets:
            bad.append(f"{len(waves[0]['assets'])} assets (limit {max_assets})")
        if bad:
            return "Contradicted", "canary is not safe: " + "; ".join(bad) + ".", ev
        return "Supported", f"canary {', '.join(waves[0]['assets'])} runs only tier-{min_tier}+ workloads.", ev

    def _c_canary_covers_cohorts(self, a, ctx):
        """Rebuild the configuration cohorts from inventory the Verifier fetches itself, then check the canary."""
        waves = ctx["plan"]["waves"]
        topo: Topology = ctx["topo"]
        if not waves:
            return "Unverifiable", "plan has no waves.", []
        servers, e1 = self.call("compute.list_servers")
        info = {s["name"]: s for s in servers}
        scheduled = [x for w in waves for x in w["assets"] if x in info]
        cohorts = build_cohorts(scheduled, info, ctx["cr"]["components"])
        cov = coverage([x for x in waves[0]["assets"] if x in info], cohorts, topo, self.sv.policy)
        e2 = self.sv.evidence.add(self.name, "blastradius.cohort_coverage", {"canary": waves[0]["assets"]},
                                  {k: cov[k] for k in ("covered", "total", "required", "missing", "hosts_represented", "hosts_total")})
        claimed = a.get("cohorts")
        if isinstance(claimed, str) and claimed.strip().lower() in ("all", "every", "each"):
            claimed = None  # "every cohort" is what coverage['ok'] checks below
        if not cov["ok"]:
            return ("Contradicted", f"canary covers {cov['covered']} of {cov['total']} configuration cohorts; untested: "
                    + "; ".join(f"{m['label']} ({m['size']} hosts)" for m in cov["missing"]) + ".", [e1, e2])
        if claimed is not None and int(claimed) not in (cov["required"], cov["total"]):
            return "Contradicted", f"inventory shows {cov['total']} cohorts ({cov['required']} required in the canary), not {claimed}.", [e1, e2]
        return ("Supported", f"inventory groups the {len(scheduled)} scheduled hosts into {cov['total']} cohorts; the canary covers "
                f"{cov['covered']} ({cov['hosts_represented']}/{cov['hosts_total']} hosts represented).", [e1, e2])

    def _c_no_planned_outage(self, a, ctx):
        topo: Topology = ctx["topo"]
        bad = []
        for i, w in enumerate(ctx["plan"]["waves"], 1):
            sw = [x for x in w["assets"] if x in topo.switches]
            hosts = [x for x in w["assets"] + w.get("evacuate", []) if x in topo.servers]
            imp = topo.simulate(sw, hosts, **impact_kwargs(self.sv.policy))
            if imp["impacted_vms"]:
                bad.append((i, len(imp["impacted_vms"])))
        e = self.sv.evidence.add(self.name, "blastradius.simulate", {"plan_waves": len(ctx["plan"]["waves"])}, {"waves_with_outage": bad})
        if bad:
            return "Contradicted", "simulation finds outages in " + ", ".join(f"wave {i} ({n} VMs)" for i, n in bad) + ".", [e]
        return "Supported", "independent re-simulation of every wave finds no workload outage.", [e]

    def _stated_order(self, first: str, second: str, ctx) -> tuple[str | None, list[str]]:
        """Release-note sentence saying ``first`` is updated before ``second``, if any."""
        versions = {v.get(second) for v in ctx["target_versions"].values() if v.get(second)}
        ev = []
        for ver in sorted(versions):
            rn, e = self.call("knowledge.get_release_notes", component=second, version=ver)
            ev.append(e)
            text = (rn.get("install_notes", "") + " " + rn.get("text", "")).lower()
            if f"update {first.lower()} before {second.lower()}" in text or f"update {first.lower().split()[0]} first" in text:
                return f"{rn['id']} instructs updating {first} before {second}.", ev
        for r in self.sv.kb.release_notes:
            if r["component"] == first and f"before {second.lower()}" in r.get("install_notes", "").lower():
                rn, e = self.call("knowledge.get_release_notes", component=first, version=r["version"])
                return f"{rn['id']}: {rn['install_notes']}", ev + [e]
        return None, ev

    def _c_install_order(self, a, ctx):
        first, second = a["first"], a["second"]
        said, ev = self._stated_order(first, second, ctx)
        if said:
            return "Supported", said, ev
        # The notes may state the opposite order, which contradicts the claim.
        said, ev2 = self._stated_order(second, first, ctx)
        if said:
            return "Contradicted", f"the release notes give the opposite order: {said}", ev + ev2
        return "Unverifiable", f"release notes do not state an order for {first} and {second}.", ev + ev2

    def _c_in_window(self, a, ctx):
        topo: Topology = ctx["topo"]
        comps = ctx["cr"]["components"]
        total = sum(wave_duration(w["assets"], w.get("evacuate", []), topo, comps, self.sv.policy) for w in ctx["plan"]["waves"])
        window = ctx["cr"]["window"]["duration_minutes"]
        claimed = int(a["minutes"])
        e = self.sv.evidence.add(self.name, "blastradius.duration", {"waves": len(ctx["plan"]["waves"])}, {"computed_min": total, "window_min": window})
        if total > window:
            return "Contradicted", f"computed duration {total} min exceeds the {window}-min window.", [e]
        if abs(claimed - total) > 0.35 * total:
            return "Contradicted", f"claimed {claimed} min but the plan computes to {total} min (window {window}).", [e]
        return "Supported", f"computed {total} min, within the {window}-min window.", [e]

    def _c_freeform(self, claim, ctx):
        hits, e = self.call("knowledge.search", query=claim["text"], k=3)
        # Evidence the sentence itself cites (e.g. an Investigator answer: "... [EV-0042].") goes to the judge first.
        cited_ids = [x for x in dict.fromkeys(re.findall(r"EV-\d{4}", claim["text"])) if self.sv.evidence.get(x)]
        evidence = cited_ids + [e]
        user = json.dumps({"claim": claim["text"], "evidence": [self.sv.evidence.summary(x, 3000 if x in cited_ids else 1200) for x in evidence]})
        try:
            j: Judgement = self.sv.verifier_llm.complete_json(
                "verifier_judge", load_prompt("verifier_judge"), user, Judgement,
                context={"claim": claim["text"], "hits": hits,
                         "cited": [{"id": x, "result": json.dumps(self.sv.evidence.get(x)["result"], default=str)} for x in cited_ids]},
                temperature=0.0)
        except LLMError as exc:  # fail closed: no judgement is no support
            self._judge_errors.append((claim["text"], str(exc)[:300]))
            return "Unverifiable", f"judge unavailable (LLM failed: {str(exc)[:200]}).", evidence
        self._llm_calls.append(self.sv.verifier_llm.last())
        # Only evidence the judge was given for this claim counts; any other id in the store is dropped.
        cited = [x for x in dict.fromkeys(j.evidence) if x in evidence]
        if j.label != "Unverifiable" and not cited:
            dropped = [x for x in j.evidence if x not in evidence]
            return "Unverifiable", (f"judge answered {j.label} citing only evidence it was not given ({', '.join(dropped[:3])}); downgraded."
                                    if dropped else f"judge answered {j.label} without citing evidence; downgraded."), evidence
        return j.label, j.explanation, cited or evidence

    # -------------------------------------------------------------- run
    def run(self, plan: dict, cr: dict, topo: Topology, risk: dict) -> dict:
        self._cache.clear()
        self._judge_errors, self._llm_calls = [], []
        pol = self.sv.policy
        user = json.dumps({"rationale": plan["rationale"], "switches": list(topo.switches), "clusters": list(topo.clusters)})
        ext_ctx = {"rationale": plan["rationale"], "switch_names": list(topo.switches)}
        fallbacks = []
        extractor = "offline stand-in (rule-based)" if self.sv.settings.offline else f"llm:{self.sv.verifier_llm.model}"
        try:
            extracted: ClaimList = self.sv.verifier_llm.complete_json(
                "verifier_extract", load_prompt("verifier_extract"), user, ClaimList, context=ext_ctx, temperature=0.0)
            self._llm_calls.append(self.sv.verifier_llm.last())
        except LLMError as exc:
            # The rule-based extractor still types every sentence it recognises; the rest stay freeform and
            # go to the judge, so the gate keeps checking the rationale instead of crashing.
            from ..offline_llm import extract_claims

            extracted = ClaimList.model_validate(extract_claims(ext_ctx))
            err = str(exc)[:300]
            extractor = f"extractor fallback: rule-based extractor (LLM failed: {err})"
            fallbacks.append({"role": "verifier_extract", "error": err, "fallback": "rule-based extractor"})
        ctx = {"plan": plan, "cr": cr, "topo": topo, "target_versions": risk["target_versions"]}
        weights = pol.get("verification.claim_weights", {})
        values = pol.get("verification.label_values", {})
        # Every sentence must be accounted for: one the extractor left out is judged as a freeform claim.
        extracted_claims = [c.model_dump() for c in extracted.claims]
        n_sent = len(_sentences(plan["rationale"]))
        missed = uncovered_sentences(plan["rationale"], extracted_claims)
        coverage_ = {"sentences": n_sent, "covered": n_sent - len(missed), "uncovered": missed}
        claims = []
        for i, cd in enumerate(extracted_claims + [{"text": s, "type": "freeform", "args": {}} for s in missed], 1):
            label, why, ev = self.check(cd, ctx)
            cat = CATEGORY.get(cd["type"], "informational")
            claims.append({"id": f"C{i}", **cd, "category": cat, "weight": weights.get(cat, 1), "label": label,
                           "explanation": why, "evidence": ev})
        if self._judge_errors:
            fallbacks.append({"role": "verifier_judge", "error": self._judge_errors[0][1],
                              "fallback": f"{len(self._judge_errors)} claim(s) marked Unverifiable (judge unavailable)",
                              "claims": [t for t, _ in self._judge_errors]})
        tw = sum(c["weight"] for c in claims)
        share = (sum(c["weight"] * values.get(c["label"], 0) for c in claims) / tw) if tw else 0.5
        n_contra = sum(1 for c in claims if c["label"] == "Contradicted")
        trust = max(0.0, min(100.0, 100 * share - float(pol.get("verification.contradiction_penalty", 15)) * n_contra))
        threshold = float(pol.get("verification.trust_threshold", 80))
        blocked_by = []
        # A safety claim that could not be checked must not slip through just because Unverifiable only lowers
        # the score: a typed safety claim, or an untyped sentence that sounds like a safety guarantee.
        for c in claims:
            c["safety_language"] = c["type"] == "freeform" and bool(SAFETY_RE.search(c["text"]))
        unchecked_safety = [c for c in claims if (c["category"] == "safety" or c["safety_language"]) and c["label"] == "Unverifiable"]
        if unchecked_safety and pol.get("verification.block_unverified_safety_claims", True):
            blocked_by.append(f"{len(unchecked_safety)} safety claim(s) no evidence could check")
        if trust < threshold:
            blocked_by.append(f"Trust Score {trust:.0f} < {threshold:.0f}")
        if n_contra and pol.get("verification.block_on_contradiction", True):
            blocked_by.append(f"{n_contra} contradicted claim(s)")
        return {
            "claims": claims,
            "trust_score": round(trust, 1),
            "self_confidence": plan.get("self_confidence"),
            "counts": dict(Counter(c["label"] for c in claims)),
            "passed": not blocked_by,
            "blocked_by": blocked_by,
            "verifier_model": self.sv.verifier_llm.model,
            "independent_model": self.sv.verifier_llm.model != self.sv.llm.model,
            "extractor": extractor,
            "extraction_coverage": coverage_,
            "llm_fallbacks": fallbacks,
            "llm_calls": list(self._llm_calls),
        }
