"""Risk-aware wave optimizer.

The solver (solver.py) is greedy and feasible-first: it fills waves in a fixed
order and stops at the first plan that passes ``constraints.check_plan``. It
schedules the switch waves straight after the canary, so the riskiest asset of
the change (here ``tor-r1-a``, which also carries a single-homed tier-0 host)
goes out when the least evidence exists. This module improves a feasible plan
under exactly the same hard constraints.

Objective (lower is better; weights come from ``optimizer.*`` in policy.yaml)::

    J = duration_min + w_brs * sum_k BRS_k + w_exposure * exposure + w_waves * n_waves

* ``duration_min``: sum of ``constraints.wave_duration`` over the waves.
* ``BRS_k``: Blast-Radius Score of wave k, from the same simulation the
  constraints use (``constraints.wave_impact``).
* ``exposure`` (progressive exposure): each scheduled asset ``a`` has a weight
  ``r(a) = risk(a) / 100 + tier0_weight * [a carries tier-0 workloads]`` (a host
  runs a tier-0 VM, or a switch is an uplink of a host that does) and is charged
  the share of the plan that is still unvalidated when its wave starts::

      exposure = sum_k sum_{a in wave k} r(a) * (1 - V_{k-1} / N)

  where ``V_{k-1}`` is the number of assets in waves 1..k-1 and ``N`` the number
  of scheduled assets. High-risk and tier-0 assets are cheap late, once earlier
  waves have produced evidence, and expensive early.
* ``n_waves``: every wave is another hand-off, soak and approval step.

Search: seeded simulated annealing over six moves (move a host, swap two hosts,
move or swap a switch, reorder waves, split a wave, merge two waves). Wave 1,
the cohort-covering canary, never changes. A switch moves together with the
hosts single-homed to it (or with their evacuation entries) and is never placed
in its VSX/MC-LAG peer's wave.

Feasibility uses the per-wave rules of ``check_plan`` (redundant pair, cluster
capacity, wave size, simulated outage) plus the window, cached by wave
contents. The simulation is the expensive part, so it only runs for candidates
the annealing would accept: a wave without an outage migrates every VM on its
hosts, so its BRS, and therefore the candidate's objective, is known exactly
before simulating. The best plan is re-checked with the full ``check_plan``; if
it is not strictly better, or the check fails, the input plan is returned
unchanged.

The optimised plan keeps the planner's rationale, whose claims name wave
contents ("blr-esx-07 is scheduled in the same wave as tor-r1-a"), so it must
go through the Verifier again; ``regrounded`` rebuilds the solver's grounded
rationale from the new waves for the deterministic-solver path.
"""

from __future__ import annotations

import math
import random
import time
from collections import Counter

from .constraints import check_plan, impact_kwargs, wave_duration, wave_impact
from .policy import Policy
from .solver import grounded_rationale, plan_facts
from .topology import Topology

KINDS = ("move", "swap", "move_switch", "reorder", "split", "merge")
KIND_WEIGHTS = (0.30, 0.30, 0.12, 0.13, 0.10, 0.05)
T_START, T_END = 3.0, 0.02  # annealing temperature, in objective units (minutes)
PLATEAU_P = 0.2              # chance of taking a move that leaves the objective unchanged


def objective_weights(policy: Policy) -> dict[str, float]:
    return {
        "w_brs": float(policy.get("optimizer.w_brs", 1.0)),
        "w_exposure": float(policy.get("optimizer.w_exposure", 30.0)),
        "w_waves": float(policy.get("optimizer.w_waves", 10.0)),
        "tier0_weight": float(policy.get("optimizer.tier0_weight", 1.0)),
    }


def asset_weights(assets: list[str], topo: Topology, scores: dict[str, float], tier0_weight: float) -> dict[str, float]:
    """r(a): normalised risk plus a bonus for assets that carry tier-0 workloads."""
    out = {}
    for a in assets:
        if a in topo.servers:
            tier0 = topo.most_critical_tier(a) == 0
        else:
            tier0 = any(topo.most_critical_tier(h) == 0 for h in topo.servers_depending_on(a))
        out[a] = float(scores.get(a, 0)) / 100 + tier0_weight * tier0
    return out


def _scores(risk: dict) -> dict[str, float]:
    if isinstance(risk.get("assets"), dict):
        return {a: r["score"] for a, r in risk["assets"].items()}
    return {a: float(v) for a, v in risk.items()}


def _names(items) -> list[str]:
    return [d["asset"] if isinstance(d, dict) else d for d in items]


def _copy(waves: list[dict]) -> list[dict]:
    return [{"assets": list(w["assets"]), "evacuate": list(w.get("evacuate", []))} for w in waves]


def _key(w: dict) -> tuple:
    return tuple(w["assets"]), tuple(w["evacuate"])


class _Model:
    """Per-wave rules of check_plan and the objective, cached by wave contents (order matters to evacuation)."""

    def __init__(self, topo: Topology, policy: Policy, components: list[str], window: int, r: dict[str, float], wts: dict):
        self.topo, self.policy, self.components, self.window, self.r, self.wts = topo, policy, components, window, r, wts
        per_cluster = int(policy.get("planning.max_parallel_per_cluster", 5))
        self.cap = {c: min(per_cluster, topo.cluster_capacity(c)["max_hosts_down"]) for c in topo.clusters}
        self.wave_max = int(policy.get("planning.max_assets_per_wave", 12))
        kw = impact_kwargs(policy)
        tw = {int(k): float(v) for k, v in kw["tier_weights"].items()}
        self.migrated_weight, self.brs_scale = kw["migrated_weight"], kw["brs_scale"]
        self.host_weight = {h: sum(tw.get(v["tier"], 1) for v in topo.vms_on(h)) for h in topo.servers}
        self.cheap: dict[tuple, dict] = {}
        self.sim: dict[tuple, dict] = {}

    def rules(self, w: dict) -> dict:
        """Cheap rules, duration, and the BRS the wave has if the simulation finds no outage."""
        key = _key(w)
        if key not in self.cheap:
            topo, assets, evac = self.topo, w["assets"], w["evacuate"]
            sw = [a for a in assets if a in topo.switches]
            hosts = [a for a in assets + evac if a in topo.servers]
            by_cluster = Counter(topo.servers[h]["cluster"] for h in hosts)
            ok = (len(assets) <= self.wave_max and len(set(hosts)) == len(hosts)
                  and all(a in topo.servers or a in topo.switches for a in assets)
                  and not any(topo.peer_of(s) in sw for s in sw)
                  and all(n <= self.cap[c] for c, n in by_cluster.items()))
            # No outage means every VM on the wave's hosts is live-migrated, so BRS is known in closed form.
            weight = self.migrated_weight * sum(self.host_weight[h] for h in hosts)
            self.cheap[key] = {"ok": ok, "duration": wave_duration(assets, evac, topo, self.components, self.policy),
                               "brs": round(100 * (1 - math.exp(-weight / self.brs_scale)), 1)}
        return self.cheap[key]

    def simulate(self, w: dict) -> dict:
        key = _key(w)
        if key not in self.sim:
            imp = wave_impact(w, self.topo, self.policy)
            self.sim[key] = {"ok": not imp["impacted_vms"], "brs": imp["brs"]}
        return self.sim[key]

    def evaluate(self, waves: list[dict], simulate: bool = True) -> dict | None:
        """Objective breakdown, or None if a wave breaks a rule or the plan overruns the window.

        With ``simulate=False`` only the cheap rules run and the result is what the plan scores if no wave has
        a simulated outage (exact in that case)."""
        parts = [self.rules(w) for w in waves]
        duration = sum(p["duration"] for p in parts)
        if duration > self.window or not all(p["ok"] for p in parts):
            return None
        if simulate:
            parts = [self.simulate(w) for w in waves]
            if not all(p["ok"] for p in parts):
                return None
        n = sum(len(w["assets"]) for w in waves) or 1
        exposure, done = 0.0, 0
        for w in waves:
            exposure += (1 - done / n) * sum(self.r.get(a, 0.0) for a in w["assets"])
            done += len(w["assets"])
        sum_brs = sum(p["brs"] for p in parts)
        wt = self.wts
        terms = {"duration": float(duration), "brs": wt["w_brs"] * sum_brs, "exposure": wt["w_exposure"] * exposure,
                 "waves": wt["w_waves"] * len(waves)}
        return {"J": round(sum(terms.values()), 3), "duration_min": duration, "sum_brs": round(sum_brs, 1),
                "max_brs": max((p["brs"] for p in parts), default=0.0), "exposure": round(exposure, 3),
                "waves": len(waves), "terms": {k: round(v, 2) for k, v in terms.items()}}


class _Moves:
    """Neighbourhood of a plan. Wave index 0 (the canary) is never touched."""

    def __init__(self, topo: Topology, rng: random.Random, glued_to: dict[str, str], r: dict[str, float]):
        self.topo, self.rng, self.glued_to, self.r = topo, rng, glued_to, r
        biggest = {h: max([v["memoryGB"] for v in topo.vms_on(h)], default=0) for h in topo.servers}
        # Switches first, then hosts with the biggest VMs: hosts enter maintenance (and are evacuated) in list
        # order, and placing the largest VMs while the cluster is emptiest is what lets a wave fit.
        self.order = lambda a: (0, 0, a) if a in topo.switches else (1, -biggest.get(a, 0), a)

    def tidy(self, waves: list[dict]) -> list[dict]:
        """Drop emptied waves and put every fleet wave in canonical evacuation order (wave 1 is left as is)."""
        return waves[:1] + [{"assets": sorted(w["assets"], key=self.order), "evacuate": sorted(w["evacuate"], key=self.order)}
                            for w in waves[1:] if w["assets"]]

    def cluster(self, h: str) -> str:
        return self.topo.servers[h]["cluster"]

    def free_hosts(self, waves: list[dict]) -> list[tuple[int, str]]:
        """Hosts that may move on their own: not riding with a switch they are single-homed to."""
        return [(i, h) for i, w in enumerate(waves) if i > 0 for h in w["assets"]
                if h in self.topo.servers and self.glued_to.get(h) not in w["assets"]]

    def pick(self, cands: list[tuple[int, str]]) -> tuple[int, str]:
        """Half the time uniform, half the time biased towards heavy (risky / tier-0) assets."""
        if self.rng.random() < 0.5:
            return self.rng.choice(cands)
        return self.rng.choices(cands, [self.r.get(h, 0.0) + 0.05 for _, h in cands])[0]

    def unit(self, w: dict, s: str) -> tuple[list[str], list[str]]:
        """A switch and what must travel with it: its single-homed hosts (targets or evacuations)."""
        return ([s] + [h for h in w["assets"] if self.glued_to.get(h) == s],
                [h for h in w["evacuate"] if self.glued_to.get(h) == s])

    def units(self, w: dict) -> list[tuple[list[str], list[str]]]:
        sws = [a for a in w["assets"] if a in self.topo.switches]
        out = [self.unit(w, s) for s in sws]
        out += [([h], []) for h in w["assets"] if h not in self.topo.switches and self.glued_to.get(h) not in sws]
        return out

    def propose(self, kind: str, waves: list[dict]) -> tuple[list[dict], str] | None:
        out = getattr(self, f"_{kind}")(waves) if len(waves) >= 2 else None
        return (self.tidy(out[0]), out[1]) if out else None

    def _move(self, waves):
        free = self.free_hosts(waves)
        if not free or len(waves) < 3:
            return None
        i, h = self.pick(free)
        j = self.rng.choice([k for k in range(1, len(waves)) if k != i])
        new = _copy(waves)
        new[i]["assets"].remove(h)
        new[j]["assets"].append(h)
        return new, f"move {h} from wave {i + 1} to wave {j + 1}"

    def _swap(self, waves):
        free = self.free_hosts(waves)
        if len(free) < 2:
            return None
        i, h1 = self.pick(free)
        others = [(j, h) for j, h in free if j != i]
        same = [(j, h) for j, h in others if self.cluster(h) == self.cluster(h1)]
        pool = same if same and self.rng.random() < 0.8 else others
        if not pool:
            return None
        j, h2 = self.rng.choice(pool)
        new = _copy(waves)
        new[i]["assets"][new[i]["assets"].index(h1)] = h2
        new[j]["assets"][new[j]["assets"].index(h2)] = h1
        return new, f"swap {h1} (wave {i + 1}) with {h2} (wave {j + 1})"

    def _take(self, w: dict, unit: tuple[list[str], list[str]]) -> None:
        w["assets"] = [a for a in w["assets"] if a not in unit[0]]
        w["evacuate"] = [e for e in w["evacuate"] if e not in unit[1]]

    def _put(self, w: dict, unit: tuple[list[str], list[str]]) -> None:
        w["assets"] += unit[0]
        w["evacuate"] += [e for e in unit[1] if e not in w["evacuate"]]

    def _move_switch(self, waves):
        """Move a switch (with its single-homed hosts) to another wave or a new one, or swap two switches' waves."""
        sws = [(i, a) for i, w in enumerate(waves) if i > 0 for a in w["assets"] if a in self.topo.switches]
        if not sws:
            return None
        i, s = self.pick(sws)
        u = self.unit(waves[i], s)
        new = _copy(waves)
        others = [(j, t) for j, t in sws if j != i]
        if others and self.rng.random() < 0.35:
            j, t = self.rng.choice(others)
            v = self.unit(waves[j], t)
            self._take(new[i], u)
            self._take(new[j], v)
            self._put(new[i], v)
            self._put(new[j], u)
            return new, f"swap {'+'.join(u[0])} (wave {i + 1}) with {'+'.join(v[0])} (wave {j + 1})"
        self._take(new[i], u)
        opts = [k for k in range(1, len(waves)) if k != i]
        if opts and self.rng.random() < 0.75:
            j = self.rng.choice(opts)
            self._put(new[j], u)
            return new, f"move {'+'.join(u[0])} from wave {i + 1} to wave {j + 1}"
        pos = self.rng.randint(1, len(new))
        new.insert(pos, {"assets": list(u[0]), "evacuate": list(u[1])})
        return new, f"move {'+'.join(u[0])} from wave {i + 1} to a new wave {pos + 1}"

    def _reorder(self, waves):
        if len(waves) < 3:
            return None
        i, j = self.rng.sample(range(1, len(waves)), 2)
        new = _copy(waves)
        new.insert(j, new.pop(i))
        return new, f"run wave {i + 1} as wave {j + 1}"

    def _split(self, waves):
        cands = [i for i in range(1, len(waves)) if len(self.units(waves[i])) >= 2]
        if not cands:
            return None
        i = self.rng.choice(cands)
        us = self.units(waves[i])
        pick = [u for u in us if self.rng.random() < 0.5]
        if not pick or len(pick) == len(us):
            pick = [us[self.rng.randrange(len(us))]]
        moved, moved_ev = {a for u in pick for a in u[0]}, {e for u in pick for e in u[1]}
        new = _copy(waves)
        w = new[i]
        part = {"assets": [a for a in w["assets"] if a in moved], "evacuate": [e for e in w["evacuate"] if e in moved_ev]}
        self._take(w, (list(moved), list(moved_ev)))
        pos = self.rng.randint(1, len(new))
        new.insert(pos, part)
        return new, f"split {len(part['assets'])} asset(s) out of wave {i + 1} into a new wave {pos + 1}"

    def _merge(self, waves):
        if len(waves) < 3:
            return None
        i, j = sorted(self.rng.sample(range(1, len(waves)), 2))
        new = _copy(waves)
        self._put(new[i], (new[j]["assets"], new[j]["evacuate"]))
        del new[j]
        return new, f"merge wave {j + 1} into wave {i + 1}"


def name_waves(waves: list[dict], topo: Topology, first: dict) -> list[dict]:
    """Solver-style names; wave 1 keeps its name and rationale."""
    out = []
    for i, w in enumerate(waves, start=1):
        if i == 1:
            out.append({**first, "assets": list(w["assets"]), "evacuate": list(w["evacuate"])})
            continue
        sws = [a for a in w["assets"] if a in topo.switches]
        out.append({"name": f"Wave {i} - " + (f"{', '.join(sws)} + hosts" if sws else "hosts"),
                    "assets": list(w["assets"]), "evacuate": list(w["evacuate"]), "rationale": ""})
    return out


def _changes(before: list[dict], after: list[dict], r: dict[str, float]) -> list[dict]:
    """Assets whose wave changed, heaviest first, with the share of the plan validated before their wave."""
    def where(waves):
        n = sum(len(w["assets"]) for w in waves) or 1
        out, done = {}, 0
        for k, w in enumerate(waves, start=1):
            for a in w["assets"]:
                out[a] = (k, round(100 * done / n))
            done += len(w["assets"])
        return out

    b, a = where(before), where(after)
    rows = [{"asset": x, "weight": round(r.get(x, 0.0), 2), "from_wave": b[x][0], "to_wave": a[x][0],
             "validated_before_pct": [b[x][1], a[x][1]]} for x in b if x in a and b[x][0] != a[x][0]]
    return sorted(rows, key=lambda row: (-row["weight"], row["asset"]))


def optimize(plan: dict, targets: list[str] | dict, topo: Topology, risk: dict, policy: Policy, components: list[str],
             window_minutes: int, deferred: list | tuple = (), seed: int = 5, iterations: int | None = None,
             time_budget_s: float = 60.0) -> dict:
    """Improve a feasible plan under the hard constraints of ``check_plan``.

    ``targets`` is the change's asset list (or ``{"servers": [...], "switches": [...]}``), ``risk`` the Risk
    agent's output (or a name -> score map), ``deferred`` names or ``risk["deferred"]`` entries. Returns the best
    plan (the input, unchanged, if nothing better is found or the input is infeasible), the objective before and
    after, the accepted moves that lead to the best plan, per-asset wave changes and search statistics.
    ``iterations`` is the stopping rule, so the same inputs give the same plan whatever the CPU load.
    ``time_budget_s`` is only a safety cap on the search loop: if it stops the search first, the result is
    still feasible and no worse but depends on machine speed, and ``stats["stopped_by"]`` says so.
    """
    t0 = time.perf_counter()
    tgt = list(targets["servers"]) + list(targets["switches"]) if isinstance(targets, dict) else list(targets)
    deferred = _names(deferred)
    iterations = int(policy.get("optimizer.iterations", 2500) if iterations is None else iterations)
    wts = objective_weights(policy)
    start = _copy(plan["waves"])
    r = asset_weights([a for w in start for a in w["assets"]], topo, _scores(risk), wts["tier0_weight"])
    model = _Model(topo, policy, components, window_minutes, r, wts)
    single = {s["server"]: s["up_links"][0] for s in topo.single_homed() if len(s["up_links"]) == 1}
    moves = _Moves(topo, random.Random(seed), single, r)

    first = check_plan({"waves": start}, topo, tgt, components, policy, window_minutes, deferred)
    before = model.evaluate(start) if first["ok"] else None

    def result(status: str, best: list[dict], after: dict | None, path: list, check: dict, stats: dict) -> dict:
        same = best is start
        return {"status": status, "improved": not same,
                "plan": plan if same else {**plan, "waves": name_waves(best, topo, plan["waves"][0])},
                "before": before, "after": before if same else after, "moves": [] if same else path,
                "changes": [] if same else _changes(start, best, r), "weights": wts,
                "check": {k: check[k] for k in ("ok", "violations", "total_duration_min", "max_brs")},
                "stats": {**stats, "seed": seed, "simulated_waves": len(model.sim),
                          "elapsed_s": round(time.perf_counter() - t0, 3)}}

    if before is None:
        return result("infeasible_input", start, None, [], first,
                      {"iterations": 0, "accepted": 0, "rejected_infeasible": 0, "stopped_by": "infeasible_input"})

    cur, cur_e = start, before
    best, best_e, path, best_path = start, before, [], []
    # Warm start: run the fleet waves lightest first. Wave contents do not change, so this stays feasible.
    ordered = moves.tidy(start[:1] + sorted(start[1:], key=lambda w: sum(r.get(a, 0.0) for a in w["assets"])))
    warm = model.evaluate(ordered)
    if ordered != start and warm is not None and warm["J"] < before["J"] - 1e-6:
        cur, cur_e = best, best_e = ordered, warm
        path = [{"iteration": 0, "kind": "reorder", "detail": "run the fleet waves in ascending order of risk weight",
                 "delta_J": round(warm["J"] - before["J"], 2)}]
        best_path = list(path)
    accepted = infeasible = done = 0
    stopped_by = "iterations"
    for it in range(1, iterations + 1):
        if time.perf_counter() - t0 > time_budget_s:
            stopped_by = "time_budget"
            break
        done = it
        temp = T_START * (T_END / T_START) ** (it / iterations)
        kind = moves.rng.choices(KINDS, KIND_WEIGHTS)[0]
        prop = moves.propose(kind, cur)
        if prop is None:
            continue
        cand, detail = prop
        u = moves.rng.random()
        guess = model.evaluate(cand, simulate=False)  # exact unless a wave turns out to have an outage
        if guess is None:
            infeasible += 1
            continue
        g = guess["J"] - cur_e["J"]
        # Sideways moves (equal-weight hosts swapped) cost a simulation and rarely lead anywhere: take a few.
        if not (g < -1e-9 or (g <= 1e-9 and u < PLATEAU_P) or (g > 1e-9 and u < math.exp(-g / temp))):
            continue
        ev = model.evaluate(cand)
        if ev is None:
            infeasible += 1
            continue
        delta = ev["J"] - cur_e["J"]
        if delta <= 1e-9 or u < math.exp(-delta / temp):
            accepted += 1
            cur, cur_e = cand, ev
            path.append({"iteration": it, "kind": kind, "detail": detail, "delta_J": round(delta, 2)})
            if ev["J"] < best_e["J"] - 1e-6:
                best, best_e, best_path = cand, ev, list(path)

    stats = {"iterations": done, "accepted": accepted, "rejected_infeasible": infeasible, "stopped_by": stopped_by}
    if best is start:
        return result("no_improvement", start, None, [], first, stats)
    final = check_plan({"waves": best}, topo, tgt, components, policy, window_minutes, deferred)
    if not final["ok"]:  # defensive: the per-wave rules above mirror check_plan, so this should not happen
        return result("rejected_by_check_plan", start, None, [], first, stats)
    return result("improved", best, best_e, best_path, final, stats)


def describe(res: dict) -> str:
    """One line for a timeline entry or the CLI."""
    b, a = res["before"], res["after"]
    if res["status"] != "improved":
        return f"optimiser kept the plan ({res['status'].replace('_', ' ')}" + (f", J {b['J']:.1f})" if b else ")")
    s = (f"optimiser: J {b['J']:.1f} -> {a['J']:.1f} ({100 * (a['J'] - b['J']) / b['J']:+.0f}%); "
         f"exposure {b['exposure']:.2f} -> {a['exposure']:.2f}, duration {b['duration_min']} -> {a['duration_min']} min, "
         f"waves {b['waves']} -> {a['waves']}, sum BRS {b['sum_brs']:.1f} -> {a['sum_brs']:.1f}")
    top = [c for c in res["changes"] if c["weight"] >= 1][:3]
    if top:
        s += "; " + ", ".join(f"{c['asset']} wave {c['from_wave']} -> {c['to_wave']} ({c['validated_before_pct'][0]}% -> "
                              f"{c['validated_before_pct'][1]}% of the plan validated first)" for c in top)
    return s + stop_note(res["stats"])


def stop_note(stats: dict) -> str:
    """Empty unless the time cap, not the iteration count, ended the search (the plan then depends on machine speed)."""
    if (stats or {}).get("stopped_by") != "time_budget":
        return ""
    return f"; stopped by the time cap after {stats['iterations']} iterations, so this plan depends on machine speed"


def regrounded(plan: dict, topo: Topology, targets: dict, policy: Policy, components: list[str],
               deferred: list | tuple = ()) -> dict:
    """The plan with its rationale rebuilt from its (optimised) waves, so the Verifier checks claims about them."""
    minutes = sum(wave_duration(w["assets"], w.get("evacuate", []), topo, components, policy) for w in plan["waves"])
    facts = plan_facts(topo, targets, policy, components, _names(deferred))
    return {**plan, "rationale": grounded_rationale(plan["waves"], facts, components, minutes)}
