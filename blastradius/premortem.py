"""Probabilistic pre-mortem: what else could go wrong while a wave runs?

The Blast-Radius Score answers a deterministic question: what does this wave break
if everything behaves? Operators also ask the pre-mortem question: *what is the
chance this wave takes down a tier-0 service if something else goes wrong while
it runs?* This module answers it over the dependency graph, using
``Topology.simulate`` as the only judge of what loses service.

Model, per wave. Every rate is a planning assumption read from ``premortem.*`` in
policy.yaml and returned with the result; none of them is a measured failure rate.

* Upgraded assets. Each wave asset fails to come back with
  ``p = min(max_failure_prob, base_failure_prob[kind] * (1 + risk / risk_scale))``,
  where ``risk`` is the Risk agent's 0-100 score. A failed asset is repaired in
  ``repair_hours[kind]``. During that repair it stays degraded (a switch stays down,
  a host stays in maintenance with its VMs evacuated, and so does any wave host
  whose only uplinks are down), while the rest of the wave returns to service.
* Background failures. Every switch and host outside the wave fails independently
  at ``background_failure_per_hour[kind]`` over the wave (and over the repair, if
  there is one), and stays failed until the window ends. A crashed host is an HA
  restart: its VMs count as lost only if its cluster cannot place them.
* Outcome. The VMs that lose service in the wave or in the repair that follows it.

Estimator. Failures are rare, so plain sampling would spend nearly every sample on
the world where nothing fails and rank equally likely single failures by noise.
Worlds are split by how many independent events happen:

* exact: nothing fails; exactly one background failure; exactly one asset fails to
  come back, with nothing or exactly one more failure during its repair;
* sampled: two or more events during the wave, or one asset fails to come back and
  two or more things fail during its repair. Each is sampled conditionally (exact
  sequential method), so every sample lands in the stratum it stands for.

The estimate is unbiased, the standard error comes only from the sampled strata and
is reported, and samples use per-sample seeds, so results are reproducible and
plans compared with the same seed see the same random numbers.

Plan level. Waves are independent, and a change halted by a failure resumes in a
later window, so every wave eventually runs once:
``P(tier-0 outage) = 1 - prod(1 - p_wave)``. The in-window figure, where the change
halts at the first failed asset or lost VM, is reported alongside.

Speed. ``simulate`` places evacuated VMs cluster by cluster, and reachability
depends only on which switches are down, so the VMs a cluster loses depend only on
the down switches and that cluster's hosts in maintenance. Results are memoised on
exactly that key, and every world (frozen set of failures) is memoised on top.
"""

from __future__ import annotations

import math
import random
from bisect import bisect_right
from collections import defaultdict
from itertools import accumulate, combinations

from .constraints import describe_outage, impact_kwargs, wave_duration
from .policy import Policy
from .topology import Topology

KINDS = ("server", "switch")
DEFAULTS = {
    "base_failure_prob": {"server": 0.01, "switch": 0.005},
    "risk_scale": 25.0,
    "max_failure_prob": 0.25,
    "background_failure_per_hour": {"server": 0.001, "switch": 0.001},
    "repair_hours": {"server": 2.0, "switch": 4.0},
}
P_MAX = 0.99  # keeps every event probability strictly below 1
ASSUMPTION_NOTE = ("Every probability here is assumption-driven: it follows from the planning assumptions below "
                   "(policy.yaml premortem.*), not from measured failure rates for this fleet. The background rates "
                   "are deliberately pessimistic (stress and operator error during a change window, far above hardware "
                   "MTBF). Use the numbers to compare waves and plans, not as a forecast.")
MODEL = [
    "assets and background failures are independent",
    "an asset that fails to come back stays down (switch) or in maintenance with its VMs evacuated (host) for its repair time",
    "a background host crash is an HA restart: its VMs count as lost only if the cluster cannot place them",
    "background failures last until the window ends; arrays, power and spine-level correlated failures are not modelled",
    "plan level: a halted change resumes later, so every wave runs once",
]
METHOD = ("Exact enumeration of worlds with at most one failure (plus one more during a repair), stratified conditional "
          "Monte Carlo for the rest; every world is evaluated with Topology.simulate.")


def assumptions(policy: Policy) -> dict:
    def per_kind(key: str) -> dict:
        given = policy.get(f"premortem.{key}", {}) or {}
        return {k: float(given.get(k, DEFAULTS[key][k])) for k in KINDS}

    return {
        "base_failure_prob": per_kind("base_failure_prob"),
        "risk_scale": float(policy.get("premortem.risk_scale", DEFAULTS["risk_scale"])),
        "max_failure_prob": min(P_MAX, float(policy.get("premortem.max_failure_prob", DEFAULTS["max_failure_prob"]))),
        "background_failure_per_hour": per_kind("background_failure_per_hour"),
        "repair_hours": per_kind("repair_hours"),
        "formula": ("p(asset fails to come back) = min(max_failure_prob, base_failure_prob[kind] * (1 + risk / risk_scale)); "
                    "p(background failure over t hours) = 1 - exp(-background_failure_per_hour[kind] * t)"),
        "model": MODEL,
        "measured": False,
        "note": ASSUMPTION_NOTE,
    }


def return_failure_prob(kind: str, risk_score: float, a: dict) -> float:
    scale = a["risk_scale"]
    p = a["base_failure_prob"][kind] * ((1 + max(0.0, risk_score) / scale) if scale > 0 else 1.0)
    return min(a["max_failure_prob"], max(0.0, p))


class SimCache:
    """Memoised ``Topology.simulate``: which VMs lose service with these switches down and
    these hosts in maintenance (in evacuation order).

    Exact decomposition: reachability depends only on the down switches, and evacuation
    is placed cluster by cluster, so a cluster's losses depend only on the down switches
    and its own hosts in maintenance. Results are memoised on that key. One more exact
    shortcut skips the call when placement provably succeeds (see ``_placeable``); then
    only the network losses of the same down switches (one ``simulate(down, [])``)
    remain. ``tests/test_premortem.py`` checks both against direct ``simulate`` calls.
    """

    def __init__(self, topo: Topology, policy: Policy):
        self.topo = topo
        self.kw = impact_kwargs(policy)
        self.cluster_of = {h: c for c, cl in topo.clusters.items() for h in cl["hosts"]}
        self.vm_cluster = {n: self.cluster_of.get(v["host"]) for n, v in topo.vms.items()}
        self.groups = sorted({self.cluster_of.get(h) for h in topo.servers}, key=str)
        self.tier0 = frozenset(n for n, v in topo.vms.items() if v["tier"] == 0)
        self.vms_on: dict[str, list[dict]] = defaultdict(list)
        for v in sorted(topo.vms.values(), key=lambda x: (-x["memoryGB"], x["name"])):
            self.vms_on[v["host"]].append(v)  # simulate's evacuation order: largest first
        self.used = {h: sum(v["memoryGB"] for v in self.vms_on[h]) for h in topo.servers}
        self.cache: dict = {}
        self._net: dict = {}
        self.calls = 0

    def _simulate(self, down: frozenset, maint: tuple) -> dict:
        self.calls += 1
        return self.topo.simulate(down, list(maint), **self.kw)

    def network(self, down: frozenset) -> tuple[frozenset, frozenset, frozenset]:
        """(VMs lost, hosts isolated, datastores unreachable) with ``down`` switches and nothing in maintenance."""
        if down not in self._net:
            res = self._simulate(down, ())
            cut = set(res["arrays_unreachable"])
            self._net[down] = (frozenset(res["impacted_vms"]), frozenset(res["isolated_servers"]),
                               frozenset(d for d, ds in self.topo.datastores.items() if ds["array"] in cut))
        return self._net[down]

    def _placeable(self, cluster: str, maint: tuple, isolated: frozenset) -> bool:
        """Sufficient condition for simulate placing every VM evacuated from ``maint``.

        VMs are checked in simulate's order (hosts in order, largest VM first). If all
        earlier VMs were placed, the least-utilised healthy host is at most at the
        memory-weighted average utilisation, so it has room for this VM when average +
        VM / smallest host stays under the ceiling. By induction every VM is placed.
        """
        c = self.topo.clusters[cluster]
        healthy = [h for h in c["hosts"] if h not in maint and h not in isolated]
        if not healthy:
            return not any(self.vms_on[h] for h in maint)
        mem = [self.topo.servers[h]["memoryGB"] for h in healthy]
        total, smallest = sum(mem), min(mem)
        ceiling = c.get("maxMemoryUtilPct", 85) / 100.0 - 1e-9
        load = sum(self.used[h] for h in healthy)
        for h in maint:
            for v in self.vms_on[h]:
                if load / total + v["memoryGB"] / smallest > ceiling:
                    return False
                load += v["memoryGB"]
        return True

    def _cluster_lost(self, down: frozenset, g: str | None, sub: tuple) -> frozenset:
        lost, isolated, bad_ds = self.network(down)
        if not sub or (g is not None and self._placeable(g, sub, isolated)):
            on = set(sub)
            return (frozenset(v for v in lost if self.vm_cluster[v] == g and self.topo.vms[v]["host"] not in on)
                    | frozenset(v["name"] for h in sub for v in self.vms_on[h] if v["datastore"] in bad_ds))
        return frozenset(v for v in self._simulate(down, sub)["impacted_vms"] if self.vm_cluster[v] == g)

    def lost(self, down: frozenset, maint: tuple) -> frozenset:
        out: frozenset = frozenset()
        for g in self.groups:
            sub = tuple(h for h in maint if self.cluster_of.get(h) == g)
            key = (down, g, sub)
            hit = self.cache.get(key)
            if hit is None:
                hit = self.cache[key] = self._cluster_lost(down, g, sub)
            out |= hit
        return out


# ------------------------------------------------------------------ sampling
def _split(probs: list[float]) -> tuple[float, list[float], float]:
    """(P(no event), [P(event i and no other)], P(two or more)) for independent events."""
    none = math.exp(sum(math.log1p(-p) for p in probs))
    one = [none * p / (1 - p) for p in probs]
    return none, one, max(0.0, 1.0 - none - sum(one))


def _bern(rng: random.Random, items: list, probs: list[float], skip=frozenset()) -> list:
    return [x for x, p in zip(items, probs) if rng.random() < p and x not in skip]


def _at_least_one(rng: random.Random, items: list, probs: list[float], p_any: float) -> list:
    """Independent Bernoulli draws conditioned on at least one event (exact sequential method)."""
    u = rng.random() * p_any
    cum, prefix, j = 0.0, 1.0, max(i for i, p in enumerate(probs) if p > 0)
    for i, p in enumerate(probs):
        cum += prefix * p
        if u < cum:
            j = i
            break
        prefix *= 1 - p
    return [items[j]] + _bern(rng, items[j + 1:], probs[j + 1:])


class _TwoPlus:
    """Independent Bernoulli draws conditioned on at least two events: the first event is
    ``j`` with weight P(none before j) * p_j * P(at least one after j), the rest follow
    conditioned on at least one."""

    def __init__(self, items: list, probs: list[float]):
        self.items, self.probs = items, probs
        self.suffix = [0.0] * (len(probs) + 1)  # P(at least one event among items[i:])
        for i in range(len(probs) - 1, -1, -1):
            self.suffix[i] = 1 - (1 - self.suffix[i + 1]) * (1 - probs[i])
        prefix, w = 1.0, []
        for i, p in enumerate(probs):
            w.append(prefix * p * self.suffix[i + 1])
            prefix *= 1 - p
        self.cum = list(accumulate(w))

    def __call__(self, rng: random.Random) -> list:
        j = bisect_right(self.cum, rng.random() * self.cum[-1])
        return [self.items[j]] + _at_least_one(rng, self.items[j + 1:], self.probs[j + 1:], self.suffix[j + 1])


def _allocate(n: int, a: float, b: float) -> tuple[int, int]:
    """Samples for two strata of mass ``a`` and ``b``: proportional, at least 10% each."""
    if a <= 0 or b <= 0:
        return (n if a > 0 else 0), (n if b > 0 and a <= 0 else 0)
    k = round(n * min(0.9, max(0.1, b / (a + b))))
    return n - k, k


def _quantile(dist: dict, q: float) -> int:
    total = sum(dist.values())
    acc = 0.0
    for x in sorted(dist):
        acc += dist[x]
        if acc >= q * total - 1e-12:
            return x
    return max(dist, default=0)


def _convolve(a: dict, b: dict, floor: float = 1e-12) -> dict:
    out: dict[int, float] = defaultdict(float)
    for x, p in a.items():
        for y, q in b.items():
            if p * q > floor:
                out[x + y] += p * q
    return dict(out)


def _sig(x: float) -> float:
    return float(f"{x:.4g}") if abs(x) > 1e-12 else 0.0


# ---------------------------------------------------------------- one wave
class _Wave:
    def __init__(self, index: int, wave: dict, topo: Topology, scores: dict, a: dict, components: list[str],
                 policy: Policy, sim: SimCache):
        self.index, self.wave, self.topo, self.a, self.sim = index, wave, topo, a, sim
        sw, srv = topo.switches, topo.servers
        self.assets = [x for x in dict.fromkeys(wave["assets"]) if x in sw or x in srv]
        self.evac = [e for e in dict.fromkeys(wave.get("evacuate", [])) if e in srv and e not in self.assets]
        self.w_sw = frozenset(x for x in self.assets if x in sw)
        self.w_hosts = tuple(x for x in self.assets if x in srv) + tuple(self.evac)
        self.minutes = wave_duration(wave["assets"], wave.get("evacuate", []), topo, components, policy)
        self.p_ret = [return_failure_prob(self.kind(x), scores.get(x, 0.0), a) for x in self.assets]
        busy = set(self.assets) | set(self.evac)
        self.others = [x for x in sorted(sw) + sorted(srv) if x not in busy]
        self.rate = [a["background_failure_per_hour"][self.kind(x)] for x in self.others]
        self.q_wave = self.q(self.minutes / 60)
        self.links = {h: frozenset(topo.links_of(h)) for h in self.w_hosts}
        self._repair: dict[float, tuple] = {}
        self._lost: dict[tuple, frozenset] = {}

    def kind(self, x: str) -> str:
        return "switch" if x in self.topo.switches else "server"

    def q(self, hours: float) -> list[float]:
        return [min(P_MAX, -math.expm1(-r * hours)) for r in self.rate]

    def repair_hours(self, failed) -> float:
        return max(self.a["repair_hours"][self.kind(x)] for x in failed)

    def repair(self, failed) -> tuple:
        """Background failure probabilities over the repair of ``failed``, their split, and a 2+ sampler."""
        t = self.repair_hours(failed)
        if t not in self._repair:
            q = self.q(t)
            self._repair[t] = (q, _split(q), _TwoPlus(self.others, q))
        return self._repair[t]

    # ------------------------------------------------------------ outcomes
    def states(self, ret: tuple, during: tuple, repair: tuple) -> list[tuple[frozenset, tuple]]:
        """(down switches, hosts in maintenance) during the wave, and during the repair if any."""
        sw = self.topo.switches
        down = self.w_sw | {x for x in during if x in sw}
        out = [(down, self.w_hosts + tuple(x for x in during if x not in sw))]
        if ret:
            # a wave host whose uplinks were all down when the wave ended keeps its VMs evacuated
            still_down = frozenset(x for x in ret + during if x in sw)
            held = tuple(h for h in self.w_hosts if h not in ret and self.links[h] <= still_down)
            out.append((still_down | {x for x in repair if x in sw},
                        tuple(x for x in ret if x not in sw) + held + tuple(x for x in during + repair if x not in sw)))
        return out

    def lost(self, ret: tuple, during: tuple, repair: tuple) -> frozenset:
        key = (ret, during, repair)
        if key not in self._lost:
            out: frozenset = frozenset()
            for down, maint in self.states(ret, during, repair):
                out |= self.sim.lost(down, maint)
            self._lost[key] = out
        return self._lost[key]

    def baseline(self, background: tuple) -> frozenset:
        """What the same background failures would cost with no change running."""
        if not background:
            return frozenset()
        sw = self.topo.switches
        return self.sim.lost(frozenset(x for x in background if x in sw), tuple(sorted(x for x in background if x not in sw)))

    @staticmethod
    def world(cause: tuple) -> tuple:
        return tuple(tuple(x for t, x in cause if t == k) for k in ("return", "during", "repair"))

    def cause(self, ret: tuple, during: tuple, repair: tuple) -> tuple:
        """Smallest subset (up to two events) of a world's failures that still loses a tier-0 VM."""
        toks = [("return", x) for x in ret] + [("during", x) for x in during] + [("repair", x) for x in repair]
        for k in range(min(2, len(toks)) + 1):
            for sub in combinations(toks, k):
                r, d, rep = self.world(sub)
                if rep and not r:
                    continue
                if self.lost(r, d, rep) & self.sim.tier0:
                    return sub
        return tuple(toks)

    def describe(self, cause: tuple) -> str:
        if not cause:
            return "no extra failure needed: the wave's planned state already causes it"
        topo = self.topo
        ret, during, repair = self.world(cause)

        def names(xs: tuple) -> str:
            return xs[0] if len(xs) == 1 else f"{', '.join(xs[:-1])} and {xs[-1]}"

        def fail(xs: tuple) -> str:
            return f"{names(xs)} {'fail' if len(xs) > 1 else 'fails' if xs[0] in topo.switches else 'crashes'}"

        parts = []
        if ret:
            many = len(ret) > 1
            parts.append(f"{names(ret)} {'do' if many else 'does'} not come back after {'their' if many else 'its'} upgrade")
        if during:
            ctx = []
            # the wave's switches matter to a failing switch or to a host cabled to them
            if self.w_sw and any(x in topo.switches or set(topo.links_of(x)) & self.w_sw for x in during):
                ctx.append(f"{' and '.join(sorted(self.w_sw))} {'is' if len(self.w_sw) == 1 else 'are'} upgrading")
            for c in dict.fromkeys(topo.servers[x]["cluster"] for x in during if x in topo.servers):
                n = sum(1 for h in self.w_hosts if topo.servers[h]["cluster"] == c)
                if n:
                    ctx.append(f"{n} {c} host{'s are' if n > 1 else ' is'} in maintenance")
            parts.append(f"{fail(during)} while " + (" and ".join(ctx) or "the wave runs"))
        if repair:
            parts.append(f"{fail(repair)} during the {self.repair_hours(ret):g} h repair")
        return "if " + " and ".join(parts)

    def scenario(self, cause: tuple, mass: float, hit: float) -> dict:
        r, d, rep = self.world(cause)
        sims = [self.topo.simulate(down, list(maint), **self.sim.kw) for down, maint in self.states(r, d, rep)]
        worst = max(sims, key=lambda s: (len(s["critical_vms"]), len(s["impacted_vms"])))
        lost = self.lost(r, d, rep)
        return {"scenario": self.describe(cause), "events": [list(t) for t in cause], "probability": _sig(mass),
                "share_of_tier0_risk": _sig(mass / hit) if hit else 0.0,
                "attributable_to_change": bool((lost & self.sim.tier0) - self.baseline(d + rep)),
                "vms_lost": len(lost), "tier0_vms": sorted(lost & self.sim.tier0), "outcome": describe_outage(worst)}

    # ------------------------------------------------------------- estimate
    def run(self, samples: int, seed: int) -> tuple[dict, dict]:
        tier0 = self.sim.tier0
        toks = [("return", x) for x in self.assets] + [("during", x) for x in self.others]
        probs = self.p_ret + self.q_wave
        none, one, more = _split(probs)

        # world = (fails to come back, background failures during the wave, during the repair) -> probability
        worlds: dict[tuple, float] = defaultdict(float)
        worlds[((), (), ())] += none
        rep_mass: list[tuple[str, float]] = []
        for (t, x), w in zip(toks, one):
            if t == "during":
                worlds[((), (x,), ())] += w
                continue
            _, (r_none, r_one, r_more), _ = self.repair([x])
            worlds[((x,), (), ())] += w * r_none
            for y, wy in zip(self.others, r_one):
                worlds[((x,), (), (y,))] += w * wy
            rep_mass.append((x, w * r_more))
        exact = len(worlds)

        pi_m, pi_r = more, sum(m for _, m in rep_mass)
        n_m, n_r = _allocate(samples, pi_m, pi_r)
        ys: dict[str, list[float]] = {"m": [], "r": []}

        def rng(stratum: int, i: int) -> random.Random:
            return random.Random(((seed * 1009 + self.index) * 3 + stratum) * 1_000_003 + i)

        multi = _TwoPlus(toks, probs) if n_m else None
        for i in range(n_m):
            g = rng(1, i)
            ev = multi(g)
            ret, during = tuple(x for t, x in ev if t == "return"), tuple(x for t, x in ev if t == "during")
            repair = tuple(_bern(g, self.others, self.repair(ret)[0], skip=set(during))) if ret else ()
            worlds[(ret, during, repair)] += pi_m / n_m
            ys["m"].append(float(bool(self.lost(ret, during, repair) & tier0)))
        cum = list(accumulate(m for _, m in rep_mass))
        for i in range(n_r):
            g = rng(2, i)
            x = rep_mass[min(len(cum) - 1, bisect_right(cum, g.random() * cum[-1]))][0]
            repair = tuple(self.repair([x])[2](g))
            worlds[((x,), (), repair)] += pi_r / n_r
            ys["r"].append(float(bool(self.lost((x,), (), repair) & tier0)))

        hit = hit_base = hit_attr = halt = expected = 0.0
        dist: dict[int, float] = defaultdict(float)
        causes: dict[tuple, float] = defaultdict(float)
        for (ret, during, repair), w in worlds.items():
            if w <= 0:
                continue
            lost = self.lost(ret, during, repair)
            base = self.baseline(during + repair) & tier0
            lost0 = lost & tier0
            if lost0:
                hit += w
                causes[self.cause(ret, during, repair)] += w
            hit_base += w * bool(base)
            hit_attr += w * bool(lost0 - base)
            halt += w * bool(ret or lost)
            expected += w * len(lost)
            dist[len(lost)] += w
        p = min(1.0, hit)
        se = math.sqrt(sum(pi * pi * _var(y) / len(y) for pi, y in ((pi_m, ys["m"]), (pi_r, ys["r"])) if len(y) > 1))

        def severity(c: tuple) -> int:
            return len(self.lost(*self.world(c)))

        ranked = sorted(causes.items(), key=lambda kv: (-kv[1], -severity(kv[0]), kv[0]))
        def added(c: tuple) -> bool:  # tier-0 loss the same failures would not cause without the change
            r, d, rep = self.world(c)
            return bool((self.lost(r, d, rep) & tier0) - self.baseline(d + rep))

        worst = max(((c, m) for c, m in causes.items() if added(c)), key=lambda kv: (severity(kv[0]), kv[1]), default=None)
        out = {
            "wave": self.index,
            "name": self.wave.get("name") or f"Wave {self.index}",
            "assets": list(self.wave["assets"]),
            "duration_min": self.minutes,
            "planned_vms_lost": len(self.lost((), (), ())),
            "p_tier0_loss": _sig(p),
            "p_tier0_loss_se": _sig(se),
            "p_tier0_loss_ci95": [_sig(max(0.0, p - 1.96 * se)), _sig(min(1.0, p + 1.96 * se))],
            "p_tier0_loss_without_change": _sig(hit_base),
            "p_tier0_loss_attributable": _sig(hit_attr),
            "expected_vms_lost": _sig(expected),
            "p95_vms_lost": _quantile(dist, 0.95),
            "p_halt": _sig(halt),
            "p_nothing_fails": _sig(none),
            "vms_lost_distribution": [[x, _sig(w)] for x, w in sorted(dist.items()) if x],
            "top_scenarios": [self.scenario(c, m, hit) for c, m in ranked[:3]],
            "worst_scenario": self.scenario(worst[0], worst[1], hit) if worst else None,
            "samples": {"exact_worlds": exact, "multi_failure": n_m, "multi_failure_during_repair": n_r},
        }
        raw = {"p": p, "se": se, "base": hit_base, "attr": hit_attr, "halt": halt, "expected": expected, "dist": dict(dist)}
        return out, raw


def _var(ys: list[float]) -> float:
    m = sum(ys) / len(ys)
    return sum((y - m) ** 2 for y in ys) / (len(ys) - 1)


# ---------------------------------------------------------------- the plan
def _scores(risk: dict | None) -> dict[str, float]:
    if not risk:
        return {}
    src = risk["assets"] if isinstance(risk.get("assets"), dict) else risk
    return {a: float(r.get("score", 0) if isinstance(r, dict) else r) for a, r in src.items()}


def _any(ps: list[float]) -> float:
    return 1.0 - math.prod(1.0 - p for p in ps)


def premortem(plan: dict | list, topo: Topology, risk: dict | None, policy: Policy, components: list[str],
              samples: int = 2000, seed: int = 11, sim: SimCache | None = None) -> dict:
    """Pre-mortem for every wave of ``plan`` and for the change as a whole.

    ``risk`` is the Risk agent's result (or a plain ``{asset: score}``). ``samples`` is the
    Monte Carlo budget per wave, split between the two sampled strata. Pass the same
    ``sim`` to several calls on one topology to share the simulate memo.
    """
    a = assumptions(policy)
    sim = sim or SimCache(topo, policy)
    scores = _scores(risk)
    waves = plan["waves"] if isinstance(plan, dict) else plan
    runs = [_Wave(i, w, topo, scores, a, components, policy, sim).run(max(1, int(samples)), seed)
            for i, w in enumerate(waves, start=1)]
    per_wave = [w for w, _ in runs]
    raw = [r for _, r in runs]

    p = _any([r["p"] for r in raw])
    # delta method: dP/dp_k = prod over the other waves of (1 - p_i)
    se = math.sqrt(sum((math.prod(1 - o["p"] for j, o in enumerate(raw) if j != k) * r["se"]) ** 2
                       for k, r in enumerate(raw)))
    dist: dict[int, float] = {0: 1.0}
    for r in raw:
        dist = _convolve(dist, r["dist"])
    # in-window view: the change halts at the first failed asset or lost VM
    reach, p_window = 1.0, 0.0
    for w, r in zip(per_wave, raw):
        w["p_reached_in_window"] = _sig(reach)
        p_window += reach * r["p"]
        reach *= 1 - r["halt"]

    scenarios = [{"wave": w["wave"], **s} for w in per_wave for s in w["top_scenarios"]]
    worst = max(per_wave, key=lambda w: (w["p_tier0_loss"], -w["wave"]), default=None)
    return {
        "p_tier0_loss": _sig(p),
        "p_tier0_loss_se": _sig(se),
        "p_tier0_loss_ci95": [_sig(max(0.0, p - 1.96 * se)), _sig(min(1.0, p + 1.96 * se))],
        "p_tier0_loss_without_change": _sig(_any([r["base"] for r in raw])),
        "p_tier0_loss_attributable": _sig(_any([r["attr"] for r in raw])),
        "p_tier0_loss_in_window": _sig(min(1.0, p_window)),
        "p_completes_in_window": _sig(reach),
        "expected_vms_lost": _sig(sum(r["expected"] for r in raw)),
        "p95_vms_lost": _quantile(dist, 0.95),
        "worst_wave": worst["wave"] if worst else None,
        "top_scenarios": sorted(scenarios, key=lambda s: (-s["probability"], -s["vms_lost"], s["wave"]))[:3],
        "waves": per_wave,
        "samples_per_wave": int(samples),
        "seed": seed,
        "method": METHOD,
        "assumptions": a,
        "simulate_calls": sim.calls,
    }


def compare(plans: dict[str, dict | list], topo: Topology, risk: dict | None, policy: Policy, components: list[str],
            samples: int = 2000, seed: int = 11) -> dict:
    """Pre-mortem for several plans (e.g. the naive first draft and the accepted plan) with
    the same seed and one shared simulate memo."""
    sim = SimCache(topo, policy)
    results = {label: premortem(p, topo, risk, policy, components, samples, seed, sim) for label, p in plans.items()}
    rows = []
    for label, r in results.items():
        top = r["top_scenarios"][0] if r["top_scenarios"] else None
        rows.append({"plan": label, "waves": len(r["waves"]), "p_tier0_loss": r["p_tier0_loss"],
                     "p_tier0_loss_attributable": r["p_tier0_loss_attributable"],
                     "expected_vms_lost": r["expected_vms_lost"], "p95_vms_lost": r["p95_vms_lost"],
                     "p_completes_in_window": r["p_completes_in_window"], "worst_wave": r["worst_wave"],
                     "top_scenario": f"wave {top['wave']}: {top['scenario']}" if top else None})
    return {"rows": rows, "results": results, "assumptions": assumptions(policy), "simulate_calls": sim.calls}


# ------------------------------------------------------------- card output
def fmt_p(p: float) -> str:
    if p >= 1:
        return "100%"
    if p <= 0:
        return "0%"
    if p < 1e-4:
        return "<0.01%"
    return f"{100 * p:.2f}%" if p < 0.1 else f"{100 * p:.1f}%"


def _scenario_text(s: dict) -> str:
    t0 = s["tier0_vms"]
    return (f"{s['scenario']} ({fmt_p(s['probability'])}; {s['vms_lost']} VM{'s' if s['vms_lost'] != 1 else ''} lost, "
            f"tier-0 {', '.join(t0[:3])}{'...' if len(t0) > 3 else ''}"
            + ("" if s["attributable_to_change"] else "; would happen without the change") + ")")


def card_view(result: dict) -> dict:
    """Compact, JSON-safe summary for the go/no-go card."""
    r = result
    return {
        "p_tier0_loss": r["p_tier0_loss"], "p_tier0_loss_ci95": r["p_tier0_loss_ci95"],
        "p_tier0_loss_attributable": r["p_tier0_loss_attributable"], "expected_vms_lost": r["expected_vms_lost"],
        "p95_vms_lost": r["p95_vms_lost"], "p_completes_in_window": r["p_completes_in_window"],
        "waves": [{"wave": w["wave"], "name": w["name"], "p_tier0_loss": w["p_tier0_loss"],
                   "top_scenario": _scenario_text(w["top_scenarios"][0]) if w["top_scenarios"] else None,
                   "worst_scenario": _scenario_text(w["worst_scenario"]) if w["worst_scenario"] else None}
                  for w in r["waves"]],
        "assumptions": {k: r["assumptions"][k] for k in ("base_failure_prob", "risk_scale", "max_failure_prob",
                                                         "background_failure_per_hour", "repair_hours", "measured")},
        "note": ASSUMPTION_NOTE,
    }


def card_lines(result: dict) -> list[str]:
    """Plain-text lines for the go/no-go card (UI and CLI)."""
    r = result
    lines = [f"Pre-mortem (assumption-driven, not measured): P(tier-0 outage during the change) {fmt_p(r['p_tier0_loss'])} "
             f"(95% CI {fmt_p(r['p_tier0_loss_ci95'][0])}-{fmt_p(r['p_tier0_loss_ci95'][1])}), "
             f"{fmt_p(r['p_tier0_loss_attributable'])} attributable to the change; expected VMs lost "
             f"{r['expected_vms_lost']:g}, P95 {r['p95_vms_lost']}."]
    for w in r["waves"]:
        line = f"{w['name']}: P(tier-0 loss) {fmt_p(w['p_tier0_loss'])}"
        top, worst = (w["top_scenarios"] or [None])[0], w["worst_scenario"]
        if top:
            line += f" - most likely: {_scenario_text(top)}"
        if worst and top and worst["events"] != top["events"]:
            line += f"; most severe: {_scenario_text(worst)}"
        lines.append(line)
    a = r["assumptions"]
    lines.append("Assumptions: fail-to-return " + ", ".join(f"{k} {v:g}" for k, v in a["base_failure_prob"].items())
                 + f" x (1 + risk/{a['risk_scale']:g}), capped at {a['max_failure_prob']:g}; background "
                 + ", ".join(f"{k} {v:g}/h" for k, v in a["background_failure_per_hour"].items())
                 + "; repair " + ", ".join(f"{k} {v:g} h" for k, v in a["repair_hours"].items()) + ".")
    return lines
