"""Statistical canary analysis: judge each canary host against un-upgraded peers.

The fixed post-check rule (post > 2x pre, ``agents/postcheck.py``) compares a
host only with its own past. That has two blind spots. It misses a subtle
regression (a 1.3x latency shift never crosses 2x), and if the threshold is
tightened it false-alarms on common-mode load: a nightly backup that slows
*every* host looks exactly like a regression on the canary.

So, like Kayenta, BlastRadius also compares the canary with a *control* group
over the same minutes:

1. **Controls** are hosts of the canary's configuration cohort
   (``cohorts.build``) that are neither in the current wave nor already
   changed. With fewer than ``min_controls`` the group widens to the same
   model; if that is still too few the check reports *insufficient controls*
   instead of guessing.
2. **Windows.** Pre is the ``pre_minutes`` before the wave started; post is
   the last ``post_minutes`` before it ended in which the canary was out of
   maintenance. Controls are read over exactly the same minutes.
3. **Normalisation.** Every host's samples are divided by its own pre-window
   median, which removes per-host baselines; comparing canary with controls
   over the same minutes then removes common-mode effects.
4. **Test.** One-sided Mann-Whitney U (canary greater), tie-corrected normal
   approximation, with the exact permutation distribution for small samples.
5. **Effect size.** The difference-in-differences ratio
   ``(canary post / canary pre) / (control post / control pre)`` (medians)
   decides; the Hodges-Lehmann shift and the ratio of medians are reported too.
6. **Verdict.** FAIL if ``p < alpha`` and ``effect >= min_effect``; MARGINAL if
   only one of the two holds; PASS otherwise. The canary score (0-100) is the
   share of metric checks that pass.

Pure Python: no numpy or scipy.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Iterable, Mapping, Sequence

from .cohorts import build as build_cohorts, short_model

PASS, MARGINAL, FAIL, INCONCLUSIVE = "PASS", "MARGINAL", "FAIL", "INCONCLUSIVE"
_SEVERITY = {INCONCLUSIVE: -1, PASS: 0, MARGINAL: 1, FAIL: 2}
DEFAULT_METRICS = ("nic_latency_ms", "rx_drop_rate")
METRIC_LABELS = {"nic_latency_ms": "NIC latency", "rx_drop_rate": "rx drop rate"}
_EPS = 1e-12


# ------------------------------------------------------------------ basics
def median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    if not s:
        raise ValueError("median of an empty sample")
    m = len(s) // 2
    return s[m] if len(s) % 2 else (s[m - 1] + s[m]) / 2


def quantile(xs: Sequence[float], q: float) -> float:
    """Linear-interpolation quantile (numpy's default)."""
    s = sorted(xs)
    pos = (len(s) - 1) * q
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def midranks(values: Sequence[float]) -> tuple[list[float], list[int]]:
    """1-based ranks with ties averaged, plus the size of every tie group."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    ties: list[int] = []
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        ties.append(j - i + 1)
        i = j + 1
    return ranks, ties


def _norm_sf(z: float) -> float:
    return 0.5 * math.erfc(z / math.sqrt(2))


def _subset_sum_counts(values: Sequence[int], k: int) -> dict[int, int]:
    """How many k-element subsets of ``values`` have each possible sum (exact permutation distribution)."""
    dp: list[dict[int, int]] = [defaultdict(int) for _ in range(k + 1)]
    dp[0][0] = 1
    for i, v in enumerate(values):
        for j in range(min(i + 1, k), 0, -1):
            prev, cur = dp[j - 1], dp[j]
            for s, c in prev.items():
                cur[s + v] += c
    return dp[k]


# ------------------------------------------------------------ Mann-Whitney
def mann_whitney_u(x: Sequence[float], y: Sequence[float], alternative: str = "greater",
                   exact_max_n: int = 250) -> dict:
    """Two-sample Mann-Whitney U test of ``x`` against ``y``.

    ``alternative="greater"`` asks whether x tends to be larger than y. Uses the exact permutation
    distribution of the (mid)rank sum when ``len(x) + len(y) <= exact_max_n`` or when one tie group holds
    most of the sample (there the normal approximation's variance collapses), otherwise the normal
    approximation with tie and continuity correction, floored at 1/C(n1+n2, min(n1, n2)), the smallest
    p a rank test can produce. If every value is tied there is no evidence either way and p is 1.
    """
    n1, n2 = len(x), len(y)
    if not n1 or not n2:
        raise ValueError("both samples must be non-empty")
    if alternative not in ("greater", "less", "two-sided"):
        raise ValueError(f"unknown alternative {alternative!r}")
    n = n1 + n2
    ranks, ties = midranks(list(x) + list(y))
    r1 = sum(ranks[:n1])
    u = r1 - n1 * (n1 + 1) / 2
    mu = n1 * n2 / 2
    if n <= exact_max_n or max(ties) > n / 2:
        # Doubled midranks are integers, so the permutation distribution is counted exactly.
        r2x = [int(round(2 * r)) for r in ranks]
        k = min(n1, n2)
        counts = _subset_sum_counts(r2x, k)
        total = math.comb(n, k)
        obs = int(round(2 * r1)) if k == n1 else sum(r2x) - int(round(2 * r1))  # rank sum of the smaller group
        hi = sum(c for s, c in counts.items() if s >= obs) / total  # P(smaller-group sum >= observed)
        lo = sum(c for s, c in counts.items() if s <= obs) / total
        p_greater, p_less = (hi, lo) if k == n1 else (lo, hi)
        p = {"greater": p_greater, "less": p_less, "two-sided": min(1.0, 2 * min(p_greater, p_less))}[alternative]
        return {"u": u, "p_value": p, "z": None, "method": "exact", "n1": n1, "n2": n2}
    var = n1 * n2 / 12 * ((n + 1) - sum(t ** 3 - t for t in ties) / (n * (n - 1)))
    if var <= 0:
        return {"u": u, "p_value": 1.0, "z": 0.0, "method": "normal", "n1": n1, "n2": n2}
    sd = math.sqrt(var)
    if alternative == "greater":
        z = (u - mu - 0.5) / sd
        p = _norm_sf(z)
    elif alternative == "less":
        z = (u - mu + 0.5) / sd
        p = 1 - _norm_sf(z)
    else:
        z = (abs(u - mu) - 0.5) / sd
        p = min(1.0, 2 * _norm_sf(z))
    return {"u": u, "p_value": min(1.0, max(1 / math.comb(n, min(n1, n2)), p)), "z": z, "method": "normal", "n1": n1, "n2": n2}


# ------------------------------------------------------------ effect sizes
def hodges_lehmann(x: Sequence[float], y: Sequence[float]) -> float:
    """Hodges-Lehmann estimate of the shift of x over y: the median of all pairwise differences."""
    return median([a - b for a in x for b in y])


def ratio_of_medians(x: Sequence[float], y: Sequence[float]) -> float:
    return median(x) / max(median(y), _EPS)


def did_ratio(canary_pre: Sequence[float], canary_post: Sequence[float],
              control_pre: Sequence[float], control_post: Sequence[float]) -> float:
    """Difference-in-differences as a ratio of medians: (canary post / pre) / (control post / pre)."""
    canary = median(canary_post) / max(median(canary_pre), _EPS)
    control = median(control_post) / max(median(control_pre), _EPS)
    return canary / max(control, _EPS)


def classify(p_value: float, effect: float, alpha: float = 0.01, min_effect: float = 1.15) -> str:
    significant, large = p_value < alpha, effect >= min_effect
    if significant and large:
        return FAIL
    return MARGINAL if (significant or large) else PASS


# ------------------------------------------------------------------- judge
def _clean(xs: Iterable[float | None]) -> list[float]:
    return [float(v) for v in xs if v is not None]


def compare_metric(canary_pre: Sequence[float | None], canary_post: Sequence[float | None],
                   controls: Mapping[str, tuple[Sequence[float | None], Sequence[float | None]]],
                   alpha: float = 0.01, min_effect: float = 1.15, exact_max_n: int = 250,
                   min_samples: int = 5, min_controls: int = 3) -> dict:
    """One metric check of one canary host. ``controls`` maps control host -> (pre, post) samples
    taken over the same minutes as the canary's. ``None`` samples (maintenance) are ignored."""
    c_pre, c_post = _clean(canary_pre), _clean(canary_post)
    ctl = {h: (_clean(a), _clean(b)) for h, (a, b) in controls.items()}
    ctl = {h: ab for h, ab in ctl.items() if len(ab[0]) >= min_samples and len(ab[1]) >= min_samples}
    out: dict[str, Any] = {"n_canary": len(c_post), "n_control": sum(len(b) for _, b in ctl.values()),
                           "n_control_hosts": len(ctl), "p_value": None, "effect": None}
    if len(c_pre) < min_samples or len(c_post) < min_samples:
        return out | {"verdict": INCONCLUSIVE, "reason": f"too few canary samples (pre {len(c_pre)}, post {len(c_post)}; "
                                                         f"need {min_samples})"}
    if len(ctl) < min_controls:
        return out | {"verdict": INCONCLUSIVE, "reason": f"insufficient controls with data ({len(ctl)}; need {min_controls})"}
    base = max(median(c_pre), _EPS)
    x = [v / base for v in c_post]
    y = [v / max(median(a), _EPS) for a, b in ctl.values() for v in b]
    mw = mann_whitney_u(x, y, "greater", exact_max_n)
    k_pre = [v for a, _ in ctl.values() for v in a]
    k_post = [v for _, b in ctl.values() for v in b]
    effect = did_ratio(c_pre, c_post, k_pre, k_post)
    log_x = [math.log(max(v, _EPS)) for v in x]
    log_y = [math.log(max(v, _EPS)) for v in y]
    return out | {
        "verdict": classify(mw["p_value"], effect, alpha, min_effect),
        "p_value": float(f"{mw['p_value']:.4g}"),
        "effect": round(effect, 4),
        "did_ratio": round(effect, 4),
        "canary_ratio": round(median(c_post) / base, 4),
        "control_ratio": round(median(k_post) / max(median(k_pre), _EPS), 4),
        "ratio_of_medians": round(ratio_of_medians(x, y), 4),
        "hl_shift": round(hodges_lehmann(x, y), 4),               # in multiples of the host's own baseline
        "hl_ratio": round(math.exp(hodges_lehmann(log_x, log_y)), 4),
        "u": mw["u"], "method": mw["method"],
        "canary_pre_median": median(c_pre), "canary_post_median": median(c_post),
        "reason": "",
    }


def _worst(verdicts: Iterable[str]) -> str:
    vs = list(verdicts)
    return max(vs, key=_SEVERITY.__getitem__) if vs else INCONCLUSIVE


def _score(checks: list[dict]) -> int | None:
    judged = [c for c in checks if c["verdict"] != INCONCLUSIVE]
    return round(100 * sum(c["verdict"] == PASS for c in judged) / len(judged)) if judged else None


def judge(observations: Iterable[dict], alpha: float = 0.01, min_effect: float = 1.15, exact_max_n: int = 250,
          min_samples: int = 5, min_controls: int = 3) -> dict:
    """Judge a canary. Each observation is
    ``{"host", "metric", "canary": {"pre", "post"}, "controls": {host: {"pre", "post"}}}``, optionally with
    ``"insufficient": reason`` (no usable control group) and descriptive ``"basis"`` / ``"cohort"``.

    Returns per-check verdicts, per-host verdicts, an overall verdict (worst check; INCONCLUSIVE only if
    nothing could be judged) and the canary score: 100 x share of judged checks that PASS.
    """
    checks: list[dict] = []
    for ob in observations:
        head = {"host": ob["host"], "metric": ob["metric"], "basis": ob.get("basis", "cohort"),
                "cohort": ob.get("cohort", ""), "controls": sorted(ob.get("controls", {}))}
        if ob.get("insufficient"):
            checks.append(head | {"verdict": INCONCLUSIVE, "reason": ob["insufficient"], "p_value": None, "effect": None,
                                  "n_canary": 0, "n_control": 0, "n_control_hosts": 0})
            continue
        ctl = {h: (s["pre"], s["post"]) for h, s in ob.get("controls", {}).items()}
        checks.append(head | compare_metric(ob["canary"]["pre"], ob["canary"]["post"], ctl, alpha, min_effect,
                                            exact_max_n, min_samples, min_controls))
    hosts: dict[str, dict] = {}
    for h in dict.fromkeys(c["host"] for c in checks):
        mine = [c for c in checks if c["host"] == h]
        hosts[h] = {"verdict": _worst(c["verdict"] for c in mine), "score": _score(mine),
                    "failed": [c["metric"] for c in mine if c["verdict"] == FAIL]}
    judged = [c["verdict"] for c in checks if c["verdict"] != INCONCLUSIVE]
    return {"verdict": _worst(judged) if judged else INCONCLUSIVE, "score": _score(checks), "checks": checks,
            "hosts": hosts, "alpha": alpha, "min_effect": min_effect}


# ---------------------------------------------------------------- controls
def select_controls(host: str, server_info: Mapping[str, dict], components: list[str], exclude: Iterable[str] = (),
                    min_controls: int = 3, population: Iterable[str] | None = None, widen_to_model: bool = True) -> dict:
    """Un-upgraded peers to compare ``host`` with.

    Same configuration cohort first (model + major version of every firmware component the change does
    not touch), excluding ``exclude`` (the current wave and hosts already changed). Fewer than
    ``min_controls`` widens to the same model; still fewer reports "insufficient controls".
    """
    pop = sorted(population if population is not None else server_info)
    if host not in pop:
        pop.append(host)
    skip = set(exclude) | {host}
    cohort = next(c for c in build_cohorts(pop, dict(server_info), components) if host in c["hosts"])
    same = [h for h in cohort["hosts"] if h not in skip]
    out = {"host": host, "cohort": cohort["label"], "available": {"cohort": len(same)}}
    if len(same) >= min_controls:
        return out | {"controls": same, "basis": "cohort", "reason": ""}
    model = server_info[host]["model"]
    wide = sorted(h for h in pop if h not in skip and server_info[h]["model"] == model)
    out["available"]["model"] = len(wide)
    if widen_to_model and len(wide) >= min_controls:
        return out | {"controls": wide, "basis": "model",
                      "reason": f"only {len(same)} un-upgraded peer(s) in cohort {cohort['label']}; widened to {short_model(model)}"}
    return out | {"controls": [], "basis": "insufficient",
                  "reason": f"insufficient controls: {len(same)} un-upgraded peer(s) in cohort {cohort['label']}"
                            + (f", {len(wide)} of model {short_model(model)}" if widen_to_model else "")
                            + f"; need {min_controls}"}


def changed_assets(executions: Iterable[dict]) -> set[str]:
    """Assets touched by any executed wave (their firmware changed, or they were evacuated)."""
    out: set[str] = set()
    for e in executions:
        out |= set(e.get("assets", [])) | set(e.get("evacuate", []))
        out |= {c["asset"] for c in e.get("firmware_changes", [])}
    return out


# ------------------------------------------------------------- integration
def params(policy) -> dict:
    """Judge settings from ``policy.yaml`` (section ``canary_stats``), with defaults."""
    def g(key, default):
        return policy.get(f"canary_stats.{key}", default)

    return {
        "enabled": bool(g("enabled", True)),
        "all_waves": bool(g("all_waves", False)),   # default: judge the canary wave only
        "alpha": float(g("alpha", 0.01)),
        "min_effect": float(g("min_effect", 1.15)),
        "metrics": list(g("metrics", list(DEFAULT_METRICS))),
        "pre_minutes": int(g("pre_minutes", 15)),
        "post_minutes": int(g("post_minutes", policy.get("execution.durations_min.soak", 10))),
        "min_controls": int(g("min_controls", 3)),
        "widen_to_model": bool(g("widen_to_model", True)),
        "min_samples": int(g("min_samples", 5)),
        "exact_max_n": int(g("exact_max_n", 250)),
    }


def _post_minutes(series: Mapping[int, float | None], t0: int, t1: int, post_minutes: int) -> list[int]:
    """Minutes after the canary's last maintenance sample, within the last ``post_minutes`` of the wave."""
    down = [t for t in range(t0, t1 + 1) if t in series and series[t] is None]
    start = max(t1 - post_minutes + 1, (max(down) + 1) if down else t0 + 1)
    return [t for t in range(start, t1 + 1) if series.get(t) is not None]


def _band(canary: Mapping[int, float | None], controls: Mapping[str, Mapping[int, float | None]],
          pre: list[int], lo: int, t1: int) -> list[dict]:
    """Per-minute canary vs control band, each host in multiples of its own pre-window median."""
    def base(s):
        vals = _clean(s.get(t) for t in pre)
        return max(median(vals), _EPS) if vals else None

    cb = base(canary)
    bases = {h: base(s) for h, s in controls.items()}
    rows = []
    for t in range(lo, t1 + 1):
        ys = [s[t] / bases[h] for h, s in controls.items() if bases[h] and s.get(t) is not None]
        v = canary.get(t)
        row = {"t_min": t, "canary": round(v / cb, 4) if (v is not None and cb) else None}
        if ys:
            row |= {"control_p10": round(quantile(ys, 0.1), 4), "control_median": round(quantile(ys, 0.5), 4),
                    "control_p90": round(quantile(ys, 0.9), 4)}
        rows.append(row)
    return rows


def analyse_wave(sv, wave_exec: dict, topo, components: list[str], exclude: Iterable[str] = (),
                 metrics: Iterable[str] | None = None, actor: str = "postcheck") -> dict:
    """Judge every server in an executed wave against its controls, reading telemetry over MCP.

    ``wave_exec`` is an ``ExecutorAgent.run_wave`` result (uses ``assets``, ``evacuate``, ``t_start_min``,
    ``t_end_min``); ``exclude`` adds hosts already changed by earlier waves (see :func:`changed_assets`).
    Returns :func:`judge`'s result plus ``controls``, ``windows``, a per-minute ``band`` for charts,
    ``regressions`` in the PostValidationAgent shape (FAIL checks only), ``warnings`` (MARGINAL) and
    the evidence ids of every series read.
    """
    p = params(sv.policy)
    metrics = list(metrics or p["metrics"])
    t0, t1 = int(wave_exec["t_start_min"]), int(wave_exec["t_end_min"])
    lo = t0 - p["pre_minutes"]
    pre_ts = list(range(lo, t0 + 1))
    canaries = [a for a in wave_exec["assets"] if a in topo.servers]
    skip = set(exclude) | set(wave_exec["assets"]) | set(wave_exec.get("evacuate", []))
    picks = {h: select_controls(h, topo.servers, components, skip, p["min_controls"], topo.servers, p["widen_to_model"])
             for h in canaries}
    cache: dict[tuple[str, str], dict[int, float | None]] = {}
    evidence: list[str] = []

    def fetch(host: str, metric: str) -> dict[int, float | None]:
        if (host, metric) not in cache:
            res, ev = sv.bus.call(actor, "telemetry.get_metric_series", asset=host, metric=metric, start_t=lo, end_t=t1)
            cache[(host, metric)] = {s["t_min"]: s["value"] for s in res}
            evidence.append(ev)
        return cache[(host, metric)]

    observations, band, post_windows = [], {}, {}
    for h in canaries:
        pick = picks[h]
        for m in metrics:
            ob = {"host": h, "metric": m, "basis": pick["basis"], "cohort": pick["cohort"]}
            if not pick["controls"]:
                observations.append(ob | {"insufficient": pick["reason"]})
                continue
            cs = fetch(h, m)
            post_ts = _post_minutes(cs, t0, t1, p["post_minutes"])
            post_windows[h] = [post_ts[0], post_ts[-1]] if post_ts else None
            ctl = {c: fetch(c, m) for c in pick["controls"]}
            ob["canary"] = {"pre": [cs.get(t) for t in pre_ts], "post": [cs.get(t) for t in post_ts]}
            ob["controls"] = {c: {"pre": [s.get(t) for t in pre_ts], "post": [s.get(t) for t in post_ts]} for c, s in ctl.items()}
            observations.append(ob)
            band.setdefault(h, {})[m] = _band(cs, ctl, pre_ts, lo, t1)
    res = judge(observations, p["alpha"], p["min_effect"], p["exact_max_n"], p["min_samples"], p["min_controls"])

    def describe(c: dict) -> str:
        what = METRIC_LABELS.get(c["metric"], c["metric"])
        if c["verdict"] == INCONCLUSIVE:
            return f"{what}: {c['reason']}"
        return (f"{what} {c['effect']:.2f}x vs {c['n_control_hosts']} {c['basis']} peers over the same minutes "
                f"(own change {c['canary_ratio']:.2f}x, peers {c['control_ratio']:.2f}x; Mann-Whitney p={c['p_value']:.2g})")

    for c in res["checks"]:
        c["message"] = describe(c)
    res["regressions"] = [{"asset": c["host"], "metric": c["metric"], "pre": c["canary_pre_median"], "post": c["canary_post_median"],
                           "message": c["message"], "check": "statistical"} for c in res["checks"] if c["verdict"] == FAIL]
    res["warnings"] = [{"asset": c["host"], "metric": c["metric"], "message": c["message"]}
                       for c in res["checks"] if c["verdict"] in (MARGINAL, INCONCLUSIVE)]
    res.update(controls=picks, band=band, evidence=evidence,
               windows={"pre": [lo, t0], "post": post_windows, "wave": [t0, t1]},
               params={k: p[k] for k in ("alpha", "min_effect", "pre_minutes", "post_minutes", "min_controls")})
    return res


def summary(res: dict) -> str:
    """One line for the timeline or the CLI."""
    checks = res.get("checks", [])
    if res["verdict"] == INCONCLUSIVE:
        why = next((c.get("reason") for c in checks if c.get("reason")), "no canary server to judge")
        return f"Statistical canary inconclusive: {why}"
    flagged = [c for c in checks if c["verdict"] in (FAIL, MARGINAL)]
    open_ = sum(c["verdict"] == INCONCLUSIVE for c in checks)
    head = (f"Statistical canary {res['verdict']} (score {res['score']}/100, {len(checks) - open_} checks vs un-upgraded peers"
            + (f", {open_} inconclusive" if open_ else "") + ")")
    if not flagged:
        return head
    return head + ": " + "; ".join(f"{c['host']} {c['verdict']} - {c.get('message', c['metric'])}" for c in flagged[:3])
