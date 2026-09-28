"""
behavioral_intelligence.util — small, dependency-free numeric and text helpers
shared across the analytical engines.

Everything here is standard-library only and total (never raises on empty or
degenerate input — an empty series returns a well-defined zero, not a
ZeroDivisionError), because these run inside the statistical core that must work
without numpy/scipy. Where a heavier library would be used in a data-science
context, the equivalent is implemented explicitly so the result is auditable and
the dependency optional.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Iterable, List, Sequence, Tuple

DAY_SECONDS = 86400.0
HOUR_SECONDS = 3600.0

WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
HOUR_LABELS = [f"{h:02d}" for h in range(24)]


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    return numerator / denominator if denominator else default


def mean(values: Sequence[float]) -> float:
    return safe_div(float(sum(values)), len(values))


def median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def stdev(values: Sequence[float]) -> float:
    """Population standard deviation (0.0 for <2 samples)."""
    n = len(values)
    if n < 2:
        return 0.0
    m = mean(values)
    var = sum((v - m) ** 2 for v in values) / n
    return math.sqrt(var)


def sample_stdev(values: Sequence[float]) -> float:
    """Sample (n-1) standard deviation (0.0 for <2 samples)."""
    n = len(values)
    if n < 2:
        return 0.0
    m = mean(values)
    var = sum((v - m) ** 2 for v in values) / (n - 1)
    return math.sqrt(var)


def zscore(value: float, m: float, sd: float) -> float:
    return safe_div(value - m, sd) if sd else 0.0


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolation percentile, q in [0,100]. Empty -> 0.0."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    rank = (q / 100.0) * (len(s) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return float(s[lo])
    frac = rank - lo
    return s[lo] * (1 - frac) + s[hi] * frac


def pearson(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Pearson correlation coefficient, total. Returns 0.0 when either series is
    constant or lengths differ / are < 2."""
    n = min(len(xs), len(ys))
    if n < 2:
        return 0.0
    xs, ys = xs[:n], ys[:n]
    mx, my = mean(xs), mean(ys)
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    vy = math.sqrt(sum((y - my) ** 2 for y in ys))
    return safe_div(cov, vx * vy)


def histogram_intersection(a: Sequence[float], b: Sequence[float]) -> float:
    """Normalised histogram intersection in [0,1]: sum(min(a_i,b_i)) after each
    histogram is L1-normalised. 1.0 = identical shape, 0.0 = disjoint."""
    sa, sb = float(sum(a)), float(sum(b))
    if sa <= 0 or sb <= 0:
        return 0.0
    na = [x / sa for x in a]
    nb = [x / sb for x in b]
    n = min(len(na), len(nb))
    return sum(min(na[i], nb[i]) for i in range(n))


def shares(counter: Dict[str, int]) -> Dict[str, float]:
    """Turn a count dict into a share (fraction) dict summing to ~1.0."""
    total = float(sum(counter.values()))
    if total <= 0:
        return {}
    return {k: v / total for k, v in counter.items()}


def entropy(dist: Iterable[float]) -> float:
    """Shannon entropy (bits) of a probability distribution."""
    h = 0.0
    for p in dist:
        if p > 0:
            h -= p * math.log2(p)
    return h


def kl_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    """KL(p||q) over the union of keys, with q smoothed to avoid infinities."""
    keys = set(p) | set(q)
    eps = 1e-9
    total = 0.0
    for k in keys:
        pk = p.get(k, 0.0)
        qk = q.get(k, 0.0) + eps
        if pk > 0:
            total += pk * math.log2(pk / qk)
    return total


def jensen_shannon(p: Dict[str, float], q: Dict[str, float]) -> float:
    """Jensen–Shannon distance (sqrt of divergence) in [0,1] over string-keyed
    distributions. Symmetric, bounded — used for drift between two windows."""
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    m = {k: 0.5 * (p.get(k, 0.0) + q.get(k, 0.0)) for k in keys}
    div = 0.5 * kl_divergence(p, m) + 0.5 * kl_divergence(q, m)
    div = max(0.0, div)
    return math.sqrt(min(1.0, div))


def top_n(counter: Dict[str, float], n: int) -> List[Tuple[str, float]]:
    return sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:n]


def counts(items: Iterable[str]) -> Counter:
    return Counter(x for x in items if x)


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def seq_similarity(a: str, b: str) -> float:
    """1 - normalised Levenshtein distance between two strings, in [0,1].
    Used for username/alias comparison. Total: two empties are identical (1.0),
    one empty is 0.0."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return 1.0 - prev[lb] / max(la, lb)


def round_dict(d: Dict[str, float], ndigits: int = 3) -> Dict[str, float]:
    return {k: round(v, ndigits) for k, v in d.items()}
