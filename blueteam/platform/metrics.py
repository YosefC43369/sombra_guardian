"""
blueteam/platform/metrics.py — a tiny in-process metrics registry (A7).

No dependency: counters, gauges, and fixed-bucket histograms. Thread-safe (a lock
around cheap ops). Exposed via ``/blueteam metrics`` (OWNER). Never records secrets
— label values are caller-controlled and should be low-cardinality identifiers.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Tuple

# Fixed latency buckets in milliseconds (upper bounds); last is +Inf.
_DEFAULT_BUCKETS_MS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 1000)


def _key(name: str, labels: Tuple[Tuple[str, str], ...]) -> str:
    if not labels:
        return name
    return name + "{" + ",".join(f"{k}={v}" for k, v in labels) + "}"


class _Histogram:
    __slots__ = ("buckets", "counts", "sum", "count")

    def __init__(self, buckets: Tuple[float, ...]):
        self.buckets = buckets
        self.counts = [0] * (len(buckets) + 1)
        self.sum = 0.0
        self.count = 0

    def observe(self, value: float) -> None:
        self.sum += value
        self.count += 1
        for i, ub in enumerate(self.buckets):
            if value <= ub:
                self.counts[i] += 1
                return
        self.counts[-1] += 1

    def percentile(self, p: float) -> float:
        if self.count == 0:
            return 0.0
        target = p / 100.0 * self.count
        cum = 0
        edges = list(self.buckets) + [float("inf")]
        for i, c in enumerate(self.counts):
            cum += c
            if cum >= target:
                return edges[i]
        return edges[-1]

    def snapshot(self) -> dict:
        return {"count": self.count, "sum_ms": round(self.sum, 3),
                "avg_ms": round(self.sum / self.count, 4) if self.count else 0.0,
                "p50_ms": self.percentile(50), "p95_ms": self.percentile(95),
                "p99_ms": self.percentile(99)}


class MetricsRegistry:
    def __init__(self, buckets: Tuple[float, ...] = _DEFAULT_BUCKETS_MS):
        self._buckets = buckets
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._hist: Dict[str, _Histogram] = {}
        self._lock = threading.Lock()

    def incr(self, name: str, value: float = 1.0, **labels) -> None:
        k = _key(name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[k] = self._counters.get(k, 0.0) + value

    def gauge(self, name: str, value: float, **labels) -> None:
        k = _key(name, tuple(sorted(labels.items())))
        with self._lock:
            self._gauges[k] = value

    def observe(self, name: str, value_ms: float, **labels) -> None:
        k = _key(name, tuple(sorted(labels.items())))
        with self._lock:
            h = self._hist.get(k)
            if h is None:
                h = self._hist[k] = _Histogram(self._buckets)
            h.observe(value_ms)

    def timer(self, name: str, **labels) -> "_Timer":
        return _Timer(self, name, labels)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "counters": dict(sorted(self._counters.items())),
                "gauges": dict(sorted(self._gauges.items())),
                "histograms": {k: h.snapshot() for k, h in sorted(self._hist.items())},
            }

    def render(self) -> str:
        snap = self.snapshot()
        lines: List[str] = ["📊 Blue Team metrics"]
        if snap["counters"]:
            lines.append("counters:")
            lines += [f"  {k} = {int(v) if v == int(v) else round(v,3)}"
                      for k, v in snap["counters"].items()]
        if snap["gauges"]:
            lines.append("gauges:")
            lines += [f"  {k} = {round(v,3)}" for k, v in snap["gauges"].items()]
        if snap["histograms"]:
            lines.append("latency (ms):")
            for k, h in snap["histograms"].items():
                lines.append(f"  {k}: n={h['count']} p50={h['p50_ms']} "
                             f"p95={h['p95_ms']} p99={h['p99_ms']}")
        return "\n".join(lines)


class _Timer:
    __slots__ = ("_reg", "_name", "_labels", "_t0")

    def __init__(self, reg: MetricsRegistry, name: str, labels: dict):
        self._reg, self._name, self._labels = reg, name, labels
        self._t0 = 0.0

    def __enter__(self):
        import time
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        import time
        self._reg.observe(self._name, (time.perf_counter() - self._t0) * 1000.0,
                          **self._labels)


# process-wide default registry
_REGISTRY = MetricsRegistry()


def get_metrics() -> MetricsRegistry:
    return _REGISTRY


__all__ = ["MetricsRegistry", "get_metrics"]
