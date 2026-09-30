"""
cve_tracker.monitoring.metrics — in-process counters, gauges and timers.

Lightweight observability (rule §30) with no external dependency: named
counters (records ingested, AI failures, alerts sent), gauges (queue depth,
cache size) and timers (source latency, AI latency). A :meth:`snapshot` renders
the current state for ``/cve_status`` and logs. Nothing here logs secrets
(rule §30) — only aggregate numbers and source/metric names.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict


class Timer:
    """Accumulates count + total + max for a latency series."""

    __slots__ = ("count", "total_ms", "max_ms")

    def __init__(self):
        self.count = 0
        self.total_ms = 0.0
        self.max_ms = 0.0

    def observe(self, ms: float) -> None:
        self.count += 1
        self.total_ms += ms
        if ms > self.max_ms:
            self.max_ms = ms

    @property
    def avg_ms(self) -> float:
        return self.total_ms / self.count if self.count else 0.0

    def to_dict(self) -> Dict[str, float]:
        return {"count": self.count, "avg_ms": round(self.avg_ms, 1),
                "max_ms": round(self.max_ms, 1)}


class MetricsRegistry:
    def __init__(self):
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, Timer] = defaultdict(Timer)
        self._lock = threading.RLock()
        self.started_at = time.time()

    def incr(self, name: str, value: float = 1.0) -> None:
        with self._lock:
            self._counters[name] += value

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, ms: float) -> None:
        with self._lock:
            self._timers[name].observe(ms)

    def counter(self, name: str) -> float:
        return self._counters.get(name, 0.0)

    def timer(self, name: str) -> Timer:
        return self._timers.get(name, Timer())

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "uptime_s": int(time.time() - self.started_at),
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "timers": {k: v.to_dict() for k, v in self._timers.items()},
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()


# Canonical metric names, referenced across the codebase so a typo can't split a
# series silently.
M_RECORDS_SEEN = "ingest.records_seen"
M_RECORDS_NEW = "ingest.records_new"
M_RECORDS_UPDATED = "ingest.records_updated"
M_RECORDS_FAILED = "ingest.records_failed"
M_ROUND = "ingest.rounds"
M_SOURCE_LATENCY = "source.latency_ms"
M_SOURCE_FAIL = "source.failures"
M_AI_CALLS = "ai.calls"
M_AI_FAIL = "ai.failures"
M_AI_FALLBACK = "ai.fallback"
M_AI_LATENCY = "ai.latency_ms"
M_ALERTS_SENT = "alerts.sent"
M_ALERTS_FAILED = "alerts.failed"
M_ALERTS_SUPPRESSED = "alerts.suppressed"
M_DELIVERY_LATENCY = "alerts.delivery_ms"
M_QUEUE_DEPTH = "alerts.queue_depth"
M_DUPLICATE_RATE = "ingest.duplicate_rate"
M_CACHE_HIT_RATE = "cache.hit_rate"
