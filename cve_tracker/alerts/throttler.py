"""
cve_tracker.alerts.throttler — a priority send queue with flood-control safety.

A CVE burst can be hundreds of records (rule §23). The throttler is a bounded
**priority queue** with a global send-rate token bucket: higher-priority alerts
(KEV added, new CRITICAL) drain first, sends are paced so Telegram flood control
is rarely hit, and when it IS hit (``retry_after``) the whole queue pauses for
that window instead of hammering. Nothing is dropped silently — an item that
can't be sent is requeued with a bounded attempt count.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
from dataclasses import dataclass, field
from typing import Any, Optional

from ..ingestion.ratelimit import TokenBucket


@dataclass(order=True)
class _QueueItem:
    # heapq is a min-heap; we negate priority so higher priority pops first.
    sort_key: tuple
    seq: int = field(compare=True)
    payload: Any = field(compare=False, default=None)
    attempts: int = field(compare=False, default=0)


class AlertThrottler:
    def __init__(self, *, send_rate_per_sec: float = 0.7, max_attempts: int = 4,
                 max_queue: int = 5000):
        self.bucket = TokenBucket(send_rate_per_sec, capacity=max(1.0, send_rate_per_sec * 2))
        self.max_attempts = max_attempts
        self.max_queue = max_queue
        self._heap: list = []
        self._counter = itertools.count()
        self._lock = asyncio.Lock()
        self._paused_until = 0.0

    def __len__(self) -> int:
        return len(self._heap)

    @property
    def depth(self) -> int:
        return len(self._heap)

    async def enqueue(self, payload: Any, *, priority: int = 0, attempts: int = 0) -> bool:
        """Add an item. Returns False if the queue is full (caller should log a
        failure rather than block ingestion)."""
        async with self._lock:
            if len(self._heap) >= self.max_queue:
                return False
            seq = next(self._counter)
            # higher priority first, then FIFO by seq
            item = _QueueItem(sort_key=(-priority, seq), seq=seq,
                              payload=payload, attempts=attempts)
            heapq.heappush(self._heap, item)
            return True

    async def _pop(self) -> Optional[_QueueItem]:
        async with self._lock:
            if not self._heap:
                return None
            return heapq.heappop(self._heap)

    async def acquire_slot(self) -> None:
        """Await a send slot (paces the global send rate)."""
        import time
        now = time.monotonic()
        if now < self._paused_until:
            await asyncio.sleep(self._paused_until - now)
        await self.bucket.acquire()

    def pause(self, seconds: float) -> None:
        """Flood-control back-off: pause all sends for ``seconds``."""
        import time
        self._paused_until = max(self._paused_until, time.monotonic() + max(0.0, seconds))
        self.bucket.penalize(seconds)

    async def drain(self, send_fn, *, max_items: int = 1000) -> dict:
        """Drain up to ``max_items`` items, calling ``await send_fn(payload)``
        for each under the rate limit. ``send_fn`` returns one of:
          * True                 → sent OK
          * ('retry', seconds)   → flood control; pause and requeue
          * False                → permanent failure; drop (counted)
        Returns a small stats dict.
        """
        sent = failed = requeued = 0
        processed = 0
        while processed < max_items:
            item = await self._pop()
            if item is None:
                break
            processed += 1
            await self.acquire_slot()
            try:
                outcome = await send_fn(item.payload)
            except Exception:
                outcome = ("retry", 5.0)

            if outcome is True:
                sent += 1
            elif isinstance(outcome, tuple) and outcome and outcome[0] == "retry":
                delay = float(outcome[1]) if len(outcome) > 1 else 5.0
                self.pause(delay)
                if item.attempts + 1 < self.max_attempts:
                    await self.enqueue(item.payload,
                                       priority=-item.sort_key[0],
                                       attempts=item.attempts + 1)
                    requeued += 1
                else:
                    failed += 1
            else:
                failed += 1
        return {"sent": sent, "failed": failed, "requeued": requeued,
                "remaining": len(self._heap)}
