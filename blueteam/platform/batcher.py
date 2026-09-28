"""
blueteam/platform/batcher.py — write-behind batcher for high-frequency writes (A4).

Sightings, rule hits and metric rows are written through this so the event loop is
never blocked on SQLite. Items are appended to a bounded in-memory buffer; the
buffer is flushed to the ``flush_fn`` (a batched, parameterized insert) when it
reaches ``max_batch``, every ``max_interval_s``, or on ``shutdown``. The flush runs
in a thread executor (``run_forever``), so the DB write is off the loop.

Backpressure: the buffer is hard-capped at ``max_pending``. When full, ``add``
drops the *oldest* item and increments ``dropped`` (surfaced as a metric) rather
than growing without bound or blocking the producer — a defensive choice for a
telemetry path where losing a few rows under extreme load beats stalling
moderation.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from typing import Any, Callable, Deque, List, Optional

logger = logging.getLogger("modbot.blueteam.batcher")


class WriteBehindBatcher:
    def __init__(self, flush_fn: Callable[[List[Any]], None], *,
                 max_batch: int = 200, max_interval_s: float = 2.0,
                 max_pending: int = 10000, name: str = "batcher",
                 metrics=None):
        self._flush_fn = flush_fn
        self._max_batch = max_batch
        self._max_interval = max_interval_s
        self._max_pending = max_pending
        self._name = name
        self._metrics = metrics
        self._buf: Deque[Any] = deque()
        self._lock = threading.Lock()
        self._wake: Optional[asyncio.Event] = None
        self._stop = False
        self.dropped = 0
        self.flushed = 0

    def add(self, item: Any) -> None:
        with self._lock:
            if len(self._buf) >= self._max_pending:
                self._buf.popleft()
                self.dropped += 1
                if self._metrics:
                    self._metrics.incr("bt_batcher_dropped", name=self._name)
            self._buf.append(item)
            full = len(self._buf) >= self._max_batch
        if full and self._wake is not None:
            try:
                self._wake.set()
            except Exception:
                pass

    def _drain(self) -> List[Any]:
        with self._lock:
            if not self._buf:
                return []
            items = list(self._buf)
            self._buf.clear()
            return items

    def flush_sync(self) -> int:
        """Flush immediately on the calling thread (used at shutdown/tests)."""
        items = self._drain()
        if not items:
            return 0
        try:
            self._flush_fn(items)
            self.flushed += len(items)
            if self._metrics:
                self._metrics.incr("bt_batcher_flushed", len(items), name=self._name)
        except Exception:
            logger.exception("BATCHER %s | flush failed for %d items",
                             self._name, len(items))
        return len(items)

    async def run_forever(self) -> None:
        """Periodic driver: flush on interval or when the buffer signals full.
        The actual write runs in a thread executor so the loop is never blocked."""
        self._wake = asyncio.Event()
        loop = asyncio.get_running_loop()
        while not self._stop:
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=self._max_interval)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            if self._buf:
                await loop.run_in_executor(None, self.flush_sync)
        await loop.run_in_executor(None, self.flush_sync)  # final drain

    def stop(self) -> None:
        self._stop = True
        if self._wake is not None:
            try:
                self._wake.set()
            except Exception:
                pass

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._buf)


__all__ = ["WriteBehindBatcher"]
