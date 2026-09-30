"""
cve_tracker.ingestion.ratelimit — per-source async token-bucket rate limiting.

Each source has its own limiter (NVD's window is nothing like GitHub's), so the
coordinator holds a :class:`RateLimiterRegistry` keyed by source name. The
bucket is async-safe and honours an externally-signalled ``Retry-After`` by
pushing its next-allowed time forward, so a 429 doesn't just get retried
blindly — it actually backs off the whole source.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict


class TokenBucket:
    """A refilling token bucket. ``rate`` tokens per second, burst capacity
    ``capacity`` (defaults to max(1, rate)). ``acquire`` awaits until a token is
    available, so callers naturally pace themselves."""

    def __init__(self, rate: float, capacity: float = 0.0):
        self.rate = max(0.001, float(rate))
        self.capacity = max(1.0, capacity or max(1.0, rate))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        # Absolute monotonic time before which no token is granted (Retry-After).
        self._blocked_until = 0.0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    async def acquire(self, tokens: float = 1.0) -> float:
        """Await until ``tokens`` are available. Returns the seconds spent
        waiting (useful for latency metrics)."""
        waited = 0.0
        while True:
            async with self._lock:
                now = time.monotonic()
                # Honour an external back-off window first.
                if now < self._blocked_until:
                    sleep_for = self._blocked_until - now
                else:
                    self._refill()
                    if self._tokens >= tokens:
                        self._tokens -= tokens
                        return waited
                    deficit = tokens - self._tokens
                    sleep_for = deficit / self.rate
            sleep_for = max(0.01, min(sleep_for, 60.0))
            waited += sleep_for
            await asyncio.sleep(sleep_for)

    def penalize(self, seconds: float) -> None:
        """Push the next-allowed time forward by ``seconds`` (a Retry-After).
        Also drains the bucket so nothing slips through before the window."""
        self._blocked_until = max(self._blocked_until, time.monotonic() + max(0.0, seconds))
        self._tokens = 0.0


class RateLimiterRegistry:
    """Lazily-created per-source token buckets."""

    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}

    def configure(self, source: str, rate: float, capacity: float = 0.0) -> TokenBucket:
        bucket = TokenBucket(rate, capacity)
        self._buckets[source] = bucket
        return bucket

    def get(self, source: str, default_rate: float = 1.0) -> TokenBucket:
        bucket = self._buckets.get(source)
        if bucket is None:
            bucket = TokenBucket(default_rate)
            self._buckets[source] = bucket
        return bucket

    def penalize(self, source: str, seconds: float) -> None:
        self.get(source).penalize(seconds)
