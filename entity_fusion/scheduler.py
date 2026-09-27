"""
entity_fusion.scheduler — a small async task scheduler with bounded concurrency
and optional global rate limiting, for fanning enrichment work out politely
across many public providers.

It is a thin coordination layer over ``asyncio`` and the OSINT framework's
``RateLimiter``: submit coroutines, and the scheduler runs at most
``concurrency`` at once, optionally spaced by a shared rate limit, collecting
results (and per-task exceptions) without one failing task sinking the batch.
Reuses ``osint.utils.async_http.RateLimiter`` when available, else a local copy
of the same token-bucket, so ``entity_fusion`` stays importable standalone.
"""

from __future__ import annotations

import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, List, Optional

logger = logging.getLogger("modbot.entity_fusion.scheduler")

try:
    from osint.utils.async_http import RateLimiter  # reuse the tested one
except Exception:  # pragma: no cover - standalone fallback
    class RateLimiter:  # type: ignore
        """Minimal asyncio token-bucket (mirrors osint.utils.async_http)."""
        def __init__(self, rate: float, burst: Optional[int] = None):
            if rate <= 0:
                raise ValueError("rate must be > 0")
            self.rate = float(rate)
            self.burst = float(burst if burst is not None else max(1.0, rate))
            self._tokens = self.burst
            self._updated = time.monotonic()
            self._lock = asyncio.Lock()

        async def acquire(self) -> None:
            while True:
                async with self._lock:
                    now = time.monotonic()
                    self._tokens = min(self.burst,
                                       self._tokens + (now - self._updated) * self.rate)
                    self._updated = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    wait = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait)


@dataclass
class TaskOutcome:
    index: int
    ok: bool
    value: Any = None
    error: str = ""
    elapsed_ms: int = 0


@dataclass
class BatchResult:
    outcomes: List[TaskOutcome] = field(default_factory=list)

    @property
    def values(self) -> List[Any]:
        return [o.value for o in self.outcomes if o.ok]

    @property
    def errors(self) -> List[str]:
        return [o.error for o in self.outcomes if not o.ok]

    def stats(self) -> dict:
        return {"total": len(self.outcomes),
                "ok": sum(1 for o in self.outcomes if o.ok),
                "failed": len(self.errors)}


class AsyncScheduler:
    """Run coroutine factories with bounded concurrency + optional rate limit."""

    def __init__(self, *, concurrency: int = 8, rate: Optional[float] = None,
                 per_task_timeout: float = 60.0):
        self.concurrency = max(1, int(concurrency))
        self.limiter = RateLimiter(rate) if rate else None
        self.per_task_timeout = per_task_timeout

    async def run(self, factories: List[Callable[[], Awaitable[Any]]]) -> BatchResult:
        """Each element of ``factories`` is a zero-arg callable returning a
        coroutine (a factory, not a coroutine, so nothing starts before the
        semaphore admits it)."""
        sem = asyncio.Semaphore(self.concurrency)
        result = BatchResult(outcomes=[None] * len(factories))  # type: ignore

        async def _run(idx: int, factory: Callable[[], Awaitable[Any]]) -> None:
            start = time.monotonic()
            async with sem:
                if self.limiter is not None:
                    await self.limiter.acquire()
                try:
                    value = await asyncio.wait_for(factory(),
                                                   timeout=self.per_task_timeout)
                    result.outcomes[idx] = TaskOutcome(
                        idx, True, value,
                        elapsed_ms=int((time.monotonic() - start) * 1000))
                except Exception as exc:
                    result.outcomes[idx] = TaskOutcome(
                        idx, False, error=f"{type(exc).__name__}: {exc}",
                        elapsed_ms=int((time.monotonic() - start) * 1000))

        await asyncio.gather(*(_run(i, f) for i, f in enumerate(factories)))
        return result
