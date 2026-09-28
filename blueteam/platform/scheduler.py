"""
blueteam/platform/scheduler.py — a small persistent job scheduler (A5).

Jobs register a name, an interval and an async callable. ``next_run`` is persisted
through a :class:`JobStore` port so schedules survive restart; each run is guarded
by a **lease** (compare-and-set on ``locked_until``) so two workers never run the
same job twice. Jitter spreads runs; the **missed-run policy** is catch-up-once
(a job that missed many intervals while the bot was down runs a single time, not N
times). Heavy work goes to an executor; shutdown is graceful.

The scheduling *logic* (due calc, jitter, lease, missed-run) is pure and unit-tested
with a fake clock + in-memory store; SQLite is just one JobStore implementation.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Optional, Protocol

logger = logging.getLogger("modbot.blueteam.scheduler")


class JobStore(Protocol):
    def get_next_run(self, name: str) -> Optional[float]: ...
    def set_next_run(self, name: str, next_run: float) -> None: ...
    def try_lease(self, name: str, now: float, lease_seconds: float) -> bool: ...
    def release(self, name: str, next_run: float) -> None: ...


@dataclass
class _Job:
    name: str
    interval_s: float
    fn: Callable[[], Awaitable]
    jitter_s: float = 0.0
    lease_s: float = 300.0
    run_in_executor: bool = False


class Scheduler:
    def __init__(self, store: JobStore, clock=None, rng: Optional[random.Random] = None,
                 metrics=None):
        self._store = store
        self._clock = clock or (lambda: __import__("time").time())
        self._rng = rng or random.Random()
        self._metrics = metrics
        self._jobs: Dict[str, _Job] = {}
        self._stop = False

    def register(self, name: str, interval_s: float, fn: Callable[[], Awaitable], *,
                 jitter_s: float = 0.0, lease_s: float = 300.0,
                 run_in_executor: bool = False) -> None:
        self._jobs[name] = _Job(name, interval_s, fn, jitter_s, lease_s, run_in_executor)
        if self._store.get_next_run(name) is None:
            # First run is due immediately (plus optional jitter to spread startup).
            self._store.set_next_run(name, self._clock() + self._rng.uniform(0, jitter_s))

    def due_jobs(self, now: float) -> List[_Job]:
        out = []
        for job in self._jobs.values():
            nr = self._store.get_next_run(job.name)
            if nr is not None and nr <= now:
                out.append(job)
        return out

    def _next_run_after(self, job: _Job, now: float) -> float:
        jitter = self._rng.uniform(0, job.jitter_s) if job.jitter_s else 0.0
        return now + job.interval_s + jitter

    async def run_due_once(self) -> List[str]:
        """Run all currently-due jobs once (used by the driver and by tests)."""
        now = self._clock()
        ran: List[str] = []
        for job in self.due_jobs(now):
            if not self._store.try_lease(job.name, now, job.lease_s):
                continue  # someone else holds the lease
            try:
                if job.run_in_executor:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, lambda: asyncio.run(job.fn())
                                               if asyncio.iscoroutinefunction(job.fn) else job.fn())
                else:
                    await job.fn()
                ran.append(job.name)
                if self._metrics:
                    self._metrics.incr("bt_scheduler_runs", job=job.name)
            except Exception:
                logger.exception("SCHEDULER | job %s failed", job.name)
                if self._metrics:
                    self._metrics.incr("bt_scheduler_errors", job=job.name)
            finally:
                # catch-up-once: next_run is relative to *now*, never a backlog of missed slots
                self._store.release(job.name, self._next_run_after(job, self._clock()))
        return ran

    async def run_forever(self, tick_s: float = 5.0) -> None:
        self._stop = False
        while not self._stop:
            try:
                await self.run_due_once()
            except Exception:
                logger.exception("SCHEDULER | tick failed")
            await asyncio.sleep(tick_s)

    def stop(self) -> None:
        self._stop = True


class InMemoryJobStore:
    """A JobStore for tests / minimal deploys (no persistence across process)."""

    def __init__(self):
        self._next: Dict[str, float] = {}
        self._lease: Dict[str, float] = {}

    def get_next_run(self, name):
        return self._next.get(name)

    def set_next_run(self, name, next_run):
        self._next[name] = next_run

    def try_lease(self, name, now, lease_seconds):
        held = self._lease.get(name, 0.0)
        if held > now:
            return False
        self._lease[name] = now + lease_seconds
        return True

    def release(self, name, next_run):
        self._next[name] = next_run
        self._lease[name] = 0.0


__all__ = ["Scheduler", "JobStore", "InMemoryJobStore"]
