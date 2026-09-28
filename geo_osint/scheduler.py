"""
geo_osint.scheduler — lightweight periodic re-run scheduler (spec §28, §51 hooks).

A minimal async scheduler for *monitoring* use (the blue-team 20%): re-run a
Geo-OSINT job for a set of entities on a fixed interval and hand each result to a
callback (e.g. detect a new geographic observation, append to a timeline, alert on
a location change). It is infrastructure/asset monitoring only — it observes public
data about places on a schedule; it never tracks people or devices (spec §50).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, List, Optional

from .configuration import GeoConfig, GeoMode
from .orchestrator import GeoOrchestrator, OrchestrationResult

logger = logging.getLogger("modbot.geo_osint.scheduler")

ResultCallback = Callable[[OrchestrationResult], Awaitable[None]]


@dataclass
class ScheduledJob:
    name: str
    entities: List[str]
    interval_s: float
    last_run: float = 0.0
    runs: int = 0
    enabled: bool = True


class GeoScheduler:
    def __init__(self, config: Optional[GeoConfig] = None) -> None:
        self.config = config or GeoConfig.build(GeoMode.PASSIVE)
        self._orch = GeoOrchestrator(self.config)
        self._jobs: List[ScheduledJob] = []
        self._stop = asyncio.Event()

    def add_job(self, name: str, entities: List[str], interval_s: float) -> ScheduledJob:
        job = ScheduledJob(name=name, entities=list(entities),
                           interval_s=max(1.0, interval_s))
        self._jobs.append(job)
        return job

    def due(self, now: Optional[float] = None) -> List[ScheduledJob]:
        t = now if now is not None else time.time()
        return [j for j in self._jobs
                if j.enabled and (t - j.last_run) >= j.interval_s]

    async def run_once(self) -> dict:
        out = {}
        for job in self.due():
            try:
                res = await self._orch.run(job.entities)
                job.last_run = time.time()
                job.runs += 1
                out[job.name] = res
            except Exception as exc:
                logger.exception("scheduled job failed: %s", job.name)
                out[job.name] = exc
        return out

    async def run_forever(self, callback: Optional[ResultCallback] = None,
                          tick_s: float = 5.0) -> None:
        self._stop.clear()
        while not self._stop.is_set():
            for job in self.due():
                try:
                    res = await self._orch.run(job.entities)
                    job.last_run = time.time()
                    job.runs += 1
                    if callback is not None:
                        await callback(res)
                except Exception:
                    logger.exception("scheduled job failed: %s", job.name)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=tick_s)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()
