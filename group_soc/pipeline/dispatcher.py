"""
group_soc/pipeline/dispatcher.py — the async worker that drains the bounded queue.

Heavy work (correlation, detection, scoring, alerting) runs here, off the Telegram
update path (rule §20): the bus handler only normalizes + submits, returning fast.
The queue is size-capped; on overflow the oldest pending item is dropped and counted
(rule §21 backpressure). The worker is a single background task started at plugin
setup and cancelled at shutdown; no new OS processes (rule §19).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .pipeline import Pipeline
from .stages import PipelineContext
from .backpressure import BackpressureStats

logger = logging.getLogger("modbot.group_soc.dispatcher")


class PipelineWorker:
    def __init__(self, pipeline: Pipeline, *, maxsize: int = 2000,
                 poll_interval: float = 0.5):
        self.pipeline = pipeline
        self.maxsize = max(16, int(maxsize))
        self.poll_interval = max(0.05, float(poll_interval))
        self.stats = BackpressureStats()
        self._queue: "asyncio.Queue[PipelineContext]" = asyncio.Queue(maxsize=self.maxsize)
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ---- lifecycle ----
    def start(self) -> None:
        if self._running:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.info("SOC worker: no running loop; will drain on demand")
            return
        self._running = True
        self._task = loop.create_task(self._drain())
        logger.info("SOC pipeline worker started (maxsize=%d)", self.maxsize)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    # ---- submission (non-blocking, bounded) ----
    def submit(self, ctx: PipelineContext) -> bool:
        """Enqueue for background processing. Never blocks; on a full queue drops the
        oldest pending item so the newest is kept. Returns True if accepted."""
        self.stats.submitted += 1
        try:
            self._queue.put_nowait(ctx)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                self.stats.dropped_overflow += 1
            except asyncio.QueueEmpty:
                pass
            try:
                self._queue.put_nowait(ctx)
            except asyncio.QueueFull:
                self.stats.dropped_overflow += 1
                return False
        depth = self._queue.qsize()
        if depth > self.stats.max_depth_seen:
            self.stats.max_depth_seen = depth
        return True

    def depth(self) -> int:
        return self._queue.qsize()

    # ---- draining ----
    async def _drain(self) -> None:
        while self._running:
            try:
                ctx = await asyncio.wait_for(self._queue.get(), timeout=self.poll_interval)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                await self.pipeline.run(ctx)
                self.stats.processed += 1
            except Exception:
                self.stats.dropped_error += 1
                logger.exception("SOC pipeline run failed")
            finally:
                self._queue.task_done()

    async def process_now(self, ctx: PipelineContext) -> PipelineContext:
        """Synchronously run the pipeline for one context (used in tests and when no
        background worker is running). Counts toward processed stats."""
        result = await self.pipeline.run(ctx)
        self.stats.processed += 1
        return result
