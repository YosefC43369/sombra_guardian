"""
cve_tracker.scheduler — the periodic polling loop with graceful shutdown.

Drives the coordinator on ``poll_interval`` (rule §6: fast detection), hands each
round's new/updated records to the dispatcher, and runs retention on a slower
cadence. Shutdown is cooperative: :meth:`stop` sets an event the loop checks
between steps and awaits the current round to a bounded degree, so the bot can
stop without corrupting state or leaking the task (rule §59). The loop never
lets an exception escape — a failed round is logged and the next tick proceeds.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .monitoring.metrics import (
    M_ALERTS_SENT, M_ALERTS_FAILED, M_ALERTS_SUPPRESSED, M_QUEUE_DEPTH,
)

logger = logging.getLogger("modbot.cve.scheduler")


class CVEScheduler:
    def __init__(self, config, coordinator, dispatcher, *, retention=None,
                 metrics=None, on_round=None):
        self.config = config
        self.coordinator = coordinator
        self.dispatcher = dispatcher
        self.retention = retention
        self.metrics = metrics
        self.on_round = on_round            # callback(RoundResult) — optional
        self._stop = asyncio.Event()
        self._running = False
        self._last_retention = 0.0
        self._retention_interval = 6 * 3600  # run retention every ~6h

    @property
    def running(self) -> bool:
        return self._running

    async def run(self) -> None:
        """The background loop. Returns only after :meth:`stop`."""
        self._running = True
        # small initial delay so bot startup isn't competed with
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass

        while not self._stop.is_set():
            cycle_started = time.monotonic()
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("CVE SCHEDULER tick error")
            # wait for the interval or an early stop
            elapsed = time.monotonic() - cycle_started
            wait = max(1.0, self.config.poll_interval - elapsed)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass
        self._running = False
        logger.info("CVE SCHEDULER stopped")

    async def _tick(self) -> None:
        result = await self.coordinator.run_round()
        if self.on_round:
            try:
                self.on_round(result)
            except Exception:
                pass
        logger.info("CVE ROUND | %s", result.summary)

        # dispatch alerts (dispatcher may be None in a collector-only mode)
        if self.dispatcher is not None:
            if result.new_records:
                stats = await self.dispatcher.dispatch_new(result.new_records)
                self._record_alert_metrics(stats)
            if result.updated_pairs:
                stats = await self.dispatcher.dispatch_updates(result.updated_pairs)
                self._record_alert_metrics(stats)
            # Retry any notifications still pending from a previous round
            # (flood-control back-offs, transient send failures — rule §22).
            try:
                await self.dispatcher.redrive_pending()
            except Exception:
                logger.exception("CVE redrive_pending error")

        # periodic retention
        now = time.monotonic()
        if self.retention and (now - self._last_retention) > self._retention_interval:
            self._last_retention = now
            try:
                deleted = self.retention.run()
                if deleted:
                    logger.info("CVE RETENTION | %s", deleted)
            except Exception:
                logger.exception("CVE RETENTION error")

    def _record_alert_metrics(self, stats: dict) -> None:
        if not self.metrics or not stats:
            return
        self.metrics.incr(M_ALERTS_SENT, stats.get("sent", 0))
        self.metrics.incr(M_ALERTS_FAILED, stats.get("failed", 0))
        self.metrics.incr(M_ALERTS_SUPPRESSED, stats.get("suppressed", 0))
        self.metrics.gauge(M_QUEUE_DEPTH, stats.get("remaining", 0))

    def stop(self) -> None:
        self._stop.set()

    async def run_once(self) -> "object":
        """A single round + dispatch, for manual /cve_sync. Returns the
        RoundResult."""
        result = await self.coordinator.run_round()
        if self.dispatcher is not None:
            if result.new_records:
                self._record_alert_metrics(await self.dispatcher.dispatch_new(result.new_records))
            if result.updated_pairs:
                self._record_alert_metrics(await self.dispatcher.dispatch_updates(result.updated_pairs))
        return result
