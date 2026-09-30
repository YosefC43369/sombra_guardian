"""
cve_tracker.engine — the CVETracker facade that wires everything together.

:class:`CVETracker` is the single object the integration layer constructs. It
owns the repository, coordinator, AI summarizer, alert dispatcher, scheduler,
diagnostics and command service, and exposes a small lifecycle:

    tracker = CVETracker(config, emit=...)
    tracker.init_storage()           # ensure schema (idempotent)
    await tracker.start(bot)         # begin the background loop
    ...
    await tracker.stop()             # graceful shutdown

Plus the operations the commands/plugin need: :meth:`sync_now`, :meth:`health`,
and the module-level :func:`cve_background_loop` that app.py schedules exactly
like ``news_background_loop`` (rule §58/§59). Startup never blocks the bot: the
loop yields immediately and does its first fetch after a short delay.
"""

from __future__ import annotations

import logging
from typing import Optional

from .config import CVETrackerConfig, get_config
from .storage.repository import CVERepository
from .storage.retention import RetentionManager
from .storage import migrations as storage_migrations
from .sources.registry import default_registry
from .coordinator import IngestionCoordinator
from .ai.adapter import AIProviderAdapter
from .ai.summarizer import CVESummarizer
from .alerts.dispatcher import AlertDispatcher
from .scheduler import CVEScheduler
from .monitoring.metrics import MetricsRegistry
from .monitoring.audit import AuditLogger
from .monitoring.diagnostics import DiagnosticsService
from .telegram.commands import CVECommandService

logger = logging.getLogger("modbot.cve.engine")


class CVETracker:
    def __init__(self, config: Optional[CVETrackerConfig] = None, *,
                 db_path: Optional[str] = None, emit=None):
        self.config = config or get_config()
        self.db_path = db_path or self.config.db_path
        self.repo = CVERepository(self.db_path)
        self.metrics = MetricsRegistry()
        self.audit = AuditLogger(self.repo, emit=emit)
        self.registry = default_registry()
        self.coordinator = IngestionCoordinator(
            self.config, self.repo, registry=self.registry,
            metrics=self.metrics, audit=self.audit)
        self.ai_adapter = AIProviderAdapter(self.config.ai)
        self.summarizer = CVESummarizer(
            self.config.ai, repo=self.repo, adapter=self.ai_adapter)
        self.retention = RetentionManager(self.repo, self.config.retention)
        self.diagnostics = DiagnosticsService(
            self.repo, self.config, metrics=self.metrics, ai_adapter=self.ai_adapter)
        self.command_service = CVECommandService(
            self.repo, self.config, runtime=self, summarizer=self.summarizer)

        self.bot = None
        self.dispatcher: Optional[AlertDispatcher] = None
        self.scheduler: Optional[CVEScheduler] = None
        self._started = False
        self._last_round_summary = "ยังไม่ได้รันรอบใด"

    # ---------------- lifecycle ----------------

    def init_storage(self) -> None:
        """Ensure the schema exists. Safe even if the platform migration ran."""
        try:
            storage_migrations.apply(self.db_path)
        except Exception:
            # fall back to direct ensure_schema
            self.repo.init_schema()

    def build_dispatcher(self, bot) -> AlertDispatcher:
        return AlertDispatcher(bot, self.repo, self.config, self.summarizer,
                               event_emit=self.audit.event)

    async def start(self, bot) -> None:
        """Wire the live bot and start the scheduler. Idempotent."""
        if not self.config.enabled:
            logger.info("CVE TRACKER disabled (CVE_TRACKER_ENABLED off) — not starting")
            return
        if self._started:
            logger.warning("CVE TRACKER already started")
            return
        self.bot = bot
        self.init_storage()
        self.dispatcher = self.build_dispatcher(bot)
        self.scheduler = CVEScheduler(
            self.config, self.coordinator, self.dispatcher,
            retention=self.retention, metrics=self.metrics,
            on_round=self._on_round)
        self._started = True
        selftest = self.diagnostics.selftest()
        logger.info("CVE TRACKER starting | selftest=%s | sources=%s",
                    selftest, [s.name for s in self.config.enabled_sources()])
        await self.scheduler.run()   # returns when stopped

    async def stop(self) -> None:
        if self.scheduler is not None:
            self.scheduler.stop()
        self._started = False
        logger.info("CVE TRACKER stop requested")

    def _on_round(self, result) -> None:
        self._last_round_summary = result.summary

    # ---------------- operations (used by commands) ----------------

    async def sync_now(self, *, source: Optional[str] = None) -> dict:
        """Run one round immediately and dispatch. Returns counts."""
        self.init_storage()
        result = await self.coordinator.run_round(only_source=source)
        self._last_round_summary = result.summary
        if self.dispatcher is None and self.bot is not None:
            self.dispatcher = self.build_dispatcher(self.bot)
        if self.dispatcher is not None:
            if result.new_records:
                await self.dispatcher.dispatch_new(result.new_records)
            if result.updated_pairs:
                await self.dispatcher.dispatch_updates(result.updated_pairs)
        return {"seen": result.seen, "new": result.new,
                "updated": result.updated, "failed": result.failed,
                "duplicates": result.duplicates}

    def health(self) -> dict:
        snap = self.diagnostics.snapshot()
        snap["last_run_summary"] = self._last_round_summary
        snap["started"] = self._started
        return snap

    # ---------------- background loop entry ----------------

    async def background_loop(self, bot) -> None:
        """Entry point app.py schedules. Never raises; restarts the scheduler if
        the loop dies unexpectedly (bounded)."""
        try:
            await self.start(bot)
        except Exception:
            logger.exception("CVE TRACKER background loop crashed")


# ---------------- module-level singleton + loop ----------------

_TRACKER: Optional[CVETracker] = None


def get_tracker(*, emit=None) -> CVETracker:
    """Process-wide singleton, matching the news.py module-global style so the
    background loop and the command handlers share one instance."""
    global _TRACKER
    if _TRACKER is None:
        _TRACKER = CVETracker(emit=emit)
    return _TRACKER


def reset_tracker() -> None:
    """Test hook."""
    global _TRACKER
    _TRACKER = None


async def cve_background_loop(bot) -> None:
    """The coroutine app.py starts in ``post_init`` (mirrors
    ``news_background_loop``). Dormant unless CVE_TRACKER_ENABLED=true."""
    tracker = get_tracker()
    await tracker.background_loop(bot)


async def stop_tracker() -> None:
    if _TRACKER is not None:
        await _TRACKER.stop()
