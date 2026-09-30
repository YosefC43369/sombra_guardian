"""
cve_tracker.monitoring.diagnostics — assemble a full self-diagnostic snapshot.

Gathers config flags, source health, metrics, record counts and recent events
into one dict for a deep ``/cve_status`` view and for a startup self-test that
confirms the schema is present and the AI backend is reachable (rule §50). Reads
only; never mutates state.
"""

from __future__ import annotations

from typing import Dict

from ..utils import now_epoch
from .health import HealthTracker
from .metrics import MetricsRegistry


class DiagnosticsService:
    def __init__(self, repo, config, *, metrics: MetricsRegistry = None,
                 ai_adapter=None):
        self.repo = repo
        self.config = config
        self.metrics = metrics or MetricsRegistry()
        self.health = HealthTracker(repo, config)
        self.ai_adapter = ai_adapter

    def snapshot(self) -> Dict:
        health = self.health.report()
        return {
            "enabled": self.config.enabled,
            "poll_interval": self.config.poll_interval,
            "ai_enabled": self.config.ai.enabled,
            "ai_available": self.ai_adapter.available() if self.ai_adapter else None,
            "alerts_enabled": self.config.alerts.enabled,
            "record_count": self.repo.count(),
            "subscription_count": len(self.repo.list_subscriptions(enabled_only=False)),
            "health": {
                "overall": health.overall,
                "healthy_sources": health.healthy_count,
                "total_sources": health.total_count,
                "sources": health.sources,
            },
            "metrics": self.metrics.snapshot(),
            "recent_events": self.repo.recent_events(limit=10),
            "stats": self.repo.stats(since_epoch=now_epoch() - 7 * 86400),
        }

    def selftest(self) -> Dict[str, bool]:
        """Confirm the pieces are wired: schema present, repo readable, AI
        reachable. Used at startup and by /cve_test diagnostics."""
        results: Dict[str, bool] = {}
        try:
            self.repo.count()
            results["storage"] = True
        except Exception:
            results["storage"] = False
        try:
            from ..storage.migrations import verify
            results["schema"] = verify(self.repo.db_path)
        except Exception:
            results["schema"] = False
        results["ai"] = bool(self.ai_adapter.available()) if self.ai_adapter else False
        results["sources_enabled"] = len(self.config.enabled_sources()) > 0
        return results
