"""
cve_tracker.storage.retention — configurable pruning of history tables.

CVE *core records are never auto-deleted* (rule §25) — a ten-year-old CVE is
still a fact worth keeping. Retention only trims the append-only history tables
(events, failures, audit, notification history, ingestion runs) and the AI
summary cache, each on its own configurable horizon. All deletes are bounded and
logged; a horizon of 0 means 'keep forever'.
"""

from __future__ import annotations

import logging
from typing import Dict

from ..config import RetentionConfig
from ..utils import now_epoch
from .repository import CVERepository

logger = logging.getLogger("modbot.cve.retention")


class RetentionManager:
    def __init__(self, repo: CVERepository, config: RetentionConfig):
        self.repo = repo
        self.config = config

    def run(self) -> Dict[str, int]:
        """Apply every retention horizon once. Returns {table: rows_deleted}."""
        now = now_epoch()
        deleted: Dict[str, int] = {}
        plan = [
            ("cve_events", self.config.event_days),
            ("cve_failures", self.config.audit_days),
            ("cve_audit_log", self.config.audit_days),
            ("cve_ingestion_runs", self.config.event_days),
            ("cve_ai_summaries", self.config.ai_summary_days),
            ("cve_notifications", self.config.notification_days),
        ]
        for table, days in plan:
            if not days or days <= 0:
                continue
            cutoff = now - days * 86400
            deleted[table] = self._prune(table, cutoff)
        # Raw per-source payloads: trim only the raw blob text, keep the row.
        if self.config.raw_days and self.config.raw_days > 0:
            deleted["cve_source_records(raw)"] = self._trim_raw(
                now - self.config.raw_days * 86400)
        total = sum(deleted.values())
        if total:
            logger.info("CVE RETENTION | pruned %d rows across %d tables",
                        total, len([v for v in deleted.values() if v]))
        return deleted

    def _prune(self, table: str, cutoff: int) -> int:
        column = "at" if table == "cve_audit_log" else (
            "started_at" if table == "cve_ingestion_runs" else "created_at")

        def _txn(conn):
            cur = conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
            return cur.rowcount or 0
        try:
            return self.repo._execute_write(_txn)
        except Exception:
            logger.exception("CVE RETENTION | failed pruning %s", table)
            return 0

    def _trim_raw(self, cutoff: int) -> int:
        """Null out large raw payloads older than the horizon while keeping the
        provenance row (source/url/fetched_at). Saves space without losing the
        fact that a source contributed."""
        def _txn(conn):
            cur = conn.execute(
                "UPDATE cve_source_records SET raw='{}' WHERE fetched_at < ? AND raw != '{}'",
                (cutoff,))
            return cur.rowcount or 0
        try:
            return self.repo._execute_write(_txn)
        except Exception:
            logger.exception("CVE RETENTION | failed trimming raw payloads")
            return 0
