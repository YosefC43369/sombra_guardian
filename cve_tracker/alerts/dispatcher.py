"""
cve_tracker.alerts.dispatcher — turn records into delivered Telegram alerts.

The dispatcher ties routing → AI summary → formatting → throttled send together:

    order by priority → summarise once per record (cached) → format once →
    route to chats → record idempotent notifications → throttled fan-out send

It owns the :class:`AlertThrottler`, so a burst is paced and flood control is
honoured. Telegram objects are imported at call time only, so the module (and
its unit tests) import cleanly with no telegram installed. Every send updates
its notification row (sent/failed/retry) for audit and idempotency (rules §22,
§23, §46).
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from ..enums import NotificationState, EventType
from ..models import CVERecord, ChangeSet, Notification
from ..intelligence.prioritization import order_for_dispatch
from .formatter import format_new_cve, format_updated_cve
from .routing import route
from .throttler import AlertThrottler

logger = logging.getLogger("modbot.cve.dispatcher")


class AlertDispatcher:
    def __init__(self, bot, repo, config, summarizer, *, event_emit=None):
        self.bot = bot
        self.repo = repo
        self.config = config
        self.summarizer = summarizer
        self.emit = event_emit
        self.throttler = AlertThrottler(
            send_rate_per_sec=config.alerts.send_rate_per_sec,
            max_attempts=config.alerts.max_send_retries,
        )
        self._stats = {"sent": 0, "failed": 0, "suppressed": 0}

    # ---------------- public ----------------

    async def dispatch_new(self, records: List[CVERecord]) -> dict:
        """Queue + send 'new CVE' alerts for a batch."""
        if not self.config.alerts.enabled:
            return {"enqueued": 0, "reason": "alerts-disabled"}
        subs = self.repo.list_subscriptions(enabled_only=True)
        enqueued = 0
        for rec in order_for_dispatch(records):
            targets = self._route(rec, subs, is_update=False)
            fresh = self._persist_targets(targets)
            if not fresh:
                continue
            ai = await self._summarize_if_wanted(rec, fresh)
            chunks = format_new_cve(rec, ai)
            for n in fresh:
                await self.throttler.enqueue(
                    (n, chunks, rec.cve_id), priority=rec.priority_score)
                enqueued += 1
        result = await self._drain()
        result["enqueued"] = enqueued
        return result

    async def dispatch_updates(self, pairs: List[Tuple[CVERecord, ChangeSet]]) -> dict:
        """Queue + send 'CVE updated' alerts. ``pairs`` is (record, change_set)."""
        if not self.config.alerts.enabled:
            return {"enqueued": 0, "reason": "alerts-disabled"}
        subs = self.repo.list_subscriptions(enabled_only=True)
        enqueued = 0
        for rec, change_set in pairs:
            targets = self._route(rec, subs, is_update=True)
            fresh = self._persist_targets(targets)
            if not fresh:
                continue
            ai = await self._summarize_if_wanted(rec, fresh)
            chunks = format_updated_cve(rec, change_set, ai)
            for n in fresh:
                await self.throttler.enqueue(
                    (n, chunks, rec.cve_id), priority=rec.priority_score + 5)
                enqueued += 1
        result = await self._drain()
        result["enqueued"] = enqueued
        return result

    # ---------------- internals ----------------

    def _route(self, rec: CVERecord, subs, *, is_update: bool) -> List[Notification]:
        return route(
            rec, subs,
            global_min_cvss=self.config.alerts.min_cvss,
            global_min_severity=self.config.alerts.min_severity,
            admin_chat_id=self.config.alerts.admin_chat_id,
            admin_topic_id=self.config.alerts.admin_topic_id,
            is_update=is_update,
        )

    def _persist_targets(self, targets: List[Notification]) -> List[Notification]:
        """Record each notification idempotently; keep only the newly-created
        ones (a duplicate dedupe_key means already handled)."""
        fresh: List[Notification] = []
        for n in targets:
            if self.repo.notification_exists(n.dedupe_key):
                self._stats["suppressed"] += 1
                continue
            row_id = self.repo.record_notification(n)
            if row_id is not None:
                fresh.append(n)
            else:
                self._stats["suppressed"] += 1
        return fresh

    async def _summarize_if_wanted(self, rec: CVERecord, notifs: List[Notification]):
        """Summarise once per record if any target chat wants an AI summary.
        The summarizer's own cache makes repeats free."""
        try:
            summary = await self.summarizer.summarize(rec)
            if self.emit and summary and summary.validated:
                self._safe_emit(EventType.CVE_AI_SUMMARIZED.value, {"cve_id": rec.cve_id})
            return summary
        except Exception:
            logger.exception("CVE dispatch: summarize failed for %s", rec.cve_id)
            return None

    async def redrive_pending(self, *, limit: int = 100) -> dict:
        """Re-attempt notifications the DB still shows as pending/retry (rule
        §22 retry queue that survives across rounds and restarts). Rebuilds each
        message from its stored record + summary and re-sends under the
        throttler. Idempotency is preserved — a SENT row is never retried."""
        if not self.config.alerts.enabled:
            return {"redriven": 0, "reason": "alerts-disabled"}
        pending = self.repo.pending_notifications(limit=limit)
        if not pending:
            return {"redriven": 0}
        # group by (cve_id, is_update) so each record is summarised once
        by_cve: dict = {}
        for n in pending:
            by_cve.setdefault((n.cve_id, n.is_update), []).append(n)
        redriven = 0
        for (cve_id, is_update), notifs in by_cve.items():
            rec = self.repo.get_record(cve_id)
            if rec is None:
                # record gone — mark the orphan notifications suppressed
                for n in notifs:
                    self.repo.mark_notification(
                        n.dedupe_key, NotificationState.SUPPRESSED.value,
                        error="record-missing")
                continue
            ai = await self._summarize_if_wanted(rec, notifs)
            chunks = format_new_cve(rec, ai)
            for n in notifs:
                await self.throttler.enqueue((n, chunks, cve_id),
                                             priority=rec.priority_score)
                redriven += 1
        result = await self._drain()
        result["redriven"] = redriven
        return result

    async def _drain(self) -> dict:
        return await self.throttler.drain(
            self._send_one, max_items=self.config.alerts.max_per_cycle)

    async def _send_one(self, payload):
        """Send one notification's chunks to its chat. Returns True / ('retry',
        secs) / False per the throttler contract."""
        notification, chunks, cve_id = payload
        try:
            from telegram.error import RetryAfter, TelegramError
        except Exception:
            RetryAfter = TelegramError = Exception  # type: ignore

        topic = notification.topic_id or None
        try:
            for chunk in chunks:
                await self.bot.send_message(
                    chat_id=notification.chat_id,
                    text=chunk,
                    parse_mode="HTML",
                    message_thread_id=topic,
                    disable_web_page_preview=True,
                )
            self.repo.mark_notification(notification.dedupe_key, NotificationState.SENT.value)
            self._stats["sent"] += 1
            self._safe_emit(EventType.CVE_ALERT_SENT.value,
                            {"cve_id": cve_id, "chat_id": notification.chat_id})
            return True
        except RetryAfter as exc:  # type: ignore[misc]
            secs = float(getattr(exc, "retry_after", 5) or 5)
            logger.info("CVE ALERT flood control %ss | chat=%s", secs, notification.chat_id)
            self.repo.mark_notification(notification.dedupe_key, NotificationState.RETRY.value,
                                        error=f"flood:{secs}s")
            return ("retry", secs)
        except TelegramError as exc:  # type: ignore[misc]
            logger.warning("CVE ALERT telegram error | chat=%s | %s",
                           notification.chat_id, exc)
            self.repo.mark_notification(notification.dedupe_key, NotificationState.FAILED.value,
                                        error=str(exc)[:200])
            self._stats["failed"] += 1
            self._safe_emit(EventType.CVE_ALERT_FAILED.value,
                            {"cve_id": cve_id, "chat_id": notification.chat_id})
            return False
        except Exception as exc:
            logger.exception("CVE ALERT send crashed | chat=%s", notification.chat_id)
            self.repo.mark_notification(notification.dedupe_key, NotificationState.FAILED.value,
                                        error=str(exc)[:200])
            self._stats["failed"] += 1
            return False

    def _safe_emit(self, event_type: str, payload: dict) -> None:
        if not self.emit:
            return
        try:
            self.emit(event_type, payload)
        except Exception:
            pass

    @property
    def stats(self) -> dict:
        return dict(self._stats, queue_depth=self.throttler.depth)
