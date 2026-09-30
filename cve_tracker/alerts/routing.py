"""
cve_tracker.alerts.routing — decide which chats receive a record.

Given a record and the set of subscriptions, routing produces one
:class:`Notification` per matching chat, each stamped with the reason it
matched and an idempotency ``dedupe_key`` (rule §22). The platform floor is
applied first; then each subscription's own filters. An optional admin/security
chat (from config) is treated as a broad subscription so the SOC channel gets
everything above the floor.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import CVERecord, Notification, Subscription
from ..enums import NotificationState
from . import filters


def route(
    record: CVERecord,
    subscriptions: List[Subscription],
    *,
    global_min_cvss: float = 0.0,
    global_min_severity: str = "MEDIUM",
    admin_chat_id: int = 0,
    admin_topic_id: Optional[int] = None,
    is_update: bool = False,
) -> List[Notification]:
    """Return the notifications to create for ``record``."""
    notifs: List[Notification] = []
    seen_targets = set()

    # platform floor
    if not filters.passes_global_floor(
            record, min_cvss=global_min_cvss, min_severity=global_min_severity):
        # KEV records bypass the floor inside passes_global_floor already.
        # Below-floor records still go to explicit narrow subscriptions that
        # asked for a specific vendor/product/cwe/keyword — check those only.
        subscriptions = [s for s in subscriptions
                         if (s.vendors or s.products or s.cwes or s.keywords)]
        if not subscriptions:
            return []

    for sub in subscriptions:
        if not sub.enabled:
            continue
        if is_update and not sub.include_updates:
            continue
        matched, reason = filters.matches(sub, record)
        if not matched:
            continue
        target = (sub.chat_id, sub.topic_id or 0)
        if target in seen_targets:
            continue
        seen_targets.add(target)
        notifs.append(Notification(
            cve_id=record.cve_id, chat_id=sub.chat_id, topic_id=sub.topic_id,
            reason=reason, state=NotificationState.PENDING.value,
            priority=record.priority, is_update=is_update,
        ))

    # admin/security channel — broad, above floor
    if admin_chat_id:
        target = (admin_chat_id, admin_topic_id or 0)
        if target not in seen_targets:
            if filters.passes_global_floor(
                    record, min_cvss=global_min_cvss, min_severity=global_min_severity):
                notifs.append(Notification(
                    cve_id=record.cve_id, chat_id=admin_chat_id, topic_id=admin_topic_id,
                    reason="admin-channel", state=NotificationState.PENDING.value,
                    priority=record.priority, is_update=is_update,
                ))

    return notifs
