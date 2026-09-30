"""
group_soc/alerts/manager.py — the AlertManager.

Turns a SecuritySignal into an alert decision (create / fold / suppress / escalate)
and owns the analyst lifecycle operations (ack, assign, suppress, escalate, resolve,
close). Every state change is audited. The manager is storage-focused and bus-free:
it returns an outcome and lets the caller emit soc.* events, so it is fully testable
offline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ..models.alert import Alert
from ..constants import AlertStatus
from ..exceptions import SocNotFoundError
from ..util import now
from ..prioritization.priority_engine import PriorityEngine
from .deduplication import fold_changes
from .suppression import recently_resolved_within
from .grouping import choose_group_id
from .escalation import should_escalate
from .lifecycle import transition

logger = logging.getLogger("modbot.group_soc.alerts")


@dataclass
class AlertOutcome:
    alert: Optional[Alert]
    action: str            # created | folded | escalated | suppressed
    escalated: bool = False


class AlertManager:
    def __init__(self, storage, config, priority_engine: Optional[PriorityEngine] = None):
        self.storage = storage
        self.config = config
        self.priority = priority_engine or PriorityEngine()

    # ---- ingest a signal ----
    def process_signal(self, signal) -> AlertOutcome:
        chat = signal.chat_id
        ps = self.priority.score(signal, hit_count=1)
        active = self.storage.alerts.find_active_by_dedup(chat, signal.dedup_key)

        if active is not None:
            changes = fold_changes(active, signal.signal_id, ps.score, ps.band)
            escalated = should_escalate(
                changes["hit_count"], self.config.escalation_repeat_threshold, active.status)
            if escalated:
                changes["status"] = AlertStatus.ESCALATED.value
            self.storage.alerts.update(active.alert_id, changes)
            updated = self.storage.alerts.get(active.alert_id)
            self.storage.audit(chat, "alert.folded", target_kind="alert",
                               target_id=active.alert_id,
                               detail={"hit_count": changes["hit_count"]})
            if escalated:
                self.storage.audit(chat, "alert.escalated", target_kind="alert",
                                   target_id=active.alert_id,
                                   detail={"hit_count": changes["hit_count"]})
                return AlertOutcome(updated, "escalated", True)
            return AlertOutcome(updated, "folded", False)

        # no active alert — check cooldown suppression
        if recently_resolved_within(self.storage.alerts, chat, signal.dedup_key,
                                    self.config.alert_cooldown_s):
            self.storage.audit(chat, "alert.suppressed", target_kind="signal",
                               target_id=signal.signal_id,
                               detail={"dedup_key": signal.dedup_key})
            return AlertOutcome(None, "suppressed", False)

        group_id = choose_group_id(self.storage.alerts, chat, signal.correlation_id,
                                   self.config.alert_group_window_s)
        alert = Alert(
            chat_id=chat, correlation_id=signal.correlation_id, signal_id=signal.signal_id,
            dedup_key=signal.dedup_key, title=signal.title, summary=signal.summary,
            severity=ps.severity_label, priority_band=ps.band, priority_score=ps.score,
            group_id=group_id, signal_ids=[signal.signal_id],
            metadata={"producer": signal.producer, "signal_type": signal.signal_type},
        )
        self.storage.alerts.add(alert)
        self.storage.audit(chat, "alert.created", target_kind="alert",
                           target_id=alert.alert_id,
                           detail={"priority": ps.band, "score": ps.score})
        return AlertOutcome(alert, "created", False)

    # ---- lifecycle operations ----
    def _load(self, alert_id: str) -> Alert:
        alert = self.storage.alerts.get(alert_id)
        if alert is None:
            raise SocNotFoundError("alert not found", code="SOC_NOT_FOUND", alert_id=alert_id)
        return alert

    def set_status(self, alert_id: str, new_status: str,
                   actor_hash: Optional[str] = None) -> Alert:
        alert = self._load(alert_id)
        updated, changes = transition(alert, new_status)
        if changes:
            self.storage.alerts.update(alert_id, changes)
            self.storage.audit(alert.chat_id, f"alert.{new_status}", actor_hash=actor_hash,
                               target_kind="alert", target_id=alert_id)
        return updated

    def acknowledge(self, alert_id: str, actor_hash: Optional[str] = None) -> Alert:
        return self.set_status(alert_id, AlertStatus.ACKNOWLEDGED.value, actor_hash)

    def escalate(self, alert_id: str, actor_hash: Optional[str] = None) -> Alert:
        return self.set_status(alert_id, AlertStatus.ESCALATED.value, actor_hash)

    def suppress(self, alert_id: str, actor_hash: Optional[str] = None) -> Alert:
        return self.set_status(alert_id, AlertStatus.SUPPRESSED.value, actor_hash)

    def resolve(self, alert_id: str, actor_hash: Optional[str] = None) -> Alert:
        return self.set_status(alert_id, AlertStatus.RESOLVED.value, actor_hash)

    def close(self, alert_id: str, actor_hash: Optional[str] = None) -> Alert:
        return self.set_status(alert_id, AlertStatus.CLOSED.value, actor_hash)

    def assign(self, alert_id: str, assignee_hash: str,
               actor_hash: Optional[str] = None) -> Alert:
        alert = self._load(alert_id)
        self.storage.alerts.update(alert_id, {"assignee_hash": assignee_hash})
        # moving an assignment on a NEW alert also triages it
        if alert.status == AlertStatus.NEW.value:
            self.storage.alerts.update(alert_id, {"status": AlertStatus.TRIAGED.value})
        self.storage.audit(alert.chat_id, "alert.assigned", actor_hash=actor_hash,
                           target_kind="alert", target_id=alert_id)
        return self._load(alert_id)
