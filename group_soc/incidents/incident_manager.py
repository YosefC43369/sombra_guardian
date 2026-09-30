"""
group_soc/incidents/incident_manager.py — the SOC IncidentManager.

A SOC incident aggregates alerts/cases/correlations into one situation. It can be
opened automatically (from a set of signals — classified + risk-aggregated) or
manually by an analyst. When it concerns a specific member it can bridge to the
existing member_incident system through an injected adapter (single source of truth
for member custody) rather than duplicating it.

Containment side-effects (restrict/ban) are NOT performed here; the manager records a
containment intent and delegates any Telegram action to the injected adapter, which
degrades to a no-op when unavailable.
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional

from ..models.incident import Incident
from ..models.signal import SecuritySignal
from ..constants import IncidentStatus, IncidentClass, Severity, MAX_LABEL_LEN
from ..exceptions import SocNotFoundError, SocValidationError
from ..util import clean_str
from ..models.severity import float_to_severity as _f2s
from .classification import classify, aggregate_dimensions
from .lifecycle import transition

logger = logging.getLogger("modbot.group_soc.incidents")


class IncidentManager:
    def __init__(self, storage, *, member_bridge: Optional[Callable] = None,
                 containment: Optional[Callable] = None):
        self.storage = storage
        # member_bridge(chat_id, actor_hash, classification, severity, reason) -> Optional[int]
        self.member_bridge = member_bridge
        # containment(incident) -> Optional[str]  (records/attempts containment)
        self.containment = containment

    def _load(self, incident_id: str) -> Incident:
        inc = self.storage.incidents.get(incident_id)
        if inc is None:
            raise SocNotFoundError("incident not found", code="SOC_NOT_FOUND",
                                   incident_id=incident_id)
        return inc

    def create_from_signals(self, chat_id: int, signals: List[SecuritySignal], *,
                            opened_by_hash: Optional[str] = None,
                            title: Optional[str] = None) -> Incident:
        if not signals:
            raise SocValidationError("no signals for incident", code="SOC_VALIDATION_ERROR")
        klass = classify(signals)
        dims = aggregate_dimensions(signals)
        sev = _f2s(dims.severity)
        corr_ids = sorted({s.correlation_id for s in signals if s.correlation_id})
        inc = Incident(
            chat_id=int(chat_id),
            title=clean_str(title, MAX_LABEL_LEN) or f"{klass.replace('_',' ').title()}",
            summary=signals[0].summary,
            classification=klass, severity=sev, dimensions=dims,
            correlation_ids=corr_ids, opened_by_hash=opened_by_hash,
        )
        self.storage.incidents.add(inc)
        self.storage.audit(chat_id, "incident.created", actor_hash=opened_by_hash,
                           target_kind="incident", target_id=inc.incident_id,
                           detail={"classification": klass, "severity": sev})
        return inc

    def create_manual(self, chat_id: int, title: str, classification: str, *,
                      severity: str = Severity.HIGH.value, summary: str = "",
                      opened_by_hash: Optional[str] = None) -> Incident:
        title = clean_str(title, MAX_LABEL_LEN)
        if not title:
            raise SocValidationError("incident title required", code="SOC_VALIDATION_ERROR")
        if classification not in {c.value for c in IncidentClass}:
            classification = IncidentClass.OTHER.value
        inc = Incident(chat_id=int(chat_id), title=title, classification=classification,
                       severity=severity, summary=summary, opened_by_hash=opened_by_hash)
        self.storage.incidents.add(inc)
        self.storage.audit(chat_id, "incident.created", actor_hash=opened_by_hash,
                           target_kind="incident", target_id=inc.incident_id,
                           detail={"manual": True, "classification": classification})
        return inc

    def get(self, incident_id: str) -> Optional[Incident]:
        return self.storage.incidents.get(incident_id)

    def list_open(self, chat_id: int, limit: int = 20) -> List[Incident]:
        return self.storage.incidents.list_open(chat_id, limit)

    def link_alert(self, incident_id: str, alert_id: str,
                   actor_hash: Optional[str] = None) -> Incident:
        inc = self._load(incident_id)
        if alert_id not in inc.alert_ids:
            self.storage.incidents.update(incident_id, {"alert_ids": inc.alert_ids + [alert_id]})
            self.storage.investigations.add_evidence_link(
                inc.chat_id, "incident", incident_id, "alert", alert_id, added_by_hash=actor_hash)
            self.storage.audit(inc.chat_id, "incident.alert_linked", actor_hash=actor_hash,
                               target_kind="incident", target_id=incident_id,
                               detail={"alert_id": alert_id})
        return self._load(incident_id)

    def link_case(self, incident_id: str, case_id: str,
                  actor_hash: Optional[str] = None) -> Incident:
        inc = self._load(incident_id)
        if case_id not in inc.case_ids:
            self.storage.incidents.update(incident_id, {"case_ids": inc.case_ids + [case_id]})
            self.storage.cases.update(case_id, {"incident_id": incident_id})
            self.storage.audit(inc.chat_id, "incident.case_linked", actor_hash=actor_hash,
                               target_kind="incident", target_id=incident_id,
                               detail={"case_id": case_id})
        return self._load(incident_id)

    def bridge_member(self, incident_id: str, actor_hash: str, reason: str = "",
                      actor_id_for_bridge: Optional[int] = None) -> Incident:
        """Link this incident to a member_incident via the injected adapter (if any)."""
        inc = self._load(incident_id)
        if self.member_bridge is None:
            return inc
        try:
            mid = self.member_bridge(inc.chat_id, actor_id_for_bridge, inc.classification,
                                     inc.severity, reason)
        except Exception:
            logger.exception("member incident bridge failed")
            mid = None
        if mid is not None:
            self.storage.incidents.update(incident_id, {"member_incident_id": int(mid)})
            self.storage.audit(inc.chat_id, "incident.member_bridged",
                               target_kind="incident", target_id=incident_id,
                               detail={"member_incident_id": int(mid)})
        return self._load(incident_id)

    def contain(self, incident_id: str, actor_hash: Optional[str] = None) -> Incident:
        inc = self._load(incident_id)
        detail = None
        if self.containment is not None:
            try:
                detail = self.containment(inc)
            except Exception:
                logger.exception("containment hook failed")
        updated = self.set_status(incident_id, IncidentStatus.CONTAINED.value, actor_hash)
        self.storage.audit(inc.chat_id, "incident.contained", actor_hash=actor_hash,
                           target_kind="incident", target_id=incident_id,
                           detail={"action": detail})
        return updated

    def set_status(self, incident_id: str, new_status: str,
                   actor_hash: Optional[str] = None) -> Incident:
        inc = self._load(incident_id)
        updated, changes = transition(inc, new_status)
        if changes:
            self.storage.incidents.update(incident_id, changes)
            self.storage.audit(inc.chat_id, f"incident.{new_status}", actor_hash=actor_hash,
                               target_kind="incident", target_id=incident_id)
        return updated

    def resolve(self, incident_id: str, resolution: str = "",
                actor_hash: Optional[str] = None) -> Incident:
        inc = self._load(incident_id)
        updated, changes = transition(inc, IncidentStatus.RESOLVED.value)
        changes["resolution"] = clean_str(resolution, 2000) or ""
        self.storage.incidents.update(incident_id, changes)
        self.storage.audit(inc.chat_id, "incident.resolved", actor_hash=actor_hash,
                           target_kind="incident", target_id=incident_id)
        return self._load(incident_id)
