"""
group_soc/collector/signal_events.py — collect UPSTREAM security signals.

These do not come from Telegram; they are emitted by other Sombra modules onto the
same bus and are the SOC's richest inputs:

  detection.triggered  {chat_id, user_id, detection_type, severity, reason}
  rule.matched         (blueteam.platform.events.RuleMatched.to_payload)
  intel.ioc_matched    (blueteam.platform.events.IocMatched.to_payload — value ALWAYS defanged)

All collectors are defensive: they read fields with .get() and tolerate a changed
payload shape rather than raising. The IOC value is already defanged upstream; we
keep it that way.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..constants import EventType, ObjectType, EntityKind, Severity, VALID_SEVERITIES
from ..normalization.schema import RawEvent


def _sev(value: Any, default: str = Severity.MEDIUM.value) -> str:
    v = str(value or "").lower()
    # upstream uses 'level'/'severity' with values like low/medium/high/critical
    return v if v in VALID_SEVERITIES else default


def collect_detection(payload: Dict[str, Any], *,
                      correlation_id: Optional[str] = None) -> Optional[RawEvent]:
    if not payload or payload.get("chat_id") is None:
        return None
    return RawEvent(
        event_type=EventType.DETECTION_TRIGGERED.value,
        chat_id=payload.get("chat_id"),
        source="detection",
        correlation_id=correlation_id,
        actor_id=payload.get("user_id"),
        severity=_sev(payload.get("severity")),
        confidence=0.6,
        context={
            "detection_type": str(payload.get("detection_type") or "unknown"),
            "reason": str(payload.get("reason") or "")[:500],
        },
        metadata={"upstream": "detection.triggered"},
    )


def collect_rule_matched(payload: Dict[str, Any], *,
                         correlation_id: Optional[str] = None) -> Optional[RawEvent]:
    if not payload or payload.get("chat_id") is None:
        return None
    return RawEvent(
        event_type=EventType.SECURITY_RULE_TRIGGERED.value,
        chat_id=payload.get("chat_id"),
        source="blueteam",
        correlation_id=correlation_id,
        actor_id=payload.get("user_id"),
        severity=_sev(payload.get("level")),
        confidence=0.65,
        context={
            "rule_id": str(payload.get("rule_id") or ""),
            "rule_title": str(payload.get("rule_title") or "")[:200],
            "attack": str(payload.get("attack") or ""),
            "mode": str(payload.get("mode") or "enabled"),
        },
        metadata={"upstream": "rule.matched"},
    )


def collect_ioc_matched(payload: Dict[str, Any], *,
                        correlation_id: Optional[str] = None) -> Optional[RawEvent]:
    if not payload or payload.get("chat_id") is None:
        return None
    ioc_type = str(payload.get("ioc_type") or "").lower()
    value_defanged = str(payload.get("value_defanged") or "")
    # map ioc type to an entity kind where we can
    kind = {"domain": EntityKind.DOMAIN.value, "url": EntityKind.URL.value,
            "ip": EntityKind.IP.value, "hash": EntityKind.HASH.value}.get(
                ioc_type, EntityKind.PATTERN.value)
    entities = [(kind, value_defanged)] if value_defanged else []
    conf = payload.get("confidence")
    try:
        conf = float(conf) / 100.0 if conf and float(conf) > 1 else float(conf or 0.7)
    except (TypeError, ValueError):
        conf = 0.7
    return RawEvent(
        event_type=EventType.IOC_MATCHED.value,
        chat_id=payload.get("chat_id"),
        source="intel",
        correlation_id=correlation_id,
        actor_id=payload.get("user_id"),
        object_type=ObjectType.URL.value if kind == EntityKind.URL.value else ObjectType.DOMAIN.value,
        severity=_sev(payload.get("severity")),
        confidence=conf,
        entities=entities,
        context={
            "ioc_type": ioc_type,
            "feeds": str(payload.get("feeds") or ""),
            "attack": str(payload.get("attack") or ""),
        },
        metadata={"upstream": "intel.ioc_matched"},
    )
