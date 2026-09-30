"""
group_soc/detection/rule_engine.py — declarative single-event rules.

The rule engine "promotes" high-value single events — especially upstream security
events already normalized into SOC events (IOC match, rule match, high-severity
detection) — into first-class SOC signals so they enter triage/alerting. It does NOT
re-detect anything; it recognises an already-detected condition and lifts it into the
SOC's own object model.

Rules are declarative (a predicate + a signal template), so new promotions are added
as data, not code branches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.entity import EntityRef
from ..models.severity import RiskDimensions, severity_to_float
from ..constants import EventType, DetectorKind, AnalyticState, Severity, SEVERITY_RANK


@dataclass
class Rule:
    rule_id: str
    title: str
    predicate: Callable[[SecurityEvent], bool]
    base_severity: float = 0.5
    base_confidence: float = 0.6
    urgency: float = 0.6
    impact: float = 0.5
    analytic_state: str = AnalyticState.SUSPICIOUS.value
    summary: str = ""

    def build_signal(self, event: SecurityEvent) -> SecuritySignal:
        # severity tracks the event's own severity where present
        sev = max(self.base_severity, severity_to_float(event.severity))
        conf = max(self.base_confidence, event.confidence or 0.0)
        dims = RiskDimensions(severity=sev, confidence=conf, impact=self.impact,
                              urgency=self.urgency, exposure=0.5, persistence=0.4)
        entities = [EntityRef.user(event.actor_hash)] if event.actor_hash else []
        entities += [e for e in event.entities if e.kind != "user"][:5]
        return SecuritySignal(
            signal_type=DetectorKind.RULE.value,
            producer=f"detection:rule:{self.rule_id}",
            chat_id=event.chat_id,
            title=self.title,
            summary=self.summary or self.title,
            dimensions=dims,
            analytic_state=self.analytic_state,
            event_ids=[event.event_id],
            entities=entities,
            dedup_key=f"{event.chat_id}:rule:{self.rule_id}:{event.actor_hash or event.event_id}",
            metadata={"rule_id": self.rule_id, "source_event": event.event_type},
        )


def _high(event: SecurityEvent) -> bool:
    return SEVERITY_RANK.get(event.severity, 0) >= SEVERITY_RANK[Severity.HIGH.value]


def default_rules() -> List[Rule]:
    return [
        Rule("ioc_match", "Matched threat indicator (IOC)",
             lambda e: e.event_type == EventType.IOC_MATCHED.value,
             base_severity=0.7, base_confidence=0.7, urgency=0.7, impact=0.6,
             summary="An indicator matched a threat-intel feed (defanged)."),
        Rule("rule_match_enabled", "Blue Team rule matched (enforcing)",
             lambda e: (e.event_type == EventType.SECURITY_RULE_TRIGGERED.value
                        and e.context.get("mode") == "enabled"),
             base_severity=0.6, base_confidence=0.65, urgency=0.6, impact=0.5,
             summary="An enforcing detection rule matched."),
        Rule("high_detection", "High-severity detection",
             lambda e: e.event_type == EventType.DETECTION_TRIGGERED.value and _high(e),
             base_severity=0.65, base_confidence=0.6, urgency=0.65, impact=0.5,
             summary="A high-severity primary detection fired."),
    ]


class RuleEngine:
    name = "rule_engine"

    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules: List[Rule] = list(rules) if rules is not None else default_rules()

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def detect(self, event: SecurityEvent, storage, config) -> List[SecuritySignal]:
        out: List[SecuritySignal] = []
        for rule in self.rules:
            try:
                if rule.predicate(event):
                    out.append(rule.build_signal(event))
            except Exception:
                continue
        return out
