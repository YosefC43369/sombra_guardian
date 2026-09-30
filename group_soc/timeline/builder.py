"""
group_soc/timeline/builder.py — reconstruct an ordered timeline from scattered records.

Pulls the events, signals and alerts tied to one or more correlation ids (or a chat
time window) and merges them into a single time-ordered list of TimelineEntry objects.
This is the raw material for the security story and for durable incident records.
All reads are bounded.
"""

from __future__ import annotations

from typing import List, Optional

from ..models.timeline import TimelineEntry
from ..models.event import SecurityEvent
from ..models.signal import SecuritySignal
from ..models.alert import Alert
from ..util import gen_id


def _from_event(ev: SecurityEvent) -> TimelineEntry:
    label = ev.event_type.replace("_", " ")
    return TimelineEntry(chat_id=ev.chat_id, ts=ev.ts, kind="event", ref_id=ev.event_id,
                         correlation_id=ev.correlation_id, actor_hash=ev.actor_hash,
                         summary=label, metadata={"severity": ev.severity,
                                                  "source": ev.source})


def _from_signal(sig: SecuritySignal) -> TimelineEntry:
    return TimelineEntry(chat_id=sig.chat_id, ts=sig.ts, kind="signal", ref_id=sig.signal_id,
                         correlation_id=sig.correlation_id,
                         summary=sig.title or sig.producer,
                         metadata={"producer": sig.producer,
                                   "state": sig.analytic_state})


def _from_alert(alert: Alert) -> TimelineEntry:
    return TimelineEntry(chat_id=alert.chat_id, ts=alert.created_at, kind="alert",
                         ref_id=alert.alert_id, correlation_id=alert.correlation_id,
                         summary=alert.title,
                         metadata={"priority": alert.priority_band, "status": alert.status})


class TimelineBuilder:
    def __init__(self, storage):
        self.storage = storage

    def build_for_correlation(self, correlation_id: str) -> List[TimelineEntry]:
        entries: List[TimelineEntry] = []
        entries += [_from_event(e) for e in self.storage.events.by_correlation(correlation_id)]
        entries += [_from_signal(s) for s in self.storage.signals.by_correlation(correlation_id)]
        # alerts sharing this correlation id
        rows = self.storage.alerts._get_many(
            "SELECT * FROM soc_alerts WHERE correlation_id=? ORDER BY created_at ASC LIMIT 200",
            (correlation_id,))
        entries += [_from_alert(Alert.from_row(r)) for r in rows]
        return self._ordered(entries)

    def build_for_incident(self, incident) -> List[TimelineEntry]:
        entries: List[TimelineEntry] = []
        seen = set()
        for corr in incident.correlation_ids:
            for e in self.build_for_correlation(corr):
                if e.ref_id not in seen:
                    entries.append(e)
                    seen.add(e.ref_id)
        # include linked alerts directly
        for alert_id in incident.alert_ids:
            alert = self.storage.alerts.get(alert_id)
            if alert and alert.alert_id not in seen:
                entries.append(_from_alert(alert))
                seen.add(alert.alert_id)
        entries.append(TimelineEntry(
            chat_id=incident.chat_id, ts=incident.created_at, kind="incident",
            ref_id=incident.incident_id, summary=f"Incident opened: {incident.title}",
            metadata={"classification": incident.classification}))
        return self._ordered(entries)

    def build_window(self, chat_id: int, since_ts: int, until_ts: int) -> List[TimelineEntry]:
        events = self.storage.events.search(chat_id, since_ts=since_ts, until_ts=until_ts,
                                            limit=200)
        return self._ordered([_from_event(e) for e in events])

    def persist(self, entries: List[TimelineEntry]) -> int:
        return self.storage.timeline.add_many(entries)

    @staticmethod
    def _ordered(entries: List[TimelineEntry]) -> List[TimelineEntry]:
        return sorted(entries, key=lambda e: (e.ts, e.kind))
