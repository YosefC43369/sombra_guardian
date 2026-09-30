"""Timeline reconstruction + rendering."""

from __future__ import annotations

from group_soc.models import SecurityEvent, SecuritySignal, Incident, RiskDimensions
from group_soc.timeline import TimelineBuilder, render_timeline
from group_soc.util import now

from .conftest import CHAT


def test_build_for_correlation_ordered(storage, config):
    corr = "corr-1"
    storage.events.add(SecurityEvent(event_type="member_joined", chat_id=CHAT,
                                     correlation_id=corr, ts=now() - 10))
    storage.events.add(SecurityEvent(event_type="message_created", chat_id=CHAT,
                                     correlation_id=corr, ts=now() - 5))
    storage.signals.add(SecuritySignal(chat_id=CHAT, correlation_id=corr,
                                       title="Campaign", ts=now()))
    entries = TimelineBuilder(storage).build_for_correlation(corr)
    assert len(entries) == 3
    assert [e.ts for e in entries] == sorted(e.ts for e in entries)   # ordered


def test_build_for_incident_includes_incident_marker(storage, config):
    corr = "corr-2"
    storage.events.add(SecurityEvent(event_type="member_joined", chat_id=CHAT,
                                     correlation_id=corr))
    inc = Incident(chat_id=CHAT, classification="raid", correlation_ids=[corr],
                   dimensions=RiskDimensions(confidence=0.6))
    storage.incidents.add(inc)
    entries = TimelineBuilder(storage).build_for_incident(inc)
    kinds = {e.kind for e in entries}
    assert "incident" in kinds and "event" in kinds


def test_render_plaintext():
    from group_soc.models import TimelineEntry
    entries = [TimelineEntry(chat_id=CHAT, ts=now(), kind="alert", summary="Join burst",
                             metadata={"priority": "P2"})]
    text = render_timeline(entries)
    assert "SECURITY TIMELINE" in text and "Join burst" in text and "[P2]" in text
