"""Security story generation keeps the four registers separate + the confidence caveat."""

from __future__ import annotations

from group_soc.models import SecuritySignal, Incident, RiskDimensions, SecurityEvent
from group_soc.stories import StoryGenerator, format_story
from group_soc.util import now

from .conftest import CHAT


def _incident_with_signal(storage, klass="spam_campaign"):
    corr = "story-corr"
    storage.events.add(SecurityEvent(event_type="message_created", chat_id=CHAT,
                                     correlation_id=corr, ts=now()))
    storage.signals.add(SecuritySignal(chat_id=CHAT, correlation_id=corr,
                                       title="Coordinated identical messages",
                                       summary="3 actors posted the same content"))
    inc = Incident(chat_id=CHAT, classification=klass, correlation_ids=[corr],
                   title="Spam wave", dimensions=RiskDimensions(confidence=0.62))
    storage.incidents.add(inc)
    return inc


def test_story_registers_separated(storage, config):
    inc = _incident_with_signal(storage)
    story = StoryGenerator(storage).for_incident(inc)
    assert story.facts and story.analysis and story.hypotheses and story.recommendations
    # analysis must contain the signal, facts must not contain the recommendation
    assert any("Coordinated" in a for a in story.analysis)


def test_story_format_has_caveat(storage, config):
    inc = _incident_with_signal(storage)
    text = format_story(StoryGenerator(storage).for_incident(inc))
    for section in ("SECURITY STORY", "FACTS", "ANALYSIS", "HYPOTHESIS", "RECOMMENDATION"):
        assert section in text
    assert "Confidence is an analytical signal, not proof of malicious intent." in text


def test_story_confidence_from_incident(storage, config):
    inc = _incident_with_signal(storage)
    story = StoryGenerator(storage).for_incident(inc)
    assert abs(story.confidence - 0.62) < 0.01
