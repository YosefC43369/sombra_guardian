"""Detection: threshold, rule promotion, anomaly, sequence detectors."""

from __future__ import annotations

from group_soc.models import SecurityEvent
from group_soc.util import hash_id, content_hash, now
from group_soc.detection import (
    JoinBurstDetector, RepeatedContentDetector, RuleEngine,
    ActivitySpikeDetector, DetectorManager,
)
from group_soc.detection.sequence import default_sequence_detectors

from .conftest import CHAT


def _add(storage, **kw):
    kw.setdefault("chat_id", CHAT)
    kw.setdefault("ts", now())
    e = SecurityEvent(**kw)
    storage.events.add(e)
    return e


def test_join_burst_threshold(storage, config):
    last = None
    for uid in range(3):                 # threshold=3 in fixture
        last = _add(storage, event_type="member_joined", actor_hash=hash_id(uid))
    sigs = JoinBurstDetector().detect(last, storage, config)
    assert sigs and sigs[0].producer == "detection:threshold:join_burst"


def test_join_burst_below_threshold(storage, config):
    last = _add(storage, event_type="member_joined", actor_hash=hash_id(1))
    assert JoinBurstDetector().detect(last, storage, config) == []


def test_repeated_content_by_actor(storage, config):
    actor = hash_id(42)
    ch = content_hash("spammy")
    last = None
    for _ in range(3):
        last = _add(storage, event_type="message_created", actor_hash=actor, content_hash=ch)
    sigs = RepeatedContentDetector().detect(last, storage, config)
    assert sigs and "repeated_content" in sigs[0].producer


def test_rule_engine_promotes_ioc(storage, config):
    ev = _add(storage, event_type="ioc_matched", severity="high", confidence=0.9)
    sigs = RuleEngine().detect(ev, storage, config)
    assert any(s.producer == "detection:rule:ioc_match" for s in sigs)


def test_rule_engine_high_detection(storage, config):
    ev = _add(storage, event_type="detection_triggered", severity="high")
    sigs = RuleEngine().detect(ev, storage, config)
    assert any("high_detection" in s.producer for s in sigs)


def test_activity_spike(storage, config):
    # 12 events in current window, ~0 before → spike
    last = None
    for i in range(12):
        last = _add(storage, event_type="message_created", actor_hash=hash_id(i))
    sigs = ActivitySpikeDetector().detect(last, storage, config)
    assert sigs and sigs[0].producer == "detection:anomaly:activity_spike"


def test_sequence_join_leave_churn(storage, config):
    actor = hash_id(88)
    _add(storage, event_type="member_joined", actor_hash=actor)
    left = _add(storage, event_type="member_left", actor_hash=actor)
    det = default_sequence_detectors()[0]
    sigs = det.detect(left, storage, config)
    assert sigs and "churn" in sigs[0].producer


def test_manager_dedups_and_isolates(storage, config):
    last = None
    for uid in range(3):
        last = _add(storage, event_type="member_joined", actor_hash=hash_id(uid))
    sigs = DetectorManager().detect(last, storage, config)
    keys = [s.dedup_key for s in sigs]
    assert len(keys) == len(set(keys))
