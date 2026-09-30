"""Correlation engine: each correlator fires on its pattern and stays quiet otherwise."""

from __future__ import annotations

from group_soc.models import SecurityEvent, EntityRef
from group_soc.util import hash_id, content_hash, now
from group_soc.correlation import (
    CampaignClusterer, SequenceCorrelator, BehavioralCorrelator,
    EntityCorrelator, TemporalCorrelator, CorrelationEngine,
)

from .conftest import CHAT


def _add(storage, **kw):
    kw.setdefault("chat_id", CHAT)
    kw.setdefault("ts", now())
    e = SecurityEvent(**kw)
    storage.events.add(e)
    return e


def test_campaign_clusterer(storage, config):
    ch = content_hash("FREE crypto claim")
    last = None
    for uid in range(3):
        last = _add(storage, event_type="message_created", actor_hash=hash_id(uid),
                    content_hash=ch)
    sig = CampaignClusterer().correlate(last, storage, config)
    assert sig is not None and sig.signal_type == "campaign"
    assert sig.metadata["distinct_actors"] == 3
    # one actor only → no campaign
    ch2 = content_hash("just me")
    solo = _add(storage, event_type="message_created", actor_hash=hash_id(99), content_hash=ch2)
    assert CampaignClusterer().correlate(solo, storage, config) is None


def test_sequence_join_then_link(storage, config):
    actor = hash_id(500)
    _add(storage, event_type="member_joined", actor_hash=actor)
    link = _add(storage, event_type="message_created", actor_hash=actor,
                entities=[EntityRef.domain("evil.com")])
    sig = SequenceCorrelator().correlate(link, storage, config)
    assert sig is not None and "join" in sig.producer
    # a link with no preceding join → no signal
    link2 = _add(storage, event_type="message_created", actor_hash=hash_id(501),
                 entities=[EntityRef.domain("evil.com")])
    assert SequenceCorrelator().correlate(link2, storage, config) is None


def test_behavioral_multi_signal(storage, config):
    actor = hash_id(700)
    _add(storage, event_type="detection_triggered", actor_hash=actor, severity="high")
    ioc = _add(storage, event_type="ioc_matched", actor_hash=actor, severity="high")
    sig = BehavioralCorrelator().correlate(ioc, storage, config)
    assert sig is not None and sig.metadata["distinct_types"] >= 2


def test_entity_shared_indicator(storage, config):
    dom = EntityRef.domain("shared.com")
    for uid in range(2):
        _add(storage, event_type="message_created", actor_hash=hash_id(uid), entities=[dom])
    cur = _add(storage, event_type="message_created", actor_hash=hash_id(2), entities=[dom])
    sig = EntityCorrelator().correlate(cur, storage, config)
    assert sig is not None and sig.signal_type == "entity"


def test_temporal_elevated_cluster(storage, config):
    _add(storage, event_type="detection_triggered", severity="high", analytic_state="observed")
    cur = _add(storage, event_type="ioc_matched", severity="critical")
    sig = TemporalCorrelator().correlate(cur, storage, config)
    assert sig is not None and sig.signal_type == "temporal"
    assert sig.metadata["cluster_size"] >= 2


def test_engine_dedups(storage, config):
    ch = content_hash("dupe")
    last = None
    for uid in range(3):
        last = _add(storage, event_type="message_created", actor_hash=hash_id(uid), content_hash=ch)
    sigs = CorrelationEngine().correlate(last, storage, config)
    keys = [s.dedup_key for s in sigs]
    assert len(keys) == len(set(keys))     # no duplicate dedup keys in one batch
