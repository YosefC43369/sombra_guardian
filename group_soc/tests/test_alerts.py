"""Alert engine: create, dedup/fold, escalate, suppress, lifecycle transitions."""

from __future__ import annotations

import dataclasses

import pytest

from group_soc.models import SecuritySignal, RiskDimensions
from group_soc.alerts import AlertManager
from group_soc.exceptions import SocStateError

from .conftest import CHAT


def _sig(dedup="k", **kw):
    d = dict(chat_id=CHAT, title="t", summary="s", dedup_key=dedup,
             dimensions=RiskDimensions(severity=0.7, confidence=0.7, impact=0.5, urgency=0.6))
    d.update(kw)
    return SecuritySignal(**d)


def test_create_then_fold(storage, config):
    am = AlertManager(storage, config)
    o1 = am.process_signal(_sig())
    assert o1.action == "created" and o1.alert is not None
    o2 = am.process_signal(_sig())
    assert o2.action in ("folded", "escalated")
    # still exactly one alert for that dedup key
    assert storage.alerts.count_open(CHAT) == 1
    assert storage.alerts.get(o1.alert.alert_id).hit_count == 2


def test_escalation_after_threshold(storage, config):
    am = AlertManager(storage, config)      # escalation_repeat_threshold=3
    for _ in range(3):
        last = am.process_signal(_sig())
    assert last.escalated is True
    assert storage.alerts.get(last.alert.alert_id).status == "escalated"


def test_suppression_after_resolution(storage, config):
    cfg = dataclasses.replace(config, alert_cooldown_s=3600)
    am = AlertManager(storage, cfg)
    o = am.process_signal(_sig("kx"))
    am.resolve(o.alert.alert_id)
    # a fresh identical signal within cooldown is suppressed, not re-opened
    o2 = am.process_signal(_sig("kx"))
    assert o2.action == "suppressed" and o2.alert is None


def test_lifecycle_valid_and_invalid(storage, config):
    am = AlertManager(storage, config)
    o = am.process_signal(_sig("kl"))
    a = am.acknowledge(o.alert.alert_id)
    assert a.status == "acknowledged" and a.acknowledged_at is not None
    r = am.resolve(o.alert.alert_id)
    assert r.status == "resolved" and r.resolved_at is not None
    # resolved -> acknowledged is illegal
    with pytest.raises(SocStateError):
        am.acknowledge(o.alert.alert_id)


def test_assign_triages_new_alert(storage, config):
    am = AlertManager(storage, config)
    o = am.process_signal(_sig("ka"))
    a = am.assign(o.alert.alert_id, "analyst_hash")
    assert a.assignee_hash == "analyst_hash" and a.status == "triaged"


def test_grouping_shares_group_id(storage, config):
    am = AlertManager(storage, config)
    o1 = am.process_signal(_sig("g1", correlation_id="corrX"))
    o2 = am.process_signal(_sig("g2", correlation_id="corrX"))
    assert o1.alert.group_id == o2.alert.group_id
