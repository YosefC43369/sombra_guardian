"""Incident manager: classification, aggregation, linking, lifecycle, member bridge."""

from __future__ import annotations

import pytest

from group_soc.models import SecuritySignal, RiskDimensions
from group_soc.incidents import IncidentManager, classify, aggregate_dimensions
from group_soc.exceptions import SocStateError, SocValidationError

from .conftest import CHAT


def _sig(producer, sev=0.7, conf=0.6):
    return SecuritySignal(chat_id=CHAT, producer=producer, title="t",
                          dimensions=RiskDimensions(severity=sev, confidence=conf, impact=0.6))


def test_classify_from_producers():
    assert classify([_sig("detection:threshold:join_burst")]) == "raid"
    assert classify([_sig("correlation:campaign")]) == "spam_campaign"
    assert classify([_sig("detection:rule:ioc_match")]) == "ioc_exposure"
    assert classify([_sig("something:else")]) == "other"


def test_aggregate_dimensions_noisy_or():
    dims = aggregate_dimensions([_sig("a", conf=0.5), _sig("b", conf=0.5)])
    assert 0.74 < dims.confidence < 0.76      # noisy-OR of two 0.5s


def test_create_from_signals(storage, config):
    im = IncidentManager(storage)
    inc = im.create_from_signals(CHAT, [_sig("detection:threshold:join_burst")],
                                 opened_by_hash="admin")
    assert inc.classification == "raid" and inc.status == "open"


def test_create_from_no_signals_raises(storage, config):
    with pytest.raises(SocValidationError):
        IncidentManager(storage).create_from_signals(CHAT, [])


def test_lifecycle_and_resolve(storage, config):
    im = IncidentManager(storage)
    inc = im.create_manual(CHAT, "manual", "raid", opened_by_hash="admin")
    contained = im.set_status(inc.incident_id, "contained")
    assert contained.status == "contained"
    with pytest.raises(SocStateError):
        im.set_status(inc.incident_id, "open")      # cannot go back to open
    resolved = im.resolve(inc.incident_id, "handled")
    assert resolved.status == "resolved" and resolved.resolution == "handled"


def test_link_alert_and_case(storage, config):
    im = IncidentManager(storage)
    inc = im.create_manual(CHAT, "t", "raid")
    im.link_alert(inc.incident_id, "alt_9")
    inc2 = im.link_case(inc.incident_id, "case_9")
    assert "alt_9" in inc2.alert_ids and "case_9" in inc2.case_ids


def test_member_bridge_injected(storage, config):
    calls = {}
    def bridge(chat_id, user_id, classification, severity, reason):
        calls["hit"] = (chat_id, classification)
        return 12345
    im = IncidentManager(storage, member_bridge=bridge)
    inc = im.create_manual(CHAT, "t", "raid")
    inc2 = im.bridge_member(inc.incident_id, "actorhash", "reason", actor_id_for_bridge=999)
    assert inc2.member_incident_id == 12345 and calls["hit"][1] == "raid"
