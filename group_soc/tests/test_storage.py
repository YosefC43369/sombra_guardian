"""Storage layer: idempotent ingest, bounded queries, policy, audit, dedup lookups."""

from __future__ import annotations

from group_soc.models import SecurityEvent, SecuritySignal, Alert, Case, CaseNote, Incident, RiskDimensions
from group_soc.util import hash_id, content_hash

from .conftest import CHAT


def test_event_idempotent_ingest(storage):
    e = SecurityEvent(event_type="member_joined", chat_id=CHAT, actor_hash="h")
    assert storage.events.add(e) is True
    assert storage.events.add(e) is False       # duplicate event_id
    assert storage.events.total(CHAT) == 1


def test_content_hash_aggregates(storage):
    ch = content_hash("buy now")
    for uid in range(3):
        storage.events.add(SecurityEvent(event_type="message_created", chat_id=CHAT,
                                         actor_hash=hash_id(uid), content_hash=ch))
    assert storage.events.count_by_content_hash(CHAT, ch, 0) == 3
    assert storage.events.distinct_actors_by_content_hash(CHAT, ch, 0) == 3


def test_policy_default_inactive_then_active(storage):
    assert storage.is_group_active(CHAT) is False
    storage.set_policy(CHAT, enabled=True, mode="alert")
    assert storage.is_group_active(CHAT) is True
    assert storage.get_policy(CHAT)["mode"] == "alert"


def test_alert_dedup_lookup_and_open_count(storage):
    a = Alert(chat_id=CHAT, dedup_key="k1", title="A")
    storage.alerts.add(a)
    assert storage.alerts.find_active_by_dedup(CHAT, "k1").alert_id == a.alert_id
    assert storage.alerts.count_open(CHAT) == 1
    storage.alerts.update(a.alert_id, {"status": "closed", "resolved_at": 1})
    assert storage.alerts.find_active_by_dedup(CHAT, "k1") is None   # terminal excluded
    assert storage.alerts.count_open(CHAT) == 0


def test_audit_and_retention(storage):
    storage.audit(CHAT, "test.action", target_kind="x", target_id="1")
    assert len(storage.base.list_audit(CHAT)) == 1
    # retention allow-list guards table names
    storage.events.add(SecurityEvent(chat_id=CHAT, ts=1))
    removed = storage.base.purge_older_than("soc_events", "ts", 100)
    assert removed == 1


def test_retention_rejects_unknown_table(storage):
    import pytest
    from group_soc.exceptions import SocStorageError
    with pytest.raises(SocStorageError):
        storage.base.purge_older_than("soc_alerts", "created_at", 1)


def test_case_notes_and_incident_store(storage):
    c = Case(chat_id=CHAT, title="case")
    storage.cases.add(c)
    storage.cases.add_note(CaseNote(case_id=c.case_id, text="note"))
    assert len(storage.cases.list_notes(c.case_id)) == 1
    inc = Incident(chat_id=CHAT, classification="raid")
    storage.incidents.add(inc)
    assert storage.incidents.count_by_status(CHAT).get("open") == 1
