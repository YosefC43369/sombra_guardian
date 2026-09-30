"""Case manager: create, note, assign, link, close, invalid transitions."""

from __future__ import annotations

import pytest

from group_soc.cases import CaseManager
from group_soc.exceptions import SocValidationError, SocStateError, SocNotFoundError

from .conftest import CHAT


def test_create_and_note(storage, config):
    cm = CaseManager(storage)
    c = cm.create(CHAT, "Investigate spam", opened_by_hash="admin")
    assert c.status == "open"
    cm.add_note(c.case_id, "looks coordinated", "admin")
    assert len(cm.list_notes(c.case_id)) == 1


def test_create_requires_title(storage, config):
    with pytest.raises(SocValidationError):
        CaseManager(storage).create(CHAT, "   ")


def test_assign_moves_to_assigned(storage, config):
    cm = CaseManager(storage)
    c = cm.create(CHAT, "t")
    c2 = cm.assign(c.case_id, "analyst", "admin")
    assert c2.status == "assigned" and c2.assignee_hash == "analyst"


def test_link_alert(storage, config):
    cm = CaseManager(storage)
    c = cm.create(CHAT, "t")
    c2 = cm.link_alert(c.case_id, "alt_1", "admin")
    assert "alt_1" in c2.alert_ids
    links = storage.investigations.list_evidence_links("case", c.case_id)
    assert any(l["ref_id"] == "alt_1" for l in links)


def test_close_and_invalid_transition(storage, config):
    cm = CaseManager(storage)
    c = cm.create(CHAT, "t")
    closed = cm.close(c.case_id, "admin")
    assert closed.status == "closed" and closed.closed_at is not None
    with pytest.raises(SocStateError):
        cm.set_status(c.case_id, "open")     # closed is terminal


def test_note_on_missing_case(storage, config):
    with pytest.raises(SocNotFoundError):
        CaseManager(storage).add_note("nope", "x")
