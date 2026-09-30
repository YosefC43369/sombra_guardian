"""
group_soc/cases/case_manager.py — the SOC CaseManager.

Owns the case object: creation, assignment, notes, evidence links, alert linkage and
validated lifecycle transitions. Every mutation is audited. Storage-focused and
bus-free (testable offline).
"""

from __future__ import annotations

from typing import List, Optional

from ..models.case import Case, CaseNote
from ..constants import CaseStatus, Severity, MAX_LABEL_LEN, MAX_NOTE_LEN
from ..exceptions import SocNotFoundError, SocValidationError
from ..util import clean_str
from .lifecycle import transition


class CaseManager:
    def __init__(self, storage):
        self.storage = storage

    def _load(self, case_id: str) -> Case:
        case = self.storage.cases.get(case_id)
        if case is None:
            raise SocNotFoundError("case not found", code="SOC_NOT_FOUND", case_id=case_id)
        return case

    def create(self, chat_id: int, title: str, *, opened_by_hash: Optional[str] = None,
               summary: str = "", severity: str = Severity.MEDIUM.value,
               alert_ids: Optional[List[str]] = None) -> Case:
        title = clean_str(title, MAX_LABEL_LEN)
        if not title:
            raise SocValidationError("case title required", code="SOC_VALIDATION_ERROR")
        case = Case(chat_id=int(chat_id), title=title, summary=summary or "",
                    severity=severity, opened_by_hash=opened_by_hash,
                    alert_ids=list(alert_ids or []))
        self.storage.cases.add(case)
        self.storage.audit(chat_id, "case.created", actor_hash=opened_by_hash,
                           target_kind="case", target_id=case.case_id)
        # link alerts back to the case
        for alert_id in case.alert_ids:
            self.storage.investigations.add_evidence_link(
                chat_id, "case", case.case_id, "alert", alert_id, added_by_hash=opened_by_hash)
        return case

    def get(self, case_id: str) -> Optional[Case]:
        return self.storage.cases.get(case_id)

    def list_open(self, chat_id: int, limit: int = 20) -> List[Case]:
        return self.storage.cases.list_open(chat_id, limit)

    def add_note(self, case_id: str, text: str, author_hash: Optional[str] = None) -> CaseNote:
        case = self._load(case_id)
        text = clean_str(text, MAX_NOTE_LEN)
        if not text:
            raise SocValidationError("empty note", code="SOC_VALIDATION_ERROR")
        note = CaseNote(case_id=case_id, text=text, author_hash=author_hash)
        self.storage.cases.add_note(note)
        self.storage.cases.update(case_id, {})  # bump updated_at
        self.storage.audit(case.chat_id, "case.note_added", actor_hash=author_hash,
                           target_kind="case", target_id=case_id)
        return note

    def list_notes(self, case_id: str) -> List[CaseNote]:
        return self.storage.cases.list_notes(case_id)

    def link_alert(self, case_id: str, alert_id: str,
                   actor_hash: Optional[str] = None) -> Case:
        case = self._load(case_id)
        if alert_id not in case.alert_ids:
            new_ids = case.alert_ids + [alert_id]
            self.storage.cases.update(case_id, {"alert_ids": new_ids})
            self.storage.investigations.add_evidence_link(
                case.chat_id, "case", case_id, "alert", alert_id, added_by_hash=actor_hash)
            self.storage.audit(case.chat_id, "case.alert_linked", actor_hash=actor_hash,
                               target_kind="case", target_id=case_id,
                               detail={"alert_id": alert_id})
        return self._load(case_id)

    def assign(self, case_id: str, assignee_hash: str,
               actor_hash: Optional[str] = None) -> Case:
        case = self._load(case_id)
        changes = {"assignee_hash": assignee_hash}
        if case.status == CaseStatus.OPEN.value:
            changes["status"] = CaseStatus.ASSIGNED.value
        self.storage.cases.update(case_id, changes)
        self.storage.audit(case.chat_id, "case.assigned", actor_hash=actor_hash,
                           target_kind="case", target_id=case_id)
        return self._load(case_id)

    def set_status(self, case_id: str, new_status: str,
                   actor_hash: Optional[str] = None) -> Case:
        case = self._load(case_id)
        updated, changes = transition(case, new_status)
        if changes:
            self.storage.cases.update(case_id, changes)
            self.storage.audit(case.chat_id, f"case.{new_status}", actor_hash=actor_hash,
                               target_kind="case", target_id=case_id)
        return updated

    def close(self, case_id: str, actor_hash: Optional[str] = None) -> Case:
        return self.set_status(case_id, CaseStatus.CLOSED.value, actor_hash)
