"""group_soc/storage/case_store.py — persistence for Cases and their notes."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .repository import SocStore
from ..models.case import Case, CaseNote
from ..constants import (
    MAX_QUERY_LIMIT, DEFAULT_QUERY_LIMIT, TERMINAL_CASE_STATUSES,
)
from ..util import bounded_limit, now, json_dump


class CaseStore(SocStore):
    # ---- cases ----
    def add(self, case: Case) -> None:
        self._insert("soc_cases", case.to_row())

    def get(self, case_id: str) -> Optional[Case]:
        row = self._get_one("SELECT * FROM soc_cases WHERE case_id=?", (case_id,))
        return Case.from_row(row) if row else None

    def save(self, case: Case) -> None:
        self._insert("soc_cases", case.to_row(), replace=True)

    def update(self, case_id: str, changes: Dict[str, Any]) -> int:
        changes = dict(changes)
        changes.setdefault("updated_at", now())
        for key in ("metadata", "alert_ids"):
            if key in changes and not isinstance(changes[key], (str, type(None))):
                changes[key] = json_dump(changes[key])
        return self._update("soc_cases", "case_id", case_id, changes)

    def recent(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[Case]:
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_cases WHERE chat_id=? ORDER BY updated_at DESC LIMIT ?",
            (int(chat_id), n))
        return [Case.from_row(r) for r in rows]

    def list_open(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[Case]:
        placeholders = ", ".join("?" for _ in TERMINAL_CASE_STATUSES)
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        params = [int(chat_id)] + list(TERMINAL_CASE_STATUSES) + [n]
        rows = self._get_many(
            f"SELECT * FROM soc_cases WHERE chat_id=? AND status NOT IN ({placeholders}) "
            f"ORDER BY updated_at DESC LIMIT ?", params)
        return [Case.from_row(r) for r in rows]

    def count_by_status(self, chat_id: int) -> Dict[str, int]:
        rows = self._get_many(
            "SELECT status, COUNT(*) AS n FROM soc_cases WHERE chat_id=? GROUP BY status",
            (int(chat_id),))
        return {r["status"]: int(r["n"]) for r in rows}

    # ---- notes ----
    def add_note(self, note: CaseNote) -> None:
        self._insert("soc_case_notes", note.to_row())

    def list_notes(self, case_id: str, limit: int = MAX_QUERY_LIMIT) -> List[CaseNote]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_case_notes WHERE case_id=? ORDER BY ts ASC LIMIT ?",
            (case_id, n))
        return [CaseNote.from_row(r) for r in rows]
