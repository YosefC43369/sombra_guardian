"""
group_soc/storage/watchlist_store.py — persistence for watchlist entries.

A watchlist entry is a monitoring target, NOT a malicious verdict. Entries are
chat-scoped and can expire. Matching is done in-memory by the watchlist matcher
against a small, cached active set.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .repository import SocStore
from ..constants import MAX_QUERY_LIMIT, VALID_ENTITY_KINDS, VALID_SEVERITIES, Severity
from ..exceptions import SocValidationError
from ..util import now, clean_str, bounded_limit
from ..constants import MAX_LABEL_LEN, MAX_REASON_LEN


class WatchlistStore(SocStore):
    def add(self, chat_id: int, kind: str, value: str, *, note: Optional[str] = None,
            severity: str = Severity.MEDIUM.value, added_by_hash: Optional[str] = None,
            expires_at: Optional[int] = None) -> int:
        if kind not in VALID_ENTITY_KINDS:
            raise SocValidationError("invalid watchlist kind", code="SOC_VALIDATION_ERROR",
                                     kind=kind)
        if severity not in VALID_SEVERITIES:
            severity = Severity.MEDIUM.value
        value = (clean_str(value, MAX_LABEL_LEN) or "").lower()
        if not value:
            raise SocValidationError("empty watchlist value", code="SOC_VALIDATION_ERROR")
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO soc_watchlist (chat_id, kind, value, note, severity,
                       active, added_by_hash, added_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                   ON CONFLICT(chat_id, kind, value) DO UPDATE SET
                     active=1, note=excluded.note, severity=excluded.severity,
                     added_by_hash=excluded.added_by_hash, added_at=excluded.added_at,
                     expires_at=excluded.expires_at""",
                (int(chat_id), kind, value, clean_str(note, MAX_REASON_LEN), severity,
                 added_by_hash, now(), expires_at))
            return cur.lastrowid or 0

    def remove(self, chat_id: int, kind: str, value: str) -> int:
        value = (clean_str(value, MAX_LABEL_LEN) or "").lower()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE soc_watchlist SET active=0 WHERE chat_id=? AND kind=? AND value=?",
                (int(chat_id), kind, value))
            return cur.rowcount

    def list_active(self, chat_id: int, kind: Optional[str] = None,
                    limit: int = MAX_QUERY_LIMIT) -> List[Dict[str, Any]]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        t = now()
        if kind:
            return self._get_many(
                "SELECT * FROM soc_watchlist WHERE chat_id=? AND kind=? AND active=1 "
                "AND (expires_at IS NULL OR expires_at>?) ORDER BY added_at DESC LIMIT ?",
                (int(chat_id), kind, t, n))
        return self._get_many(
            "SELECT * FROM soc_watchlist WHERE chat_id=? AND active=1 "
            "AND (expires_at IS NULL OR expires_at>?) ORDER BY added_at DESC LIMIT ?",
            (int(chat_id), t, n))

    def match(self, chat_id: int, kind: str, value: str) -> Optional[Dict[str, Any]]:
        value = (clean_str(value, MAX_LABEL_LEN) or "").lower()
        return self._get_one(
            "SELECT * FROM soc_watchlist WHERE chat_id=? AND kind=? AND value=? AND active=1 "
            "AND (expires_at IS NULL OR expires_at>?)",
            (int(chat_id), kind, value, now()))
