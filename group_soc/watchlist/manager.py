"""
group_soc/watchlist/manager.py — manage monitoring targets.

A watchlist entry is a monitoring target, never a malicious verdict (rule §14). The
manager applies privacy rules (a watched *user* is stored as a salted hash, not a raw
id), validates kinds, and audits every change.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..constants import EntityKind, Severity
from ..exceptions import SocValidationError
from ..util import hash_id, defang
from .indicators import normalize_indicator


class WatchlistManager:
    def __init__(self, storage):
        self.storage = storage

    def add(self, chat_id: int, kind: str, value: str, *, note: Optional[str] = None,
            severity: str = Severity.MEDIUM.value, added_by_hash: Optional[str] = None,
            expires_at: Optional[int] = None) -> int:
        kind, value = normalize_indicator(kind, value)
        wid = self.storage.watchlist.add(chat_id, kind, value, note=note, severity=severity,
                                         added_by_hash=added_by_hash, expires_at=expires_at)
        self.storage.audit(chat_id, "watchlist.added", actor_hash=added_by_hash,
                           target_kind="watchlist", target_id=f"{kind}:{value}")
        return wid

    def watch_user(self, chat_id: int, user_id: int, *, note: Optional[str] = None,
                   severity: str = Severity.MEDIUM.value,
                   added_by_hash: Optional[str] = None) -> int:
        """Watch a user by id — stored as a salted hash for privacy."""
        h = hash_id(user_id)
        if not h:
            raise SocValidationError("invalid user id", code="SOC_VALIDATION_ERROR")
        return self.add(chat_id, EntityKind.USER.value, h, note=note, severity=severity,
                        added_by_hash=added_by_hash)

    def remove(self, chat_id: int, kind: str, value: str,
               actor_hash: Optional[str] = None) -> int:
        kind, value = normalize_indicator(kind, value)
        n = self.storage.watchlist.remove(chat_id, kind, value)
        if n:
            self.storage.audit(chat_id, "watchlist.removed", actor_hash=actor_hash,
                               target_kind="watchlist", target_id=f"{kind}:{value}")
        return n

    def list(self, chat_id: int, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.storage.watchlist.list_active(chat_id, kind)
