"""group_soc/storage/alert_store.py — persistence for Alerts + the dedup/grouping queries."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .repository import SocStore
from ..models.alert import Alert
from ..constants import (
    MAX_QUERY_LIMIT, DEFAULT_QUERY_LIMIT, TERMINAL_ALERT_STATUSES, AlertStatus,
)
from ..util import bounded_limit, now, json_dump


class AlertStore(SocStore):
    def add(self, alert: Alert) -> None:
        self._insert("soc_alerts", alert.to_row())

    def get(self, alert_id: str) -> Optional[Alert]:
        row = self._get_one("SELECT * FROM soc_alerts WHERE alert_id=?", (alert_id,))
        return Alert.from_row(row) if row else None

    def save(self, alert: Alert) -> None:
        """Full upsert (INSERT OR REPLACE) — used after building a mutated copy."""
        self._insert("soc_alerts", alert.to_row(), replace=True)

    def update(self, alert_id: str, changes: Dict[str, Any]) -> int:
        changes = dict(changes)
        changes.setdefault("updated_at", now())
        # metadata/signal_ids passed as objects get json-encoded
        for key in ("metadata", "signal_ids"):
            if key in changes and not isinstance(changes[key], (str, type(None))):
                changes[key] = json_dump(changes[key])
        return self._update("soc_alerts", "alert_id", alert_id, changes)

    def find_active_by_dedup(self, chat_id: int, dedup_key: str) -> Optional[Alert]:
        """The most recent non-terminal alert sharing this dedup key (for folding)."""
        placeholders = ", ".join("?" for _ in TERMINAL_ALERT_STATUSES)
        params = [int(chat_id), dedup_key] + list(TERMINAL_ALERT_STATUSES)
        row = self._get_one(
            f"SELECT * FROM soc_alerts WHERE chat_id=? AND dedup_key=? "
            f"AND status NOT IN ({placeholders}) ORDER BY last_seen_at DESC LIMIT 1",
            params)
        return Alert.from_row(row) if row else None

    def recent(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[Alert]:
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_alerts WHERE chat_id=? ORDER BY updated_at DESC LIMIT ?",
            (int(chat_id), n))
        return [Alert.from_row(r) for r in rows]

    def list_by_status(self, chat_id: int, status: str,
                       limit: int = DEFAULT_QUERY_LIMIT) -> List[Alert]:
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_alerts WHERE chat_id=? AND status=? "
            "ORDER BY priority_score DESC, updated_at DESC LIMIT ?",
            (int(chat_id), status, n))
        return [Alert.from_row(r) for r in rows]

    def list_open(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[Alert]:
        placeholders = ", ".join("?" for _ in TERMINAL_ALERT_STATUSES)
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        params = [int(chat_id)] + list(TERMINAL_ALERT_STATUSES) + [n]
        rows = self._get_many(
            f"SELECT * FROM soc_alerts WHERE chat_id=? AND status NOT IN ({placeholders}) "
            f"ORDER BY priority_score DESC, updated_at DESC LIMIT ?",
            params)
        return [Alert.from_row(r) for r in rows]

    def count_by_status(self, chat_id: int) -> Dict[str, int]:
        rows = self._get_many(
            "SELECT status, COUNT(*) AS n FROM soc_alerts WHERE chat_id=? GROUP BY status",
            (int(chat_id),))
        return {r["status"]: int(r["n"]) for r in rows}

    def count_open(self, chat_id: int) -> int:
        placeholders = ", ".join("?" for _ in TERMINAL_ALERT_STATUSES)
        params = [int(chat_id)] + list(TERMINAL_ALERT_STATUSES)
        return self._count(
            f"SELECT COUNT(*) FROM soc_alerts WHERE chat_id=? AND status NOT IN ({placeholders})",
            params)
