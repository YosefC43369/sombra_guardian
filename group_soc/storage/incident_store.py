"""group_soc/storage/incident_store.py — persistence for SOC Incidents."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .repository import SocStore
from ..models.incident import Incident
from ..constants import MAX_QUERY_LIMIT, DEFAULT_QUERY_LIMIT, TERMINAL_INCIDENT_STATUSES
from ..util import bounded_limit, now, json_dump


class IncidentStore(SocStore):
    def add(self, incident: Incident) -> None:
        self._insert("soc_incidents", incident.to_row())

    def get(self, incident_id: str) -> Optional[Incident]:
        row = self._get_one("SELECT * FROM soc_incidents WHERE incident_id=?", (incident_id,))
        return Incident.from_row(row) if row else None

    def save(self, incident: Incident) -> None:
        self._insert("soc_incidents", incident.to_row(), replace=True)

    def update(self, incident_id: str, changes: Dict[str, Any]) -> int:
        changes = dict(changes)
        changes.setdefault("updated_at", now())
        for key in ("metadata", "alert_ids", "case_ids", "correlation_ids", "dimensions"):
            if key in changes and not isinstance(changes[key], (str, type(None))):
                changes[key] = json_dump(changes[key])
        return self._update("soc_incidents", "incident_id", incident_id, changes)

    def recent(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[Incident]:
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_incidents WHERE chat_id=? ORDER BY updated_at DESC LIMIT ?",
            (int(chat_id), n))
        return [Incident.from_row(r) for r in rows]

    def list_open(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[Incident]:
        placeholders = ", ".join("?" for _ in TERMINAL_INCIDENT_STATUSES)
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        params = [int(chat_id)] + list(TERMINAL_INCIDENT_STATUSES) + [n]
        rows = self._get_many(
            f"SELECT * FROM soc_incidents WHERE chat_id=? AND status NOT IN ({placeholders}) "
            f"ORDER BY updated_at DESC LIMIT ?", params)
        return [Incident.from_row(r) for r in rows]

    def count_by_status(self, chat_id: int) -> Dict[str, int]:
        rows = self._get_many(
            "SELECT status, COUNT(*) AS n FROM soc_incidents WHERE chat_id=? GROUP BY status",
            (int(chat_id),))
        return {r["status"]: int(r["n"]) for r in rows}
