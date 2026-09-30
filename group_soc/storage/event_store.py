"""
group_soc/storage/event_store.py — persistence for SecurityEvents.

Ingest is idempotent: ``event_id`` is the primary key and ``add`` uses INSERT OR
IGNORE, so a duplicated bus delivery never double-counts. All read paths are
bounded and use the indexes created in migration 0006.
"""

from __future__ import annotations

from typing import List, Optional

from .repository import SocStore
from ..models.event import SecurityEvent
from ..constants import MAX_QUERY_LIMIT, DEFAULT_QUERY_LIMIT
from ..util import bounded_limit, now


class EventStore(SocStore):
    def add(self, event: SecurityEvent) -> bool:
        """Persist an event. Returns True if newly inserted, False if a duplicate
        event_id already existed (idempotent ingest)."""
        row = event.to_row()
        cols = list(row.keys())
        sql = (f"INSERT OR IGNORE INTO soc_events ({', '.join(cols)}) "
               f"VALUES ({', '.join('?' for _ in cols)})")
        with self._conn() as conn:
            cur = conn.execute(sql, [row[c] for c in cols])
            return cur.rowcount > 0

    def get(self, event_id: str) -> Optional[SecurityEvent]:
        row = self._get_one("SELECT * FROM soc_events WHERE event_id=?", (event_id,))
        return SecurityEvent.from_row(row) if row else None

    def recent(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[SecurityEvent]:
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_events WHERE chat_id=? ORDER BY ts DESC, rowid DESC LIMIT ?",
            (int(chat_id), n))
        return [SecurityEvent.from_row(r) for r in rows]

    def by_correlation(self, correlation_id: str,
                       limit: int = MAX_QUERY_LIMIT) -> List[SecurityEvent]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_events WHERE correlation_id=? ORDER BY ts ASC LIMIT ?",
            (correlation_id, n))
        return [SecurityEvent.from_row(r) for r in rows]

    def search(self, chat_id: int, *, event_type: Optional[str] = None,
               actor_hash: Optional[str] = None, since_ts: Optional[int] = None,
               until_ts: Optional[int] = None,
               limit: int = DEFAULT_QUERY_LIMIT) -> List[SecurityEvent]:
        clauses = ["chat_id=?"]
        params: list = [int(chat_id)]
        if event_type:
            clauses.append("event_type=?")
            params.append(event_type)
        if actor_hash:
            clauses.append("actor_hash=?")
            params.append(actor_hash)
        if since_ts is not None:
            clauses.append("ts>=?")
            params.append(int(since_ts))
        if until_ts is not None:
            clauses.append("ts<=?")
            params.append(int(until_ts))
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        params.append(n)
        sql = (f"SELECT * FROM soc_events WHERE {' AND '.join(clauses)} "
               f"ORDER BY ts DESC LIMIT ?")
        return [SecurityEvent.from_row(r) for r in self._get_many(sql, params)]

    # ---- aggregates used by detectors (bounded, indexed) ----
    def count_since(self, chat_id: int, event_type: str, since_ts: int,
                    actor_hash: Optional[str] = None) -> int:
        if actor_hash:
            return self._count(
                "SELECT COUNT(*) FROM soc_events WHERE chat_id=? AND event_type=? "
                "AND ts>=? AND actor_hash=?",
                (int(chat_id), event_type, int(since_ts), actor_hash))
        return self._count(
            "SELECT COUNT(*) FROM soc_events WHERE chat_id=? AND event_type=? AND ts>=?",
            (int(chat_id), event_type, int(since_ts)))

    def count_by_content_hash(self, chat_id: int, content_hash: str,
                              since_ts: int) -> int:
        return self._count(
            "SELECT COUNT(*) FROM soc_events WHERE chat_id=? AND content_hash=? AND ts>=?",
            (int(chat_id), content_hash, int(since_ts)))

    def distinct_actors_by_content_hash(self, chat_id: int, content_hash: str,
                                        since_ts: int) -> int:
        return self._count(
            "SELECT COUNT(DISTINCT actor_hash) FROM soc_events "
            "WHERE chat_id=? AND content_hash=? AND ts>=?",
            (int(chat_id), content_hash, int(since_ts)))

    def count_all_since(self, chat_id: int, since_ts: int) -> int:
        return self._count(
            "SELECT COUNT(*) FROM soc_events WHERE chat_id=? AND ts>=?",
            (int(chat_id), int(since_ts)))

    def elevated_in_window(self, chat_id: int, since_ts: int,
                           limit: int = 50) -> List["SecurityEvent"]:
        """Recent events with high/critical severity or a suspicious analytic state,
        used by the temporal correlator to cluster elevated activity. Bounded."""
        n = bounded_limit(limit, 50, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_events WHERE chat_id=? AND ts>=? "
            "AND (severity IN ('high','critical') OR analytic_state='suspicious') "
            "ORDER BY ts DESC LIMIT ?", (int(chat_id), int(since_ts), n))
        return [SecurityEvent.from_row(r) for r in rows]

    def recent_in_window(self, chat_id: int, since_ts: int,
                         limit: int = MAX_QUERY_LIMIT) -> List["SecurityEvent"]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_events WHERE chat_id=? AND ts>=? ORDER BY ts DESC LIMIT ?",
            (int(chat_id), int(since_ts), n))
        return [SecurityEvent.from_row(r) for r in rows]

    def total(self, chat_id: int) -> int:
        return self._count("SELECT COUNT(*) FROM soc_events WHERE chat_id=?", (int(chat_id),))
