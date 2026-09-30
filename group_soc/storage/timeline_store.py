"""group_soc/storage/timeline_store.py — persistence for reconstructed timeline entries."""

from __future__ import annotations

from typing import List

from .repository import SocStore
from ..models.timeline import TimelineEntry
from ..constants import MAX_QUERY_LIMIT
from ..util import bounded_limit


class TimelineStore(SocStore):
    def add(self, entry: TimelineEntry) -> None:
        self._insert("soc_timeline", entry.to_row())

    def add_many(self, entries: List[TimelineEntry]) -> int:
        n = 0
        with self._conn() as conn:
            for e in entries:
                row = e.to_row()
                cols = list(row.keys())
                conn.execute(
                    f"INSERT OR IGNORE INTO soc_timeline ({', '.join(cols)}) "
                    f"VALUES ({', '.join('?' for _ in cols)})",
                    [row[c] for c in cols])
                n += 1
        return n

    def by_correlation(self, correlation_id: str) -> List[TimelineEntry]:
        rows = self._get_many(
            "SELECT * FROM soc_timeline WHERE correlation_id=? ORDER BY ts ASC LIMIT ?",
            (correlation_id, MAX_QUERY_LIMIT))
        return [TimelineEntry.from_row(r) for r in rows]

    def window(self, chat_id: int, since_ts: int, until_ts: int,
               limit: int = MAX_QUERY_LIMIT) -> List[TimelineEntry]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_timeline WHERE chat_id=? AND ts>=? AND ts<=? "
            "ORDER BY ts ASC LIMIT ?", (int(chat_id), int(since_ts), int(until_ts), n))
        return [TimelineEntry.from_row(r) for r in rows]
