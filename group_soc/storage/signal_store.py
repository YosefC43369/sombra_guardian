"""group_soc/storage/signal_store.py — persistence for SecuritySignals."""

from __future__ import annotations

from typing import List, Optional

from .repository import SocStore
from ..models.signal import SecuritySignal
from ..constants import MAX_QUERY_LIMIT, DEFAULT_QUERY_LIMIT
from ..util import bounded_limit


class SignalStore(SocStore):
    def add(self, signal: SecuritySignal) -> bool:
        row = signal.to_row()
        cols = list(row.keys())
        sql = (f"INSERT OR IGNORE INTO soc_signals ({', '.join(cols)}) "
               f"VALUES ({', '.join('?' for _ in cols)})")
        with self._conn() as conn:
            cur = conn.execute(sql, [row[c] for c in cols])
            return cur.rowcount > 0

    def get(self, signal_id: str) -> Optional[SecuritySignal]:
        row = self._get_one("SELECT * FROM soc_signals WHERE signal_id=?", (signal_id,))
        return SecuritySignal.from_row(row) if row else None

    def recent(self, chat_id: int, limit: int = DEFAULT_QUERY_LIMIT) -> List[SecuritySignal]:
        n = bounded_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_signals WHERE chat_id=? ORDER BY ts DESC LIMIT ?",
            (int(chat_id), n))
        return [SecuritySignal.from_row(r) for r in rows]

    def by_correlation(self, correlation_id: str) -> List[SecuritySignal]:
        rows = self._get_many(
            "SELECT * FROM soc_signals WHERE correlation_id=? ORDER BY ts ASC LIMIT ?",
            (correlation_id, MAX_QUERY_LIMIT))
        return [SecuritySignal.from_row(r) for r in rows]

    def count_recent_by_dedup(self, chat_id: int, dedup_key: str, since_ts: int) -> int:
        return self._count(
            "SELECT COUNT(*) FROM soc_signals WHERE chat_id=? AND dedup_key=? AND ts>=?",
            (int(chat_id), dedup_key, int(since_ts)))

    def total(self, chat_id: int) -> int:
        return self._count("SELECT COUNT(*) FROM soc_signals WHERE chat_id=?", (int(chat_id),))
