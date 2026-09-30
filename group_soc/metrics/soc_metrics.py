"""
group_soc/metrics/soc_metrics.py — SOC operational metrics.

Computes the numbers the /soc metrics and reports surface: volumes, open/closed
counts, and the two headline SOC KPIs — MTTA (mean time to acknowledge) and MTTR
(mean time to resolve) — from the alert timestamps. All bounded aggregate queries.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..util import now


class SocMetrics:
    def __init__(self, storage):
        self.storage = storage

    def _avg_delta(self, chat_id: int, end_col: str, since_ts: Optional[int]) -> Optional[float]:
        clause = "chat_id=? AND {c} IS NOT NULL".format(c=end_col)
        params = [int(chat_id)]
        if since_ts is not None:
            clause += " AND created_at>=?"
            params.append(int(since_ts))
        row = self.storage.alerts._get_one(
            f"SELECT AVG({end_col} - created_at) AS d, COUNT(*) AS n "
            f"FROM soc_alerts WHERE {clause}", params)
        if not row or not row.get("n"):
            return None
        return round(float(row["d"]), 1) if row.get("d") is not None else None

    def mtta(self, chat_id: int, since_ts: Optional[int] = None) -> Optional[float]:
        return self._avg_delta(chat_id, "acknowledged_at", since_ts)

    def mttr(self, chat_id: int, since_ts: Optional[int] = None) -> Optional[float]:
        return self._avg_delta(chat_id, "resolved_at", since_ts)

    def overview(self, chat_id: int, window_s: Optional[int] = None) -> Dict[str, Any]:
        since = (now() - window_s) if window_s else None
        events = (self.storage.events.count_all_since(chat_id, since) if since
                  else self.storage.events.total(chat_id))
        return {
            "chat_id": int(chat_id),
            "window_s": window_s,
            "events": events,
            "signals": self.storage.signals.total(chat_id),
            "alerts_by_status": self.storage.alerts.count_by_status(chat_id),
            "alerts_open": self.storage.alerts.count_open(chat_id),
            "cases_by_status": self.storage.cases.count_by_status(chat_id),
            "incidents_by_status": self.storage.incidents.count_by_status(chat_id),
            "mtta_s": self.mtta(chat_id, since),
            "mttr_s": self.mttr(chat_id, since),
        }
