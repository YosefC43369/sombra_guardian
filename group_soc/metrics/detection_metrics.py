"""
group_soc/metrics/detection_metrics.py — detection/signal breakdowns.

Summarizes which producers are firing and the analytic-state distribution, so an
operator can see detection coverage and tune thresholds. Bounded aggregate queries.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..util import now


class DetectionMetrics:
    def __init__(self, storage):
        self.storage = storage

    def signal_breakdown(self, chat_id: int, window_s: int = 86400) -> Dict[str, Any]:
        since = now() - window_s
        by_producer = self.storage.signals._get_many(
            "SELECT producer, COUNT(*) AS n FROM soc_signals WHERE chat_id=? AND ts>=? "
            "GROUP BY producer ORDER BY n DESC LIMIT 50", (int(chat_id), since))
        by_state = self.storage.signals._get_many(
            "SELECT analytic_state, COUNT(*) AS n FROM soc_signals WHERE chat_id=? AND ts>=? "
            "GROUP BY analytic_state", (int(chat_id), since))
        return {
            "window_s": window_s,
            "by_producer": {r["producer"]: int(r["n"]) for r in by_producer},
            "by_state": {r["analytic_state"]: int(r["n"]) for r in by_state},
        }
