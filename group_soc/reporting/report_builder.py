"""
group_soc/reporting/report_builder.py — assemble report data.

Gathers metrics + recent activity into a structured report dict for a chat over a
window (daily/weekly) or for a single incident. Formatters (executive/technical) render
it; exporters serialize it. Assembly is separate from rendering so the same data can be
shown many ways.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..util import now
from ..metrics.soc_metrics import SocMetrics
from ..metrics.detection_metrics import DetectionMetrics

DAY = 86400
WEEK = 7 * DAY


class ReportBuilder:
    def __init__(self, storage):
        self.storage = storage
        self.metrics = SocMetrics(storage)
        self.detection = DetectionMetrics(storage)

    def period_report(self, chat_id: int, window_s: int, label: str) -> Dict[str, Any]:
        overview = self.metrics.overview(chat_id, window_s)
        detection = self.detection.signal_breakdown(chat_id, window_s)
        open_incidents = [i.to_payload() for i in self.storage.incidents.list_open(chat_id, 20)]
        top_alerts = [a.to_payload() for a in self.storage.alerts.list_open(chat_id, 10)]
        return {
            "label": label,
            "generated_at": now(),
            "window_s": window_s,
            "overview": overview,
            "detection": detection,
            "open_incidents": open_incidents,
            "top_alerts": top_alerts,
        }

    def daily(self, chat_id: int) -> Dict[str, Any]:
        return self.period_report(chat_id, DAY, "Daily")

    def weekly(self, chat_id: int) -> Dict[str, Any]:
        return self.period_report(chat_id, WEEK, "Weekly")

    def incident_report(self, incident) -> Dict[str, Any]:
        return {
            "label": "Incident",
            "generated_at": now(),
            "incident": incident.as_dict(),
        }
