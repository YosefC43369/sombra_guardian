"""
news_intelligence.reports.json_report — render a NewsReport to JSON.

Lossless JSON serialization of the report tree, for machine consumption and the
JSON Export deliverable. Reuses ``NewsReport.to_dict`` so the export round-trips
through ``NewsReport.from_dict``.
"""
from __future__ import annotations
import json
from ..models.report import NewsReport


def render_json(report: NewsReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


__all__ = ["render_json"]
