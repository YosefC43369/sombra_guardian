"""
threat_actor_intelligence.reports — evidence-graded dossiers + renderers.

The ``*ReportBuilder`` classes assemble one structured dossier (dict) per entity
from the store; the format modules (markdown/html/json/csv) render that single
structure so every format carries the same facts, epistemic labels and the
standing limitations. ``render_report`` dispatches by format.
"""

from typing import Any, Dict

from .actor_report import ActorReportBuilder
from .campaign_report import CampaignReportBuilder
from .malware_report import MalwareReportBuilder
from . import markdown_report, html_report, json_report, csv_report


def render_report(dossier: Dict[str, Any], *, fmt: str = "markdown") -> str:
    fmt = (fmt or "markdown").lower()
    if fmt in ("markdown", "md"):
        return markdown_report.render(dossier)
    if fmt == "html":
        return html_report.render(dossier)
    if fmt == "json":
        return json_report.render(dossier)
    if fmt == "csv":
        return csv_report.render(dossier)
    raise ValueError(f"unknown report format: {fmt}")


__all__ = ["ActorReportBuilder", "CampaignReportBuilder", "MalwareReportBuilder",
           "markdown_report", "html_report", "json_report", "csv_report",
           "render_report"]
