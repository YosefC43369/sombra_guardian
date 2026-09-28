"""
behavioral_intelligence.reports — report rendering.

Renders a ``BehaviorProfile`` to Markdown, JSON, CSV, HTML, an executive summary
or an evidence table. Every renderer preserves the epistemic labels
(OBSERVED/CORRELATED/INFERRED/UNKNOWN), confidence, observation period and
limitations, and honours the privacy/data-minimisation configuration.
"""

from . import (markdown_report, json_report, csv_report, html_report,
               executive_summary, evidence_report, behavioral_report)
from .behavioral_report import render_report, BehavioralReportBuilder

__all__ = [
    "markdown_report", "json_report", "csv_report", "html_report",
    "executive_summary", "evidence_report", "behavioral_report",
    "render_report", "BehavioralReportBuilder",
]
