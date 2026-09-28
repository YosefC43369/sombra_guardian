"""
news_intelligence.reports.base — report rendering dispatch + builder base.

``render_report`` turns a ``NewsReport`` into the requested format
(dict/markdown/html/json/csv). ``BaseReportBuilder`` gives builders shared access to
the store and a helper to attach standing limitations to every report so no news
product ever ships without its epistemic caveats.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

from ..models.report import NewsReport, ReportSection
from ..models.confidence import (STANDING_LIMITATIONS, NEWS_STANDING_LIMITATIONS)
from .markdown_report import render_markdown
from .html_report import render_html
from .json_report import render_json
from .csv_report import render_csv


def render_report(report: NewsReport, *, fmt: str = "dict") -> Any:
    fmt = (fmt or "dict").lower()
    if fmt == "dict":
        return report.to_dict()
    if fmt in ("md", "markdown"):
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "json":
        return render_json(report)
    if fmt == "csv":
        return render_csv(report)
    return report.to_dict()


class BaseReportBuilder:
    report_type = "brief"

    def __init__(self, store, *, now: Optional[float] = None):
        self.store = store
        self.now = now or time.time()

    def _new_report(self, title: str, *, subject: str = "",
                    window_start: float = 0.0, window_end: float = 0.0
                    ) -> NewsReport:
        r = NewsReport(title=title, report_type=self.report_type, subject=subject,
                       generated_at=self.now, window_start=window_start,
                       window_end=window_end or self.now)
        self._attach_limitations(r)
        return r

    @staticmethod
    def _attach_limitations(report: NewsReport) -> None:
        seen = {l.get("text") for l in report.limitations}
        for text, sev in list(STANDING_LIMITATIONS) + list(NEWS_STANDING_LIMITATIONS):
            if text not in seen:
                report.limitations.append({"text": text, "severity": sev})


__all__ = ["render_report", "BaseReportBuilder"]
