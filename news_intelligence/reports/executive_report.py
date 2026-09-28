"""
news_intelligence.reports.executive_report — the Executive Summary.

A concise, decision-maker-oriented summary of the current threat picture from the
corpus: the few most-corroborated stories, the emerging trends that clear the
significance bar, the CVEs with confirmed public exploitation, and a one-paragraph
narrative. Deliberately short and plain; every claim still traces to sources, and the
epistemic caveats ride along in the limitations block.
"""

from __future__ import annotations

import time
from typing import Optional

from ..models.report import NewsReport, ReportSection
from ..trend import TrendEngine
from ..clustering.event_cluster import EventClusterer
from ..correlation.infrastructure_correlation import InfrastructureCorrelator
from .base import BaseReportBuilder


class ExecutiveReportBuilder(BaseReportBuilder):
    report_type = "executive"

    def build(self, *, days: int = 7, top: int = 5) -> NewsReport:
        since = self.now - days * 86400
        report = self._new_report(
            f"Executive Cyber Intelligence Summary — "
            f"{time.strftime('%Y-%m-%d', time.gmtime(self.now))}",
            window_start=since, window_end=self.now)
        articles = self.store.list_articles(since=since, limit=5000)

        # most-corroborated events
        events = EventClusterer(window_hours=days * 24).cluster(articles)
        top_events = [e for e in events if e.independent_sources >= 2][:top]
        headline = ReportSection(title="Most-Corroborated Stories")
        for e in top_events:
            headline.add_row({"Story": e.label,
                              "Independent sources": e.independent_sources,
                              "Articles": e.size, "Key signals": ", ".join(
                                  e.signals[:3])})
        if not top_events:
            headline.add_line("No stories corroborated by multiple sources in window.")
        report.add_section(headline)

        # emerging trends
        te = TrendEngine(window_days=days)
        trends = []
        for kind, ts in te.all_trends(articles, now=self.now).items():
            trends += [t for t in ts if t.direction in ("emerging", "rising")
                       and t.is_significant]
        trends.sort(key=lambda t: (t.direction != "emerging", -t.current_count))
        tsec = ReportSection(title="What Is Rising")
        for t in trends[:top]:
            tsec.add_line(f"{t.subject} ({t.subject_type}) — {t.direction}, "
                          f"{t.current_count} articles / {t.distinct_sources} sources "
                          f"(sample {t.sample_size}, {t.window_days}d)")
        if not trends:
            tsec.add_line("No significant emerging trends.")
        report.add_section(tsec)

        # confirmed-exploited CVEs
        kev = ReportSection(title="CVEs with Publicly-Reported Exploitation")
        for a in articles:
            if a.detail.get("kev") if isinstance(a.detail, dict) else False:
                kev.add_line(f"{a.detail.get('cve','')} — {a.title[:80]}")
        if not kev.lines:
            kev.add_line("No new publicly-confirmed exploited CVEs in window.")
        report.add_section(kev)

        report.summary = (
            f"In the last {days} days the corpus collected {len(articles)} unique "
            f"articles from {len({a.source_domain for a in articles})} sources. "
            f"{len(top_events)} stories were independently corroborated. "
            "All figures derive from public reporting; treat attributions as the "
            "publishers'.")
        return report


__all__ = ["ExecutiveReportBuilder"]
