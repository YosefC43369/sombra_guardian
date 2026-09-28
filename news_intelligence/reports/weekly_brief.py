"""
news_intelligence.reports.weekly_brief — the Weekly Threat Brief.

Aggregates a 7-day window and adds week-over-week trend comparison against the prior
week (spec: "Include trend comparisons with previous week"). Reuses the daily brief's
section builders over the wider window and prepends a trend-comparison section that
shows what rose, fell and emerged versus the previous 7 days.
"""

from __future__ import annotations

import time
from typing import Optional

from ..models.report import NewsReport, ReportSection
from ..trend import TrendEngine
from .base import BaseReportBuilder
from .daily_brief import DailyBriefBuilder


class WeeklyBriefBuilder(BaseReportBuilder):
    report_type = "weekly"

    def build(self, *, top: int = 15) -> NewsReport:
        since = self.now - 7 * 86400
        report = self._new_report(
            f"Weekly Threat Brief — week ending "
            f"{time.strftime('%Y-%m-%d', time.gmtime(self.now))}",
            window_start=since, window_end=self.now)
        articles = self.store.list_articles(since=since, limit=5000)
        report.summary = (f"{len(articles)} unique articles across "
                          f"{len({a.source_domain for a in articles})} sources "
                          "in the last 7 days.")

        # week-over-week comparison first
        te = TrendEngine(window_days=7)
        cmp_sec = ReportSection(title="Week-over-Week Comparison")
        all_trends = te.all_trends(articles, now=self.now)
        for kind in ("cve", "malware", "actor", "topic"):
            movers = [t for t in all_trends[kind]
                      if t.direction in ("rising", "emerging", "falling")
                      and t.is_significant][:8]
            for t in movers:
                cmp_sec.add_row({"Type": kind, "Subject": t.subject,
                                 "Direction": t.direction,
                                 "This week": t.current_count,
                                 "Last week": t.prior_count,
                                 "x": t.change_ratio, "Sources": t.distinct_sources})
        if not cmp_sec.rows:
            cmp_sec.add_line("No significant week-over-week movement.")
        report.add_section(cmp_sec)

        # reuse the daily builders over the weekly window
        daily = DailyBriefBuilder(self.store, now=self.now)
        daily._top_section(report, "Top Threat Actors (7d)", "threat_actor",
                           since, top, label="Actor")
        daily._top_section(report, "Top Malware (7d)", "malware_family", since,
                           top, label="Malware")
        daily._top_section(report, "Top CVEs (7d)", "cve", since, top, label="CVE")
        daily._campaigns_section(report, articles, top)
        daily._infra_section(report, articles)
        daily._vendor_section(report, articles, top)
        daily._evidence_section(report, articles)
        return report


__all__ = ["WeeklyBriefBuilder"]
