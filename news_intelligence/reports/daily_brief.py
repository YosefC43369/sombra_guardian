"""
news_intelligence.reports.daily_brief — the automatic Daily Intelligence Brief.

Assembles the spec's daily-brief sections from the last 24h of the stored corpus:
Top Threat Actors, Top Malware, Top CVEs, Top Campaigns, Emerging Trends,
Infrastructure Signals, New IOC Categories, Vendor Highlights and an Evidence Summary.
Every count is drawn from stored, deduplicated articles; every section can be traced
to the articles behind it. Duplicates never inflate counts (the store's queries skip
``duplicate_of`` rows).
"""

from __future__ import annotations

import time
from collections import Counter
from typing import List, Optional

from ..models.report import NewsReport, ReportSection
from ..trend import TrendEngine
from ..correlation.infrastructure_correlation import InfrastructureCorrelator
from ..clustering.campaign_cluster import CampaignClusterer
from .base import BaseReportBuilder


class DailyBriefBuilder(BaseReportBuilder):
    report_type = "daily"

    def build(self, *, hours: int = 24, top: int = 10) -> NewsReport:
        since = self.now - hours * 3600
        report = self._new_report(
            f"Daily Cyber Intelligence Brief — {time.strftime('%Y-%m-%d', time.gmtime(self.now))}",
            window_start=since, window_end=self.now)
        articles = self.store.list_articles(since=since, limit=2000)
        report.summary = (f"{len(articles)} unique articles collected in the last "
                          f"{hours}h across "
                          f"{len({a.source_domain for a in articles})} sources.")

        self._top_section(report, "Top Threat Actors", "threat_actor",
                          since, top, label="Actor")
        self._top_section(report, "Top Malware", "malware_family", since, top,
                          label="Malware")
        self._top_section(report, "Top CVEs", "cve", since, top, label="CVE")
        self._campaigns_section(report, articles, top)
        self._trends_section(report, articles)
        self._infra_section(report, articles)
        self._ioc_categories_section(report, articles)
        self._vendor_section(report, articles, top)
        self._evidence_section(report, articles)
        return report

    def _top_section(self, report, title, entity_type, since, top, *, label):
        counts = self.store.entity_counts(entity_type, since=since, limit=top)
        sec = ReportSection(title=title)
        for row in counts:
            sec.add_row({label: row["value"], "Articles": row["count"]})
        if not counts:
            sec.add_line("No mentions in window.")
        report.add_section(sec)

    def _campaigns_section(self, report, articles, top):
        camps = CampaignClusterer(now=self.now).build(articles)[:top]
        sec = ReportSection(title="Top Campaigns")
        for c in camps:
            sec.add_row({"Campaign": c.name,
                         "Independent reports": c.independent_report_count,
                         "Actors": ", ".join(c.actor_names[:3]),
                         "Malware": ", ".join(c.malware_names[:3])})
        if not camps:
            sec.add_line("No multi-source campaigns detected in window.")
        report.add_section(sec)

    def _trends_section(self, report, articles):
        te = TrendEngine(window_days=1)
        sec = ReportSection(title="Emerging Trends")
        emerging = []
        for kind, trends in te.all_trends(articles, now=self.now).items():
            for t in trends:
                if t.direction in ("emerging", "rising") and t.is_significant:
                    emerging.append(t)
        emerging.sort(key=lambda t: (t.direction != "emerging", -t.current_count))
        for t in emerging[:12]:
            sec.add_row({"Subject": t.subject, "Type": t.subject_type,
                         "Direction": t.direction, "Now": t.current_count,
                         "Prior": t.prior_count, "Sources": t.distinct_sources,
                         "Window (d)": t.window_days, "Sample": t.sample_size})
        if not emerging:
            sec.add_line("No statistically notable trends "
                         f"(min sample {te.min_sample}).")
        report.add_section(sec)

    def _infra_section(self, report, articles):
        rows = InfrastructureCorrelator(self.store, now=self.now).cross_source_iocs(
            articles, min_domains=2)
        sec = ReportSection(title="Infrastructure Signals")
        for r in rows[:15]:
            sec.add_row({"Indicator": r["value"], "Type": r["type"],
                         "Independent sources": r["independent_sources"]})
        if not rows:
            sec.add_line("No indicators reported across multiple sources in window.")
        report.add_section(sec)

    def _ioc_categories_section(self, report, articles):
        cats = Counter()
        for a in articles:
            for m in a.entity_mentions:
                if m.is_ioc:
                    cats[m.entity_type.value] += 1
        sec = ReportSection(title="New IOC Categories")
        for cat, n in cats.most_common():
            sec.add_row({"IOC type": cat, "Count": n})
        if not cats:
            sec.add_line("No IOCs extracted in window.")
        report.add_section(sec)

    def _vendor_section(self, report, articles, top):
        by_vendor = Counter(a.source_name or a.source_domain for a in articles)
        sec = ReportSection(title="Vendor Highlights")
        for vendor, n in by_vendor.most_common(top):
            sec.add_row({"Source": vendor, "Articles": n})
        report.add_section(sec)

    def _evidence_section(self, report, articles):
        sec = ReportSection(title="Evidence Summary")
        classes = Counter(a.source_class.value for a in articles)
        sec.add_line(f"Total unique articles: {len(articles)}")
        sec.add_line("Source-class mix: " + ", ".join(
            f"{k}={v}" for k, v in classes.most_common()))
        sec.add_line("Every figure above is derived from stored, deduplicated "
                     "articles; syndicated copies are excluded from counts.")
        report.add_section(sec)


__all__ = ["DailyBriefBuilder"]
