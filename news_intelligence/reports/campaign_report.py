"""
news_intelligence.reports.campaign_report — the Campaign News Profile.

Renders a ``CampaignNews`` aggregate: involved actors, malware, CVEs, targeted
sectors/countries, ATT&CK techniques, IOCs, the independent sources corroborating it,
and — importantly — the *differing claims* recorded between sources (attribution,
dates), shown side by side and never resolved by the engine.
"""

from __future__ import annotations

import time
from typing import List, Optional

from ..models.report import NewsReport, ReportSection
from ..models.campaign import CampaignNews, campaign_key
from ..clustering.campaign_cluster import CampaignClusterer
from .base import BaseReportBuilder


class CampaignReportBuilder(BaseReportBuilder):
    report_type = "campaign"

    def _resolve(self, campaign: str, *, since: float = 0.0
                 ) -> Optional[CampaignNews]:
        stored = self.store.get_campaign(campaign_key(campaign))
        if stored is not None:
            return stored
        # build on the fly from the corpus
        articles = self.store.list_articles(since=since, limit=5000)
        for camp in CampaignClusterer(now=self.now).build(articles):
            if camp.name.lower() == campaign.lower():
                return camp
        return None

    def build(self, campaign: str, *, since: float = 0.0) -> NewsReport:
        camp = self._resolve(campaign, since=since)
        report = self._new_report(f"Campaign News Profile — {campaign}",
                                  subject=campaign)
        if camp is None:
            report.summary = "No multi-source campaign found for this name."
            report.add_section(ReportSection(
                title="Not found", lines=["The corpus holds no corroborated "
                                          "campaign matching this name."]))
            return report
        report.window_start = camp.first_reported
        report.window_end = camp.last_reported
        conf = camp.confidence or {}
        report.summary = (f"{camp.mention_count} articles, "
                          f"{camp.independent_report_count} independent sources. "
                          f"Confidence {conf.get('score', 0):.2f} "
                          f"({conf.get('band','n/a')}).")
        self._list(report, "Involved Threat Actors", camp.actor_names)
        self._list(report, "Malware", camp.malware_names)
        self._list(report, "CVEs", camp.cve_ids)
        self._list(report, "Targeted Countries", camp.targeted_countries)
        self._list(report, "MITRE ATT&CK Techniques", camp.mitre_techniques)
        self._list(report, "Reported Infrastructure (IOCs)", camp.iocs)

        conflicts = ReportSection(title="Differing Claims (recorded, not resolved)")
        if camp.differing_claims:
            for c in camp.differing_claims:
                conflicts.add_row({"Field": c.field,
                                   "Claim A": c.claim_a, "Source A": c.source_a,
                                   "Claim B": c.claim_b, "Source B": c.source_b})
        else:
            conflicts.add_line("No conflicting claims detected between sources.")
        report.add_section(conflicts)

        ev = ReportSection(title="Corroborating Sources / Evidence")
        ev.evidence = camp.evidence.to_list()[:25]
        report.add_section(ev)
        return report

    def _list(self, report, title, values):
        sec = ReportSection(title=title)
        for v in (values[:25] or ["None reported."]):
            sec.add_line(v)
        report.add_section(sec)


__all__ = ["CampaignReportBuilder"]
