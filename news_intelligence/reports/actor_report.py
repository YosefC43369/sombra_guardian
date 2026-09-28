"""
news_intelligence.reports.actor_report — the Threat Actor News Profile.

Builds an evidence-backed profile of one threat actor from the news corpus: reported
aliases (preserved separately, never merged), recent articles, campaign timeline,
associated malware, ATT&CK techniques, targeted sectors and countries, and the
evidence sources with a computed confidence. Every list traces to the articles behind
it; nothing is asserted beyond what the cited sources state.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import List, Optional

from ..models.report import NewsReport, ReportSection
from ..models.actor import ActorNews, normalize_actor_name
from ..models.entity import EntityType
from ..models.evidence import EvidenceBundle, EvidenceRef
from ..models.confidence import news_confidence
from ..extraction.reference import actor_aliases_for
from .base import BaseReportBuilder


class ActorReportBuilder(BaseReportBuilder):
    report_type = "actor"

    def build_profile(self, actor: str, *, since: float = 0.0) -> ActorNews:
        name = normalize_actor_name(actor)
        ids = self.store.articles_for_entity(
            value=name, entity_type=EntityType.THREAT_ACTOR.value, since=since)
        articles = [a for a in (self.store.get_article(i) for i in ids)
                    if a is not None and not a.duplicate_of]
        prof = ActorNews(name=name, aliases=actor_aliases_for(name))
        bundle = EvidenceBundle()
        malware, techniques, sectors, countries, campaigns, cves = (
            Counter() for _ in range(6))
        for a in articles:
            prof.article_ids.append(a.article_id)
            malware.update(a.malware_mentions)
            techniques.update(a.mitre_techniques)
            countries.update(a.country_mentions)
            cves.update(a.cve_mentions)
            for ev in a.evidence:
                bundle.add(EvidenceRef.from_dict(ev))
            # capture reported aliases from mention detail
            for m in a.entity_mentions:
                if m.entity_type == EntityType.THREAT_ACTOR:
                    canon = m.detail.get("canonical", "")
                    if canon and canon.lower() == name.lower() and \
                            m.value.lower() != name.lower():
                        prof.add_alias(m.value)
        prof.malware_names = [x for x, _ in malware.most_common()]
        prof.mitre_techniques = [x for x, _ in techniques.most_common()]
        prof.targeted_countries = [x for x, _ in countries.most_common()]
        prof.cve_ids = [x for x, _ in cves.most_common()]
        prof.mention_count = len(articles)
        prof.first_reported = min((a.publication_date for a in articles
                                   if a.publication_date), default=0.0)
        prof.last_reported = max((a.publication_date for a in articles), default=0.0)
        prof.evidence = bundle
        prof.confidence = news_confidence(bundle, now=self.now).to_dict()
        return prof

    def build(self, actor: str, *, since: float = 0.0) -> NewsReport:
        prof = self.build_profile(actor, since=since)
        report = self._new_report(f"Threat Actor News Profile — {prof.name}",
                                  subject=prof.name,
                                  window_start=prof.first_reported,
                                  window_end=prof.last_reported)
        conf = prof.confidence or {}
        report.summary = (f"{prof.mention_count} articles across "
                          f"{prof.independent_report_count} independent sources. "
                          f"Evidence confidence: {conf.get('score', 0):.2f} "
                          f"({conf.get('band', 'n/a')}).")
        alias_sec = ReportSection(title="Reported Aliases")
        if prof.aliases:
            alias_sec.add_line("Names reported by public sources for this activity "
                               "(tracked separately, not asserted as one identity):")
            for al in prof.aliases:
                alias_sec.add_line(al)
        else:
            alias_sec.add_line("No additional aliases in the corpus.")
        report.add_section(alias_sec)

        self._list_section(report, "Associated Malware", prof.malware_names)
        self._list_section(report, "MITRE ATT&CK Techniques", prof.mitre_techniques)
        self._list_section(report, "Targeted Countries", prof.targeted_countries)
        self._list_section(report, "Associated CVEs", prof.cve_ids)
        self._recent_articles(report, prof)
        self._evidence(report, prof)
        return report

    def _list_section(self, report, title, values):
        sec = ReportSection(title=title)
        if values:
            for v in values[:25]:
                sec.add_line(v)
        else:
            sec.add_line("None reported in corpus.")
        report.add_section(sec)

    def _recent_articles(self, report, prof):
        sec = ReportSection(title="Recent Articles")
        arts = sorted((self.store.get_article(i) for i in prof.article_ids),
                      key=lambda a: (a.publication_date if a else 0), reverse=True)
        for a in [x for x in arts if x][:15]:
            sec.add_row({"Date": time.strftime("%Y-%m-%d",
                         time.gmtime(a.publication_date)) if a.publication_date
                         else "—", "Source": a.source_name or a.source_domain,
                         "Title": a.title[:90]})
        report.add_section(sec)

    def _evidence(self, report, prof):
        sec = ReportSection(title="Evidence Sources")
        sec.evidence = prof.evidence.to_list()[:25]
        sec.add_line(f"{len(prof.evidence)} citations across "
                     f"{prof.independent_report_count} providers.")
        report.add_section(sec)


__all__ = ["ActorReportBuilder"]
