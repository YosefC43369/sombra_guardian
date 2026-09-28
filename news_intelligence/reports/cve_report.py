"""
news_intelligence.reports.cve_report — the CVE News Profile.

Aggregates all news for one CVE: publication timeline, reporting vendors, affected
products/vendors named, severity wording quoted verbatim (never re-scored), public
exploitation references (only where an article states them, or CISA KEV lists it), and
mitigations referenced. Backs the CVE News Profile deliverable.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Optional

from ..models.report import NewsReport, ReportSection
from ..models.cve import CVENews, normalize_cve
from ..models.entity import EntityType
from ..models.evidence import EvidenceBundle, EvidenceRef
from ..models.confidence import news_confidence
from .base import BaseReportBuilder


class CVEReportBuilder(BaseReportBuilder):
    report_type = "cve"

    def build_profile(self, cve: str, *, since: float = 0.0) -> CVENews:
        cid = normalize_cve(cve) or cve.upper()
        ids = self.store.articles_for_entity(
            value=cid, entity_type=EntityType.CVE.value, since=since)
        articles = [a for a in (self.store.get_article(i) for i in ids)
                    if a is not None and not a.duplicate_of]
        prof = CVENews(cve_id=cid)
        bundle = EvidenceBundle()
        vendors, products = Counter(), Counter()
        for a in articles:
            prof.article_ids.append(a.article_id)
            vendors.update([a.source_name or a.source_domain])
            products.update(a.detail.get("vendors", []) if isinstance(a.detail, dict)
                            else [])
            # exploitation signal — from CVE mention context or KEV article
            for m in a.entity_mentions:
                if m.entity_type == EntityType.CVE and m.value == cid:
                    if m.detail.get("exploit_context") or a.detail.get("kev"):
                        if a.article_id not in prof.exploited_references:
                            prof.exploited_references.append(a.article_id)
                    if m.detail.get("patch_context"):
                        if a.article_id not in prof.mitigation_references:
                            prof.mitigation_references.append(a.article_id)
            sq = a.detail.get("severity_quote") if isinstance(a.detail, dict) else ""
            if sq and sq not in prof.severity_quotes:
                prof.severity_quotes.append(sq)
            for ev in a.evidence:
                bundle.add(EvidenceRef.from_dict(ev))
        prof.vendors = [v for v, _ in vendors.most_common()]
        prof.affected_products = [p for p, _ in products.most_common()]
        prof.mention_count = len(articles)
        prof.first_reported = min((a.publication_date for a in articles
                                   if a.publication_date), default=0.0)
        prof.last_reported = max((a.publication_date for a in articles), default=0.0)
        prof.evidence = bundle
        prof.confidence = news_confidence(bundle, now=self.now).to_dict()
        return prof

    def build(self, cve: str, *, since: float = 0.0) -> NewsReport:
        prof = self.build_profile(cve, since=since)
        report = self._new_report(f"CVE News Profile — {prof.cve_id}",
                                  subject=prof.cve_id,
                                  window_start=prof.first_reported,
                                  window_end=prof.last_reported)
        exploited = "YES (per cited public reporting)" if prof.known_exploited \
            else "not asserted by any source in corpus"
        report.summary = (f"{prof.mention_count} articles, "
                          f"{prof.independent_report_count} independent sources. "
                          f"Publicly-reported exploitation: {exploited}.")
        pub = ReportSection(title="Publication Timeline")
        arts = sorted((self.store.get_article(i) for i in prof.article_ids),
                      key=lambda a: a.publication_date if a else 0)
        for a in [x for x in arts if x]:
            pub.add_row({"Date": time.strftime("%Y-%m-%d",
                         time.gmtime(a.publication_date)) if a.publication_date
                         else "—", "Source": a.source_name or a.source_domain,
                         "Title": a.title[:90]})
        report.add_section(pub)
        self._list(report, "Reporting Vendors", prof.vendors)
        self._list(report, "Affected Products / Vendors (as named)",
                   prof.affected_products)
        sev = ReportSection(title="Severity References (verbatim)")
        for q in prof.severity_quotes or ["No severity wording captured."]:
            sev.add_line(q)
        report.add_section(sev)
        ex = ReportSection(title="Known Exploitation References")
        if prof.exploited_references:
            ex.add_line("Articles asserting exploitation (publisher's claim):")
            for aid in prof.exploited_references:
                a = self.store.get_article(aid)
                if a:
                    ex.add_line(f"{a.source_name or a.source_domain}: {a.title[:90]}")
        else:
            ex.add_line("No source in the corpus asserts exploitation.")
        report.add_section(ex)
        ev = ReportSection(title="Evidence Sources")
        ev.evidence = prof.evidence.to_list()[:25]
        report.add_section(ev)
        return report

    def _list(self, report, title, values):
        sec = ReportSection(title=title)
        for v in (values[:25] or ["None in corpus."]):
            sec.add_line(v)
        report.add_section(sec)


__all__ = ["CVEReportBuilder"]
