"""
news_intelligence.correlation.topic_correlation — topic co-occurrence + vendor overlap.

Two related analyses:
  * topic co-occurrence — which topics (salient entities) are discussed together
    across the corpus, evidence-gated like the entity correlator;
  * vendor comparison — for a given subject (actor/malware/CVE), which vendors reported
    it, how their timing compares, and which observations (IOCs, techniques) are shared
    vs. unique. Answers "which campaigns are being discussed across multiple vendors?"
    and underpins the vendor-comparison report.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from ..models.article import Article
from ..models.evidence import EvidenceBundle, EvidenceRef
from .base import BaseCorrelator, NewsRelationship


class TopicCorrelator(BaseCorrelator):
    name = "topic"

    def _salient(self, a: Article) -> List[str]:
        return sorted(set(a.actor_mentions + a.malware_mentions + a.cve_mentions))

    def co_occurrence(self, articles: List[Article], *, min_articles: int = 2
                      ) -> List[NewsRelationship]:
        articles = [a for a in articles if not a.duplicate_of]
        pair_articles: Dict[tuple, List[Article]] = defaultdict(list)
        for a in articles:
            terms = self._salient(a)
            for i in range(len(terms)):
                for j in range(i + 1, len(terms)):
                    key = tuple(sorted([terms[i].lower(), terms[j].lower()]))
                    pair_articles[key].append(a)
        rels: List[NewsRelationship] = []
        for (x, y), arts in pair_articles.items():
            if len(arts) < min_articles:
                continue
            bundle = EvidenceBundle()
            for a in arts:
                for ev in a.evidence:
                    bundle.add(EvidenceRef.from_dict(ev))
            conf = self._score(bundle)
            if conf.score < self.min_confidence:
                continue
            rels.append(NewsRelationship(
                src_type="topic", src_key=f"topic:{x}", dst_type="topic",
                dst_key=f"topic:{y}", rel_type="discussed_together",
                signals=[f"co-discussed x{len(arts)}"],
                article_ids=[a.article_id for a in arts],
                source_domains=[a.source_domain for a in arts],
                weight=round(conf.score, 4), confidence=conf.to_dict()))
        rels.sort(key=lambda r: r.weight, reverse=True)
        return rels

    def vendor_comparison(self, articles: List[Article], subject: str
                          ) -> Dict[str, object]:
        """Compare how vendors/outlets reported one subject (actor/malware/CVE)."""
        subj = subject.lower()
        matching = [a for a in articles if not a.duplicate_of and subj in
                    {x.lower() for x in (a.actor_mentions + a.malware_mentions
                                         + a.cve_mentions)}]
        by_vendor: Dict[str, Dict[str, object]] = {}
        for a in matching:
            v = a.source_name or a.source_domain
            rec = by_vendor.setdefault(v, {
                "vendor": v, "domain": a.source_domain, "articles": [],
                "first_published": a.publication_date or 0.0,
                "iocs": set(), "techniques": set(), "cves": set()})
            rec["articles"].append(a.article_id)
            rec["first_published"] = min(rec["first_published"] or a.publication_date,
                                         a.publication_date or rec["first_published"])
            rec["iocs"].update(a.iocs)
            rec["techniques"].update(a.mitre_techniques)
            rec["cves"].update(a.cve_mentions)

        vendors = list(by_vendor.values())
        all_iocs = set().union(*[v["iocs"] for v in vendors]) if vendors else set()
        shared_iocs = (set.intersection(*[v["iocs"] for v in vendors])
                       if len(vendors) > 1 and all(v["iocs"] for v in vendors)
                       else set())
        for v in vendors:
            v["unique_iocs"] = sorted(v["iocs"] - shared_iocs)
            v["iocs"] = sorted(v["iocs"])
            v["techniques"] = sorted(v["techniques"])
            v["cves"] = sorted(v["cves"])
        vendors.sort(key=lambda v: v["first_published"] or float("inf"))
        return {
            "subject": subject, "vendor_count": len(vendors),
            "vendors": vendors, "shared_iocs": sorted(shared_iocs),
            "total_articles": len(matching),
            "first_reported_by": vendors[0]["vendor"] if vendors else "",
        }


__all__ = ["TopicCorrelator"]
