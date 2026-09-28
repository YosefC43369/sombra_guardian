"""
news_intelligence.correlation.infrastructure_correlation — shared-IOC correlation.

Finds infrastructure indicators (domains, IPs, ASNs, URLs, hashes) that appear across
*unrelated* news sources — the "which infrastructure indicators appear across unrelated
news sources?" question. Cross-source appearance is the strongest corroboration signal
for an indicator, so each result carries the distinct source-domain count and the
articles that reported it. Reference-only: no indicator is contacted.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from ..models.article import Article
from ..models.entity import EntityType, IOC_ENTITY_TYPES
from ..models.evidence import EvidenceBundle, EvidenceRef
from .base import BaseCorrelator, NewsRelationship


class InfrastructureCorrelator(BaseCorrelator):
    name = "infrastructure"

    def cross_source_iocs(self, articles: List[Article], *, min_domains: int = 2
                          ) -> List[Dict[str, object]]:
        """IOC values reported by >= min_domains distinct source domains."""
        articles = [a for a in articles if not a.duplicate_of]
        by_ioc: Dict[str, Dict[str, object]] = {}
        for a in articles:
            for m in a.entity_mentions:
                if m.entity_type not in IOC_ENTITY_TYPES:
                    continue
                rec = by_ioc.setdefault(m.value.lower(), {
                    "value": m.value, "type": m.entity_type.value,
                    "domains": set(), "articles": [], "bundle": EvidenceBundle()})
                rec["domains"].add(a.source_domain)
                rec["articles"].append(a.article_id)
                for ev in a.evidence:
                    rec["bundle"].add(EvidenceRef.from_dict(ev))
        out: List[Dict[str, object]] = []
        for rec in by_ioc.values():
            if len(rec["domains"]) < min_domains:
                continue
            conf = self._score(rec["bundle"])
            out.append({
                "value": rec["value"], "type": rec["type"],
                "source_domains": sorted(rec["domains"]),
                "independent_sources": len(rec["domains"]),
                "articles": rec["articles"], "confidence": conf.to_dict()})
        out.sort(key=lambda r: r["independent_sources"], reverse=True)
        return out

    def correlate(self, articles: List[Article], *, min_domains: int = 2
                  ) -> List[NewsRelationship]:
        """Relationships linking each cross-source IOC to the articles reporting it."""
        rels: List[NewsRelationship] = []
        for rec in self.cross_source_iocs(articles, min_domains=min_domains):
            ioc_key = f"ioc:{rec['value'].lower()}"
            rels.append(NewsRelationship(
                src_type="ioc", src_key=ioc_key, dst_type="corpus",
                dst_key="cross-source", rel_type="cross_source_infrastructure",
                signals=[f"{rec['independent_sources']} independent sources"],
                article_ids=list(rec["articles"]),
                source_domains=list(rec["source_domains"]),
                weight=float(rec["confidence"]["score"]),
                confidence=rec["confidence"],
                detail={"value": rec["value"], "type": rec["type"]}))
        return rels


__all__ = ["InfrastructureCorrelator"]
