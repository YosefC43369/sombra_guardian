"""
news_intelligence.correlation.article_correlation — article-to-article correlation.

Links two articles that share meaningful signals (entities, IOCs, malware, ATT&CK,
CVEs, campaigns, organizations, countries), returning evidence-backed relationships
with the shared signals attached. This is the backbone of "which reports corroborate
each other" and "which reports relate to this one".
"""

from __future__ import annotations

from itertools import combinations
from typing import Dict, List, Optional, Set

from ..models.article import Article
from ..models.evidence import EvidenceBundle, EvidenceRef
from .base import BaseCorrelator, NewsRelationship

# weight per shared-signal class (typed signals beat shared common words)
_SIGNAL_WEIGHT = {"cve": 1.0, "ioc": 1.0, "actor": 0.9, "malware": 0.9,
                  "technique": 0.7, "org": 0.5, "country": 0.3}


class ArticleCorrelator(BaseCorrelator):
    name = "article"

    def _signals(self, a: Article) -> Set[str]:
        s: Set[str] = set()
        s |= {f"cve:{x}" for x in a.cve_mentions}
        s |= {f"ioc:{x}" for x in a.iocs}
        s |= {f"actor:{x.lower()}" for x in a.actor_mentions}
        s |= {f"malware:{x.lower()}" for x in a.malware_mentions}
        s |= {f"technique:{x}" for x in a.mitre_techniques}
        s |= {f"org:{x.lower()}" for x in a.organization_mentions}
        s |= {f"country:{x.lower()}" for x in a.country_mentions}
        return s

    def _signal_score(self, shared: Set[str]) -> float:
        return sum(_SIGNAL_WEIGHT.get(sig.split(":", 1)[0], 0.2) for sig in shared)

    def correlate(self, articles: List[Article], *, min_shared: float = 1.0
                  ) -> List[NewsRelationship]:
        articles = [a for a in articles if not a.duplicate_of]
        sigs = {a.article_id: self._signals(a) for a in articles}
        by_id = {a.article_id: a for a in articles}
        rels: List[NewsRelationship] = []
        for a, b in combinations(articles, 2):
            shared = sigs[a.article_id] & sigs[b.article_id]
            if not shared:
                continue
            score = self._signal_score(shared)
            if score < min_shared:
                continue
            bundle = EvidenceBundle()
            for art in (a, b):
                for ev in art.evidence:
                    bundle.add(EvidenceRef.from_dict(ev))
            conf = self._score(bundle)
            independent = (a.source_domain != b.source_domain)
            rels.append(NewsRelationship(
                src_type="article", src_key=a.article_id,
                dst_type="article", dst_key=b.article_id,
                rel_type="corroborates" if independent else "related",
                signals=sorted(shared),
                article_ids=[a.article_id, b.article_id],
                source_domains=[a.source_domain, b.source_domain],
                weight=round(min(1.0, score / 3.0) * conf.score, 4),
                confidence=conf.to_dict(),
                detail={"shared_signal_score": round(score, 3),
                        "independent": independent}))
        rels.sort(key=lambda r: r.weight, reverse=True)
        return rels

    def related_to(self, article_id: str, articles: List[Article], *, top: int = 10
                   ) -> List[NewsRelationship]:
        rels = self.correlate(articles)
        hits = [r for r in rels if article_id in (r.src_key, r.dst_key)]
        return hits[:top]


__all__ = ["ArticleCorrelator"]
