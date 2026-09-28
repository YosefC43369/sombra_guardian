"""
news_intelligence.correlation.report_correlation — source corroboration engine.

Measures *independent* corroboration for a subject (an event, a campaign, a CVE) and
classifies each contributing article's role (spec SOURCE CORROBORATION ENGINE):
  * original      — earliest, primary reporting;
  * independent   — a distinct outlet reporting with its own added detail;
  * syndicated    — a wire/reprint sharing near-identical text (marked duplicate);
  * mirror        — same domain family / aggregator copy;
  * research_summary — a later write-up summarizing prior reporting.

Corroboration strength counts *distinct originating domains only*, so ten copies of
one wire story count once — the discipline the news standing-limitations demand.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from ..models.article import Article
from ..models.evidence import EvidenceBundle, EvidenceRef
from ..models.confidence import news_confidence


def _reliability_rank(source_class: str) -> int:
    return {"government": 0, "standards": 0, "vendor": 1, "research": 2,
            "community": 3, "aggregator": 4, "feed": 5}.get(source_class, 6)


class CorroborationResult:
    def __init__(self) -> None:
        self.original: Optional[str] = None
        self.independent: List[str] = []
        self.syndicated: List[str] = []
        self.mirror: List[str] = []
        self.research_summary: List[str] = []
        self.independent_domains: List[str] = []
        self.confidence: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "original": self.original, "independent": self.independent,
            "syndicated": self.syndicated, "mirror": self.mirror,
            "research_summary": self.research_summary,
            "independent_domains": self.independent_domains,
            "independent_source_count": len(set(self.independent_domains)),
            "confidence": self.confidence,
        }


class ReportCorrelator:
    def __init__(self, *, now: Optional[float] = None):
        import time
        self.now = now or time.time()

    def corroboration(self, articles: List[Article]) -> CorroborationResult:
        res = CorroborationResult()
        if not articles:
            return res
        # earliest, most reliable = original
        ordered = sorted(articles, key=lambda a: (
            a.publication_date or float("inf"),
            _reliability_rank(a.source_class.value)))
        original = ordered[0]
        res.original = original.article_id
        seen_domains = {original.source_domain}
        bundle = EvidenceBundle()
        for ev in original.evidence:
            bundle.add(EvidenceRef.from_dict(ev))
        res.independent_domains.append(original.source_domain)

        for a in ordered[1:]:
            role = self._classify(a, original, seen_domains)
            getattr(res, role).append(a.article_id)
            if role == "independent":
                res.independent_domains.append(a.source_domain)
                seen_domains.add(a.source_domain)
                for ev in a.evidence:
                    bundle.add(EvidenceRef.from_dict(ev))
        res.confidence = news_confidence(bundle, now=self.now).to_dict()
        return res

    def _classify(self, a: Article, original: Article, seen: set) -> str:
        if a.duplicate_of:
            return "syndicated"
        if a.source_domain and a.source_domain in seen:
            return "mirror"
        if "research" in a.source_class.value or "summary" in " ".join(a.tags):
            # later research write-up
            if (a.publication_date or 0) > (original.publication_date or 0) + 86400 * 2:
                return "research_summary"
        return "independent"

    def score_subject(self, articles: List[Article]) -> float:
        return (self.corroboration(articles).confidence or {}).get("score", 0.0)


__all__ = ["ReportCorrelator", "CorroborationResult"]
