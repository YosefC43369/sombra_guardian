"""
news_intelligence.correlation.campaign_correlation — campaign-level correlation.

Wraps the campaign clustering into evidence-backed relationships: which actors,
malware families and CVEs a campaign is reported to involve, and which articles
corroborate it. Preserves independent sources and surfaces the campaign's differing
claims (contradictions) unchanged.
"""

from __future__ import annotations

from typing import List, Optional

from ..models.article import Article
from ..models.campaign import CampaignNews, campaign_key
from ..clustering.campaign_cluster import CampaignClusterer
from .base import BaseCorrelator, NewsRelationship


class CampaignCorrelator(BaseCorrelator):
    name = "campaign"

    def correlate(self, articles: List[Article]) -> List[NewsRelationship]:
        clusterer = CampaignClusterer(now=self.now)
        campaigns = clusterer.build(articles)
        rels: List[NewsRelationship] = []
        for camp in campaigns:
            ck = camp.key
            score = (camp.confidence or {}).get("score", 0.0)
            for actor in camp.actor_names:
                rels.append(self._rel(ck, camp, "actor", f"act:{actor.lower()}",
                                      "campaign_involves_actor", actor, score))
            for mal in camp.malware_names:
                rels.append(self._rel(ck, camp, "malware", f"mal:{mal.lower()}",
                                      "campaign_uses_malware", mal, score))
            for cve in camp.cve_ids:
                rels.append(self._rel(ck, camp, "cve", f"cve:{cve.lower()}",
                                      "campaign_exploits_cve", cve, score))
        return [r for r in rels if r.weight >= self.min_confidence]

    def _rel(self, ck, camp, dst_type, dst_key, rel_type, value, score
             ) -> NewsRelationship:
        return NewsRelationship(
            src_type="campaign", src_key=ck, dst_type=dst_type, dst_key=dst_key,
            rel_type=rel_type,
            signals=[f"{camp.independent_report_count} independent reports"],
            article_ids=list(camp.article_ids),
            source_domains=[],
            weight=round(float(score), 4), confidence=camp.confidence,
            detail={"campaign": camp.name, "value": value,
                    "differing_claims": [c.to_dict() for c in camp.differing_claims]})

    def build_campaigns(self, articles: List[Article]) -> List[CampaignNews]:
        return CampaignClusterer(now=self.now).build(articles)


__all__ = ["CampaignCorrelator"]
