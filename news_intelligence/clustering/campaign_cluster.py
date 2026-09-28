"""
news_intelligence.clustering.campaign_cluster — merge reports about one campaign.

Builds ``CampaignNews`` aggregates by grouping articles that name the same campaign
(or that share an actor+malware+CVE fingerprint strong enough to be one campaign),
while:
  * preserving every independent source (corroboration is counted across distinct
    originating domains, never across syndicated copies);
  * tracking differing claims between sources (attribution, dates) as
    ``DifferingClaim`` records — recorded, never auto-resolved.

A campaign named explicitly in an article's tags/detail seeds a cluster; otherwise a
fingerprint of (top actor, top malware, top CVE) groups related coverage.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional

from ..models.article import Article
from ..models.campaign import CampaignNews, DifferingClaim, normalize_campaign_name
from ..models.evidence import EvidenceBundle, EvidenceRef
from ..models.confidence import news_confidence


class CampaignClusterer:
    def __init__(self, *, now: Optional[float] = None):
        self.now = now or time.time()

    def _fingerprint(self, a: Article) -> Optional[str]:
        actor = a.actor_mentions[0].lower() if a.actor_mentions else ""
        malware = a.malware_mentions[0].lower() if a.malware_mentions else ""
        cve = a.cve_mentions[0] if a.cve_mentions else ""
        parts = [p for p in (actor, malware, cve) if p]
        if len(parts) >= 2:
            return "+".join(parts)
        return None

    def build(self, articles: List[Article]) -> List[CampaignNews]:
        articles = [a for a in articles if not a.duplicate_of]
        buckets: Dict[str, List[Article]] = defaultdict(list)
        names: Dict[str, str] = {}

        for a in articles:
            # explicit campaign name (from tags/detail) takes priority
            explicit = a.detail.get("campaign") if isinstance(a.detail, dict) else None
            if explicit:
                key = normalize_campaign_name(explicit).lower()
                names[key] = normalize_campaign_name(explicit)
                buckets[key].append(a)
                continue
            fp = self._fingerprint(a)
            if fp:
                buckets[fp].append(a)
                names.setdefault(fp, self._label(a, fp))

        campaigns: List[CampaignNews] = []
        for key, arts in buckets.items():
            if len(arts) < 2:
                continue
            campaigns.append(self._assemble(names.get(key, key), arts))
        campaigns.sort(key=lambda c: c.independent_report_count, reverse=True)
        return campaigns

    def _label(self, a: Article, fp: str) -> str:
        if a.actor_mentions and a.malware_mentions:
            return f"{a.actor_mentions[0]} / {a.malware_mentions[0]} activity"
        return fp

    def _assemble(self, name: str, arts: List[Article]) -> CampaignNews:
        camp = CampaignNews(name=name)
        bundle = EvidenceBundle()
        for a in arts:
            camp.article_ids.append(a.article_id)
            camp.actor_names = sorted(set(camp.actor_names) | set(a.actor_mentions))
            camp.malware_names = sorted(set(camp.malware_names)
                                        | set(a.malware_mentions))
            camp.cve_ids = sorted(set(camp.cve_ids) | set(a.cve_mentions))
            camp.targeted_countries = sorted(set(camp.targeted_countries)
                                             | set(a.country_mentions))
            camp.mitre_techniques = sorted(set(camp.mitre_techniques)
                                           | set(a.mitre_techniques))
            camp.iocs = sorted(set(camp.iocs) | set(a.iocs))
            for ev in a.evidence:
                bundle.add(EvidenceRef.from_dict(ev))
        camp.evidence = bundle
        camp.mention_count = len(arts)
        camp.first_reported = min((a.publication_date for a in arts
                                   if a.publication_date), default=0.0)
        camp.last_reported = max((a.publication_date for a in arts), default=0.0)
        camp.differing_claims = self._detect_conflicts(arts)
        camp.confidence = news_confidence(bundle, now=self.now).to_dict()
        return camp

    def _detect_conflicts(self, arts: List[Article]) -> List[DifferingClaim]:
        """Record attribution disagreements: different actors named by different
        sources for the same campaign fingerprint."""
        by_actor: Dict[str, str] = {}
        conflicts: List[DifferingClaim] = []
        for a in arts:
            if not a.actor_mentions:
                continue
            actor = a.actor_mentions[0]
            src = a.source_domain or a.source_name
            for other_actor, other_src in list(by_actor.items()):
                if other_actor.lower() != actor.lower() and other_src != src:
                    conflicts.append(DifferingClaim(
                        field="attribution", claim_a=other_actor, source_a=other_src,
                        claim_b=actor, source_b=src))
            by_actor[actor] = src
        # dedupe symmetric pairs
        seen = set()
        uniq: List[DifferingClaim] = []
        for c in conflicts:
            key = tuple(sorted([c.claim_a.lower(), c.claim_b.lower()]))
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        return uniq


__all__ = ["CampaignClusterer"]
