"""
news_intelligence.timeline._specific — subject-specific timeline builders.

Thin specializations of ``NewsTimelineBuilder`` for the actor, campaign, CVE and
malware subjects. Each resolves its subject to the entity value/type and builds an
evidence-dated chronology. Kept in one module and re-exported by the per-subject
modules the package layout names, to avoid four near-identical files drifting apart.
"""

from __future__ import annotations

from typing import Optional

from ..models.entity import EntityType
from ..models.actor import normalize_actor_name
from ..models.malware import normalize_malware_name
from ..models.cve import normalize_cve
from ..models.campaign import normalize_campaign_name
from .base import Timeline
from .news_timeline import NewsTimelineBuilder


class ActorTimelineBuilder(NewsTimelineBuilder):
    subject_type = "actor"

    def build(self, actor: str, *, since: float = 0.0) -> Timeline:
        return self.build_for_value(normalize_actor_name(actor),
                                    entity_type=EntityType.THREAT_ACTOR.value,
                                    since=since)


class MalwareTimelineBuilder(NewsTimelineBuilder):
    subject_type = "malware"

    def build(self, family: str, *, since: float = 0.0) -> Timeline:
        return self.build_for_value(normalize_malware_name(family),
                                    entity_type=EntityType.MALWARE_FAMILY.value,
                                    since=since)


class CVETimelineBuilder(NewsTimelineBuilder):
    subject_type = "cve"

    def build(self, cve: str, *, since: float = 0.0) -> Timeline:
        return self.build_for_value(normalize_cve(cve) or cve.upper(),
                                    entity_type=EntityType.CVE.value, since=since)


class CampaignTimelineBuilder(NewsTimelineBuilder):
    subject_type = "campaign"

    def build(self, campaign: str, *, since: float = 0.0) -> Timeline:
        # campaigns are aggregates, not single entity values — build from the
        # stored campaign's article ids when present, else from name mentions.
        from ..models.campaign import campaign_key
        camp = self.store.get_campaign(campaign_key(campaign))
        if camp is not None:
            tl = Timeline(subject=camp.name, subject_type=self.subject_type)
            for aid in camp.article_ids:
                a = self.store.get_article(aid)
                if a is not None:
                    tl.add(self._entry(a, f"{camp.name} reported"))
            return tl
        return self.build_for_value(normalize_campaign_name(campaign),
                                    since=since)


__all__ = ["ActorTimelineBuilder", "MalwareTimelineBuilder", "CVETimelineBuilder",
           "CampaignTimelineBuilder"]
