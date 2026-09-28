"""
threat_actor_intelligence.timeline.activity_timeline — actor activity timeline.

Builds the chronological activity picture for a ThreatActor from the evidence and
references it carries: first/last observed, each supporting report's publication
(a "reported" event), and the campaigns/malware attributed to it as dated markers
where the evidence supplies a date. Every event is dated from evidence — nothing
is interpolated.
"""

from __future__ import annotations

from typing import List, Optional

from ..models.threat_actor import ThreatActor
from ..models.campaign import Campaign
from .base import Timeline, TimelineEvent


class ActivityTimelineBuilder:
    def build(self, actor: ThreatActor, *,
              campaigns: Optional[List[Campaign]] = None) -> Timeline:
        tl = Timeline(subject_type="actor", subject_id=actor.actor_id)
        if actor.first_seen:
            tl.add(TimelineEvent(at=actor.first_seen, kind="first_observed",
                                 label=f"{actor.canonical_name} first observed",
                                 sources=actor.evidence.providers()))
        if actor.last_seen and actor.last_seen != actor.first_seen:
            tl.add(TimelineEvent(at=actor.last_seen, kind="last_observed",
                                 label=f"{actor.canonical_name} latest observed activity",
                                 sources=actor.evidence.providers()))
        for ref in actor.evidence.refs:
            if ref.observed_at:
                tl.add(TimelineEvent(
                    at=ref.observed_at, kind="reported",
                    label=f"Reported by {ref.provider}: {ref.title}"[:120],
                    detail={"url": ref.source_url, "provider": ref.provider},
                    sources=[ref.provider]))
        for camp in (campaigns or []):
            if camp.campaign_id not in actor.campaigns:
                continue
            if camp.first_observed:
                tl.add(TimelineEvent(
                    at=camp.first_observed, kind="campaign_start",
                    label=f"Campaign begins: {camp.campaign_name}",
                    detail={"campaign_id": camp.campaign_id},
                    sources=camp.evidence.providers()))
            if camp.last_observed and camp.last_observed != camp.first_observed:
                tl.add(TimelineEvent(
                    at=camp.last_observed, kind="campaign_end",
                    label=f"Campaign last active: {camp.campaign_name}",
                    detail={"campaign_id": camp.campaign_id},
                    sources=camp.evidence.providers()))
        return tl


__all__ = ["ActivityTimelineBuilder"]
