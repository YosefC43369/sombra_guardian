"""
threat_actor_intelligence.timeline.campaign_timeline — campaign activity timeline.

Chronology of a campaign: first/last observed, each corroborating report's
publication, and dated IOC first-seen markers (activity spikes) drawn from the
campaign's linked IOCs. The per-report events make "which sources corroborate
this campaign, and when" legible on one axis.
"""

from __future__ import annotations

from typing import List, Optional

from ..models.campaign import Campaign
from ..models.ioc import IOC
from .base import Timeline, TimelineEvent


class CampaignTimelineBuilder:
    def build(self, campaign: Campaign, *,
              iocs: Optional[List[IOC]] = None) -> Timeline:
        tl = Timeline(subject_type="campaign", subject_id=campaign.campaign_id)
        if campaign.first_observed:
            tl.add(TimelineEvent(at=campaign.first_observed, kind="first_observed",
                                 label=f"{campaign.campaign_name} first observed",
                                 sources=campaign.evidence.providers()))
        if campaign.last_observed and campaign.last_observed != campaign.first_observed:
            tl.add(TimelineEvent(at=campaign.last_observed, kind="last_observed",
                                 label=f"{campaign.campaign_name} last active",
                                 sources=campaign.evidence.providers()))
        for ref in campaign.evidence.refs:
            if ref.observed_at:
                tl.add(TimelineEvent(
                    at=ref.observed_at, kind="reported",
                    label=f"Reported by {ref.provider}: {ref.title}"[:120],
                    detail={"url": ref.source_url}, sources=[ref.provider]))
        for ioc in (iocs or []):
            if ioc.id not in campaign.iocs:
                continue
            if ioc.first_seen:
                tl.add(TimelineEvent(
                    at=ioc.first_seen, kind="ioc_observed",
                    label=f"IOC observed: {ioc.defanged()}"[:120],
                    detail={"ioc_id": ioc.id, "type": ioc.ioc_type.value},
                    sources=ioc.evidence.providers()))
        return tl


__all__ = ["CampaignTimelineBuilder"]
