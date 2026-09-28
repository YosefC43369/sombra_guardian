"""
news_intelligence.timeline — evidence-dated chronologies.

Every timeline entry is anchored to the article that dates it; the engine never
invents a date. New-vs-historical is a pure function of the timestamp.
"""
from .base import Timeline, TimelineEntry, BaseTimelineBuilder
from .news_timeline import NewsTimelineBuilder
from .actor_timeline import ActorTimelineBuilder
from .campaign_timeline import CampaignTimelineBuilder
from .cve_timeline import CVETimelineBuilder
from .malware_timeline import MalwareTimelineBuilder

__all__ = ["Timeline", "TimelineEntry", "BaseTimelineBuilder",
           "NewsTimelineBuilder", "ActorTimelineBuilder", "CampaignTimelineBuilder",
           "CVETimelineBuilder", "MalwareTimelineBuilder"]
