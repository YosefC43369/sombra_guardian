"""
behavioral_intelligence.providers — passive public-data providers.

Read-only collectors of PUBLIC data implementing the common provider contract
(health_check / collect / normalize / validate / rate_limit). Concrete providers:
RSS/Atom feeds and public ActivityPub outboxes. All are polite clients that honour
timeouts and per-host rate limits and never authenticate, bypass or brute-force
anything. ``httpx`` (via the repo's async_http stack) is optional — parsing is
testable offline by calling ``normalize`` on raw content.
"""

from .base import (BehaviorProvider, ObservationProvider, TimelineProvider,
                   LanguageProvider, TopicProvider, InteractionProvider,
                   ProviderResult, ProviderStatus)
from .rss import RSSProvider, HAVE_FEEDPARSER
from .activitypub import ActivityPubProvider

__all__ = [
    "BehaviorProvider", "ObservationProvider", "TimelineProvider",
    "LanguageProvider", "TopicProvider", "InteractionProvider",
    "ProviderResult", "ProviderStatus",
    "RSSProvider", "HAVE_FEEDPARSER", "ActivityPubProvider",
]
