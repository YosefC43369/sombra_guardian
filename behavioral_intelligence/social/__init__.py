"""
behavioral_intelligence.social — public social-behaviour analysis.

Per-platform and per-account activity, account lifecycle and profile-change
tracking, directed mention and reply networks, observable interaction metrics
(frequency, reciprocity, response latency), community detection, and
platform-migration detection. Every metric derives from public metadata; no
relationship type (friendship, employment, association) is ever inferred.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from ..models.observation import Observation
from ..models.timeline import PlatformMigration
from .. import util
from . import (platform_activity, account_activity, mention_network,
               reply_network, interaction_patterns, community_analysis)
from .platform_activity import analyze_platforms, PlatformStat
from .account_activity import analyze_accounts, AccountLifecycle
from .mention_network import build_network as build_mention_network
from .reply_network import build_reply_network
from .interaction_patterns import analyze_interactions, InteractionPatterns
from .community_analysis import detect_communities, CommunityResult, HAVE_NETWORKX


def detect_migrations(observations: Sequence[Observation]) -> List[PlatformMigration]:
    """Detect activity shifting from one platform to another (spec §24): a
    platform whose activity tails off just as another's begins, with overlap and
    shared-link evidence. Descriptive only — a migration is a temporal pattern,
    not proof the accounts are the same person."""
    stats = {p.platform: p for p in analyze_platforms(observations)}
    if len(stats) < 2:
        return []
    # shared links per platform (for corroboration)
    links: Dict[str, set] = {}
    for o in observations:
        if o.platform:
            links.setdefault(o.platform, set()).update(o.all_domains())

    out: List[PlatformMigration] = []
    platforms = list(stats.values())
    for a in platforms:
        for b in platforms:
            if a.platform == b.platform or a.last_seen == 0 or b.first_seen == 0:
                continue
            # a declines before b rises: a.last_seen shortly after b.first_seen or
            # b starts near a's tail
            if b.first_seen >= a.first_seen and a.last_seen >= b.first_seen:
                overlap = (a.last_seen - b.first_seen) / util.DAY_SECONDS
                # only report when b clearly continues past a
                if b.last_seen > a.last_seen and 0 <= overlap <= 180:
                    shared = sorted(links.get(a.platform, set()) &
                                    links.get(b.platform, set()))
                    out.append(PlatformMigration(
                        from_platform=a.platform, to_platform=b.platform,
                        from_last_activity=a.last_seen, to_first_activity=b.first_seen,
                        overlap_days=max(overlap, 0.0),
                        shared_links=shared[:10],
                        shared_username=bool(set(a.accounts) & set(b.accounts))))
    out.sort(key=lambda m: m.overlap_days)
    return out


__all__ = [
    "platform_activity", "account_activity", "mention_network", "reply_network",
    "interaction_patterns", "community_analysis",
    "analyze_platforms", "PlatformStat", "analyze_accounts", "AccountLifecycle",
    "build_mention_network", "build_reply_network", "analyze_interactions",
    "InteractionPatterns", "detect_communities", "CommunityResult",
    "detect_migrations", "HAVE_NETWORKX",
]
