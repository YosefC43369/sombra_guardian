"""
group_soc/prioritization/impact.py — impact modifiers from signal metadata.

Impact (blast radius) is not fully known at capture time; it is refined from what the
producing correlator/detector recorded — how many distinct actors, how large the
cluster, whether an indicator was watchlisted. These modifiers nudge the base impact
dimension up (never down) before priority is computed.
"""

from __future__ import annotations

from ..models.severity import clamp01


def impact_boost(metadata: dict) -> float:
    """Return an additive impact boost in [0, 0.5] derived from metadata."""
    if not metadata:
        return 0.0
    boost = 0.0
    distinct = metadata.get("distinct_actors") or metadata.get("distinct_types") or 0
    try:
        distinct = int(distinct)
    except (TypeError, ValueError):
        distinct = 0
    if distinct >= 2:
        boost += min(0.3, 0.05 * distinct)
    cluster = metadata.get("cluster_size") or 0
    try:
        cluster = int(cluster)
    except (TypeError, ValueError):
        cluster = 0
    if cluster >= 3:
        boost += min(0.2, 0.03 * cluster)
    if metadata.get("watchlisted"):
        boost += 0.15
    return clamp01(boost)


def apply_impact(base_impact: float, metadata: dict) -> float:
    return clamp01(base_impact + impact_boost(metadata))
