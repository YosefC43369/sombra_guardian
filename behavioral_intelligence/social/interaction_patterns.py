"""
behavioral_intelligence.social.interaction_patterns — observable interaction
metrics (spec §20).

Computes interaction frequency, reciprocity, response latency (time between a
post and the reply to it, when both are observed), conversation depth, and
repeated-interaction counts, per platform. All derived from public metadata; the
engine does not infer private relationships from any of it.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..models.observation import Observation
from .. import util
from . import mention_network


@dataclass
class InteractionPatterns:
    total_interactions: int = 0
    interactions_per_day: float = 0.0
    reciprocity: float = 0.0
    mean_response_latency_seconds: Optional[float] = None
    median_response_latency_seconds: Optional[float] = None
    repeated_partners: int = 0            # partners interacted with >1 time
    top_partners: List[Dict[str, object]] = field(default_factory=list)
    per_platform: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_interactions": self.total_interactions,
            "interactions_per_day": round(self.interactions_per_day, 3),
            "reciprocity": round(self.reciprocity, 3),
            "mean_response_latency_seconds": (
                round(self.mean_response_latency_seconds, 1)
                if self.mean_response_latency_seconds is not None else None),
            "median_response_latency_seconds": (
                round(self.median_response_latency_seconds, 1)
                if self.median_response_latency_seconds is not None else None),
            "repeated_partners": self.repeated_partners,
            "top_partners": self.top_partners,
            "per_platform": self.per_platform,
        }


def analyze_interactions(observations: Sequence[Observation]) -> InteractionPatterns:
    edges = (mention_network.build_edges(observations, kind="mention") +
             mention_network.build_edges(observations, kind="reply"))
    result = InteractionPatterns()
    if not edges:
        return result

    # merge mention+reply edges by (source,target)
    merged: Dict[tuple, int] = defaultdict(int)
    per_platform: Counter = Counter()
    for e in edges:
        merged[(e.source, e.target)] += e.count
        for p in e.platforms:
            per_platform[p] += e.count

    result.total_interactions = sum(merged.values())
    result.repeated_partners = sum(1 for v in merged.values() if v > 1)
    result.per_platform = dict(per_platform)

    present = set(merged)
    mutual = sum(1 for (a, b) in present if (b, a) in present)
    result.reciprocity = util.safe_div(mutual, len(present))

    top = sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:10]
    result.top_partners = [{"source": s, "target": t, "count": c}
                           for (s, t), c in top]

    # response latency: for reply observations, gap to the post being replied to
    id_index: Dict[str, Observation] = {o.observation_id: o for o in observations}
    latencies: List[float] = []
    for o in observations:
        if o.in_reply_to and o.in_reply_to in id_index and o.has_time:
            parent = id_index[o.in_reply_to]
            if parent.has_time and o.timestamp >= parent.timestamp:
                latencies.append(o.timestamp - parent.timestamp)
    if latencies:
        result.mean_response_latency_seconds = util.mean(latencies)
        result.median_response_latency_seconds = util.median(latencies)

    # frequency per day over observed span
    timed = [o.timestamp for o in observations if o.has_time]
    if len(timed) >= 2:
        span_days = (max(timed) - min(timed)) / util.DAY_SECONDS
        result.interactions_per_day = util.safe_div(result.total_interactions,
                                                    max(span_days, 1.0))
    return result
