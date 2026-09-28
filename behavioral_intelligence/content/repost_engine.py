"""
behavioral_intelligence.content.repost_engine — public conversation-structure
analysis (spec §18).

Classifies observations by their structural role (original / reply / repost /
quote / comment / thread), computes the mix, and detects cross-posts: identical
or near-identical content appearing on more than one platform. Cross-post
detection reuses the content-reuse fingerprints so the same content republished
elsewhere is grouped, with the temporal distance recorded.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation, ContentType


@dataclass
class RepostAnalysis:
    counts: Dict[str, int] = field(default_factory=dict)
    shares: Dict[str, float] = field(default_factory=dict)
    original_ratio: float = 0.0
    repost_ratio: float = 0.0
    reply_ratio: float = 0.0
    cross_posts: List[Dict[str, object]] = field(default_factory=list)
    sample_size: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "counts": self.counts,
            "shares": {k: round(v, 3) for k, v in self.shares.items()},
            "original_ratio": round(self.original_ratio, 3),
            "repost_ratio": round(self.repost_ratio, 3),
            "reply_ratio": round(self.reply_ratio, 3),
            "cross_posts": self.cross_posts,
            "sample_size": self.sample_size,
        }


_ORIGINAL = {ContentType.POST, ContentType.ARTICLE, ContentType.MEDIA,
             ContentType.THREAD}
_REPOST = {ContentType.REPOST, ContentType.QUOTE}
_REPLY = {ContentType.REPLY, ContentType.COMMENT}


def analyze_reposts(observations: Sequence[Observation]) -> RepostAnalysis:
    counts: Counter = Counter()
    for o in observations:
        counts[o.content_type.value] += 1
    total = sum(counts.values())
    result = RepostAnalysis(counts=dict(counts), sample_size=total)
    if total == 0:
        return result
    result.shares = {k: v / total for k, v in counts.items()}
    result.original_ratio = sum(counts[t.value] for t in _ORIGINAL) / total
    result.repost_ratio = sum(counts[t.value] for t in _REPOST) / total
    result.reply_ratio = sum(counts[t.value] for t in _REPLY) / total
    result.cross_posts = _cross_posts(observations)
    return result


def _cross_posts(observations: Sequence[Observation]) -> List[Dict[str, object]]:
    """Group observations sharing a content_hash across >1 platform."""
    by_hash: Dict[str, List[Observation]] = defaultdict(list)
    for o in observations:
        if o.content_hash and (o.text or "").strip():
            by_hash[o.content_hash].append(o)
    out: List[Dict[str, object]] = []
    for h, group in by_hash.items():
        platforms = {o.platform for o in group if o.platform}
        if len(platforms) >= 2:
            ts = sorted(o.timestamp for o in group if o.has_time)
            spread = (ts[-1] - ts[0]) if len(ts) >= 2 else 0.0
            out.append({
                "content_hash": h,
                "platforms": sorted(platforms),
                "occurrences": len(group),
                "temporal_spread_seconds": round(spread, 1),
            })
    out.sort(key=lambda d: d["occurrences"], reverse=True)  # type: ignore[arg-type,return-value]
    return out
