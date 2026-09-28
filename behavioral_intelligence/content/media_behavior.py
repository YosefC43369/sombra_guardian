"""
behavioral_intelligence.content.media_behavior — public media-sharing behaviour.

Summarises the media an account attaches to public posts using metadata already
present on the observation (``content_type == MEDIA`` and any ``media_*`` keys in
``metadata``): how often media is shared, the mix of media kinds, and the share
of posts carrying media. No image is downloaded, decoded or biometrically
analysed — this is a count of publicly-declared attachments, matching the
engine's "no biometrics" posture inherited from entity_fusion.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Sequence

from ..models.observation import Observation, ContentType
from .. import util


@dataclass
class MediaBehavior:
    media_posts: int = 0
    total_posts: int = 0
    media_ratio: float = 0.0
    kind_counts: Dict[str, int] = field(default_factory=dict)
    alt_text_ratio: float = 0.0            # share of media with public alt text
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return {"media_posts": self.media_posts, "total_posts": self.total_posts,
                "media_ratio": round(self.media_ratio, 3),
                "kind_counts": self.kind_counts,
                "alt_text_ratio": round(self.alt_text_ratio, 3),
                "first_seen": self.first_seen, "last_seen": self.last_seen}


def analyze_media(observations: Sequence[Observation]) -> MediaBehavior:
    result = MediaBehavior(total_posts=len(observations))
    kinds: Counter = Counter()
    with_alt = 0
    for o in observations:
        has_media = (o.content_type == ContentType.MEDIA or
                     bool(o.metadata.get("media_type")) or
                     bool(o.metadata.get("has_media")))
        if not has_media:
            continue
        result.media_posts += 1
        kind = str(o.metadata.get("media_type", o.content_type.value))
        kinds[kind] += 1
        if o.metadata.get("alt_text") or o.metadata.get("media_alt"):
            with_alt += 1
        if o.has_time:
            result.first_seen = (o.timestamp if result.first_seen == 0
                                 else min(result.first_seen, o.timestamp))
            result.last_seen = max(result.last_seen, o.timestamp)
    result.kind_counts = dict(kinds)
    result.media_ratio = util.safe_div(result.media_posts, len(observations))
    result.alt_text_ratio = util.safe_div(with_alt, max(result.media_posts, 1))
    return result
