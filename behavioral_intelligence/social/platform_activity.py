"""
behavioral_intelligence.social.platform_activity — per-platform activity summary
(spec §23 support / footprint mapping).

For each platform an account is observed on: volume, rate, first/last activity,
content-type mix and language mix. This is the "which platforms, how much"
footprint view that both red-team footprinting and blue-team enrichment start
from.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation
from .. import util


@dataclass
class PlatformStat:
    platform: str = ""
    count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    span_days: float = 0.0
    posts_per_day: float = 0.0
    content_mix: Dict[str, int] = field(default_factory=dict)
    accounts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"platform": self.platform, "count": self.count,
                "first_seen": self.first_seen, "last_seen": self.last_seen,
                "span_days": round(self.span_days, 2),
                "posts_per_day": round(self.posts_per_day, 3),
                "content_mix": self.content_mix, "accounts": self.accounts}


def analyze_platforms(observations: Sequence[Observation]) -> List[PlatformStat]:
    groups: Dict[str, List[Observation]] = defaultdict(list)
    for o in observations:
        if o.platform:
            groups[o.platform].append(o)
    out: List[PlatformStat] = []
    for platform, obs in groups.items():
        timed = [o for o in obs if o.has_time]
        ts = sorted(o.timestamp for o in timed)
        span = (ts[-1] - ts[0]) / util.DAY_SECONDS if len(ts) >= 2 else 0.0
        content = Counter(o.content_type.value for o in obs)
        out.append(PlatformStat(
            platform=platform, count=len(obs),
            first_seen=ts[0] if ts else 0.0, last_seen=ts[-1] if ts else 0.0,
            span_days=span,
            posts_per_day=util.safe_div(len(obs), max(span, 1.0)),
            content_mix=dict(content),
            accounts=sorted({o.account_id for o in obs if o.account_id})))
    out.sort(key=lambda p: p.count, reverse=True)
    return out
