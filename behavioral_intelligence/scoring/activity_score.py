"""
behavioral_intelligence.scoring.activity_score — an explainable activity-level
and regularity score.

Turns an ``ActivityStats`` into a 0–100 activity score whose sub-factors (volume,
coverage, regularity, recency) are always exposed. This is a descriptive summary
of how active and how regular the observed public activity is — not a judgement
of the account or its holder.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from ..models.activity import ActivityStats
from .. import util


@dataclass
class ActivityScore:
    score: float = 0.0
    band: str = "minimal"
    factors: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {"score": round(self.score, 1), "band": self.band,
                "factors": {k: round(v, 3) for k, v in self.factors.items()},
                "note": "Descriptive activity-level score; not a judgement of the "
                        "account holder."}


def _band(score: float) -> str:
    if score >= 80:
        return "very high"
    if score >= 60:
        return "high"
    if score >= 40:
        return "moderate"
    if score >= 20:
        return "low"
    return "minimal"


def score_activity(stats: ActivityStats, *, now: Optional[float] = None
                   ) -> ActivityScore:
    now = now if now is not None else time.time()
    # volume: saturating on posts/day
    volume = 1.0 - math.exp(-stats.posts_per_day / 5.0)
    # coverage: fraction of days active
    coverage = util.clamp(stats.coverage, 0.0, 1.0)
    # regularity: low coefficient of variation of intervals => regular
    cv = util.safe_div(stats.intervals.stdev, stats.intervals.mean, 1.0)
    regularity = 1.0 / (1.0 + cv)
    # recency: decays over 30 days since last seen
    days_since = util.safe_div(now - stats.last_seen, util.DAY_SECONDS) \
        if stats.last_seen else 999.0
    recency = math.exp(-max(0.0, days_since) / 30.0)

    factors = {"volume": volume, "coverage": coverage,
               "regularity": regularity, "recency": recency}
    score = 100.0 * (0.4 * volume + 0.25 * coverage +
                     0.2 * regularity + 0.15 * recency)
    result = ActivityScore(score=score, band=_band(score), factors=factors)
    return result
