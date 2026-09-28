"""
behavioral_intelligence.temporal.inactivity_detection — silence detection.

Detects prolonged periods with no observed public activity (spec §6). Crucially,
the result is framed as *lack of observation*: a gap is NOT interpreted as the
account holder being physically absent, asleep, or offline — only that nothing
public was observed. The gap records the activity rate before and after so an
analyst can see whether behaviour resumed at the same cadence.
"""

from __future__ import annotations

from typing import List, Sequence

from ..models.observation import Observation
from ..models.activity import InactivityGap
from .. import util


def detect_inactivity(observations: Sequence[Observation], *,
                      min_gap_days: float = 7.0,
                      flank_days: float = 14.0) -> List[InactivityGap]:
    """Find gaps longer than ``min_gap_days`` between consecutive observations.

    ``flank_days`` sets how far before/after the gap the prior/following rate is
    measured, so the report can say whether the cadence changed across the
    silence rather than just that it occurred."""
    timed = sorted((o for o in observations if o.has_time), key=lambda o: o.timestamp)
    if len(timed) < 2:
        return []

    min_gap = min_gap_days * util.DAY_SECONDS
    flank = flank_days * util.DAY_SECONDS
    ts = [o.timestamp for o in timed]
    gaps: List[InactivityGap] = []

    for i in range(len(ts) - 1):
        delta = ts[i + 1] - ts[i]
        if delta < min_gap:
            continue
        gap_start, gap_end = ts[i], ts[i + 1]
        prior = [o for o in timed if gap_start - flank <= o.timestamp <= gap_start]
        following = [o for o in timed if gap_end <= o.timestamp <= gap_end + flank]
        gaps.append(InactivityGap(
            start=gap_start, end=gap_end, duration_seconds=delta,
            prior_rate_per_day=util.safe_div(len(prior) * util.DAY_SECONDS, flank),
            following_rate_per_day=util.safe_div(len(following) * util.DAY_SECONDS, flank),
            platforms_affected=sorted({o.platform for o in timed if o.platform})))
    gaps.sort(key=lambda g: g.duration_seconds, reverse=True)
    return gaps
