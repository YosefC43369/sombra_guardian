"""
behavioral_intelligence.temporal.burst_detection — dense-activity detection.

Detects windows where public posting rate is unusually high relative to the
entity's own baseline (spec §5). The method is a sliding count window over the
sorted event times: any maximal run of events packed more tightly than a
threshold multiple of the baseline hourly rate becomes a ``Burst`` carrying its
count, duration, absolute and relative change — the evidence, not a verdict.
"""

from __future__ import annotations

from typing import List, Sequence

from ..models.observation import Observation
from ..models.activity import Burst
from .. import util


def detect_bursts(observations: Sequence[Observation], *,
                  window_minutes: int = 15,
                  min_count: int = 5,
                  relative_threshold: float = 3.0) -> List[Burst]:
    """Find activity bursts.

    A burst is a window of length ``window_minutes`` (grown while density holds)
    containing at least ``min_count`` events at a rate at least
    ``relative_threshold``× the baseline hourly rate. Bursts are computed per
    platform (a cross-platform coincidence is not a single-source burst) then
    returned newest-first-strongest.
    """
    timed = sorted((o for o in observations if o.has_time), key=lambda o: o.timestamp)
    if len(timed) < min_count:
        return []

    # baseline hourly rate over the whole observed span
    span = timed[-1].timestamp - timed[0].timestamp
    baseline_per_hour = util.safe_div(len(timed) * util.HOUR_SECONDS, span, 0.0)
    if baseline_per_hour <= 0:
        baseline_per_hour = util.safe_div(len(timed), 1.0)

    window = window_minutes * 60.0
    bursts: List[Burst] = []

    by_platform: dict = {}
    for o in timed:
        by_platform.setdefault(o.platform or "?", []).append(o)

    for platform, obs in by_platform.items():
        ts = [o.timestamp for o in obs]
        n = len(ts)
        i = 0
        while i < n:
            # grow a window from i while events keep arriving within `window`
            j = i
            while j + 1 < n and ts[j + 1] - ts[i] <= window:
                j += 1
            count = j - i + 1
            if count >= min_count:
                duration = max(ts[j] - ts[i], 1.0)
                rate_per_hour = count * util.HOUR_SECONDS / duration
                if rate_per_hour >= relative_threshold * baseline_per_hour:
                    bursts.append(Burst(
                        start=ts[i], end=ts[j], count=count,
                        duration_seconds=duration,
                        rate_per_hour=rate_per_hour,
                        baseline_per_hour=baseline_per_hour,
                        relative_change=util.safe_div(rate_per_hour, baseline_per_hour),
                        absolute_change=rate_per_hour - baseline_per_hour,
                        platforms=[platform]))
                    i = j + 1     # don't double-count the same dense run
                    continue
            i += 1

    bursts.sort(key=lambda b: b.relative_change, reverse=True)
    return bursts
