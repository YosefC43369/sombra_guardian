"""
behavioral_intelligence.temporal.hourly_analysis — hour-of-day activity.

Builds the 24-bucket hour-of-day histogram (UTC) and derives the peak activity
window(s). Only observations whose ``timestamp_precision`` is fine enough to
place them in an hour are counted (a day-precise crawl hit contributes to the
daily histogram but must not be pinned to an hour it does not actually have).

The peak window is reported as a UTC range with the share of activity it holds;
the engine never converts this into a chronotype claim ("nocturnal") — that is
an interpretation the caller may not make from observation alone.
"""

from __future__ import annotations

from typing import List, Sequence

from ..models.observation import Observation
from ..models.activity import Histogram, ActivityWindow
from .. import util


def hour_histogram(observations: Sequence[Observation],
                   tz_offset_hours: float = 0.0) -> Histogram:
    """24-bucket hour-of-day histogram. ``tz_offset_hours`` is a *display* shift
    only; the raw data stays UTC and the offset is recorded on the result."""
    counts = [0] * 24
    for o in observations:
        if not o.has_time or not o.timestamp_precision.supports_hour:
            continue
        counts[o.local_hour(tz_offset_hours)] += 1
    labels = [f"{h:02d}:00" for h in range(24)]
    hist = Histogram(dimension="hour_of_day", labels=labels, counts=counts,
                     total=sum(counts))
    return hist


def peak_windows(hist: Histogram, *, tz_offset_hours: float = 0.0,
                 min_share: float = 0.15, max_windows: int = 2) -> List[ActivityWindow]:
    """Find contiguous hour ranges (wrapping past midnight) that concentrate
    activity. A window is grown greedily from the busiest hour outward while the
    marginal hour is above the mean; windows holding < ``min_share`` are dropped.

    Reported in UTC. This describes *when activity was observed*, nothing more."""
    counts = list(hist.counts)
    total = sum(counts)
    if total == 0:
        return []
    avg = total / 24.0
    windows: List[ActivityWindow] = []
    used = [False] * 24

    for _ in range(max_windows):
        # busiest unused hour
        best_h, best_v = -1, -1
        for h in range(24):
            if not used[h] and counts[h] > best_v:
                best_h, best_v = h, counts[h]
        if best_h < 0 or best_v <= avg:
            break
        # grow outward while neighbours are above the mean
        left = right = best_h
        window_hours = {best_h}
        used[best_h] = True
        grew = True
        while grew:
            grew = False
            nl = (left - 1) % 24
            nr = (right + 1) % 24
            if not used[nl] and counts[nl] >= avg and len(window_hours) < 24:
                left = nl
                window_hours.add(nl)
                used[nl] = True
                grew = True
            if not used[nr] and counts[nr] >= avg and len(window_hours) < 24:
                right = nr
                window_hours.add(nr)
                used[nr] = True
                grew = True
        wcount = sum(counts[h] for h in window_hours)
        share = util.safe_div(wcount, total)
        if share >= min_share:
            end_hour = (right + 1) % 24     # exclusive-ish end for readability
            windows.append(ActivityWindow(
                start_hour=left, end_hour=end_hour, share=share,
                tz_offset_hours=tz_offset_hours))
    windows.sort(key=lambda w: w.share, reverse=True)
    return windows
