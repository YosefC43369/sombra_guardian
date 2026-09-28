"""
behavioral_intelligence.temporal.change_point — statistical change detection on
an activity series (spec §7).

Three complementary detectors, each pure-stdlib and documented so the result is
auditable:

  * rolling z-score — flags a point whose value is many trailing standard
    deviations from the trailing mean (abrupt level shifts, spikes/drops).
  * CUSUM — two-sided cumulative-sum control chart; accumulates small
    persistent deviations, catching gradual regime changes a z-score misses.
  * EWMA — exponentially-weighted moving-average control chart; sensitive to
    small sustained shifts with tunable memory.

``detect_change_points`` runs all three over the (uniformly-sampled) daily
series and merges detections that fall within a tolerance so one real event
is reported once, with the method(s) that caught it.
"""

from __future__ import annotations

from typing import List, Sequence

from ..models.timeline import ChangePoint, ChangeKind
from .. import util


def rolling_zscore(values: Sequence[float], timestamps: Sequence[float], *,
                   window: int = 14, threshold: float = 3.0) -> List[ChangePoint]:
    out: List[ChangePoint] = []
    n = len(values)
    for i in range(window, n):
        past = values[i - window:i]
        m = util.mean(past)
        sd = util.stdev(past)
        if sd <= 0:
            continue
        z = (values[i] - m) / sd
        if abs(z) >= threshold:
            out.append(ChangePoint(
                at=timestamps[i], kind=ChangeKind.FREQUENCY.value, method="zscore",
                magnitude=abs(z), before_value=m, after_value=values[i],
                direction="increase" if z > 0 else "decrease",
                detail=f"value {values[i]:.1f} is {z:+.1f}σ from trailing "
                       f"{window}-point mean {m:.1f}"))
    return out


def cusum(values: Sequence[float], timestamps: Sequence[float], *,
          k: float = 0.5, h: float = 5.0) -> List[ChangePoint]:
    """Two-sided CUSUM. ``k`` is the slack (in sigmas) and ``h`` the decision
    interval (in sigmas). Emits a change point when either the high or low
    cumulative sum crosses ``h``σ, then resets that accumulator."""
    n = len(values)
    if n < 4:
        return []
    m = util.mean(values)
    sd = util.stdev(values)
    if sd <= 0:
        return []
    kk = k * sd
    hh = h * sd
    s_hi = s_lo = 0.0
    out: List[ChangePoint] = []
    for i in range(n):
        dev = values[i] - m
        s_hi = max(0.0, s_hi + dev - kk)
        s_lo = min(0.0, s_lo + dev + kk)
        if s_hi > hh:
            out.append(ChangePoint(
                at=timestamps[i], kind=ChangeKind.FREQUENCY.value, method="cusum",
                magnitude=s_hi / sd, before_value=m, after_value=values[i],
                direction="increase",
                detail=f"CUSUM high accumulator crossed {h:.0f}σ decision interval"))
            s_hi = 0.0
        if s_lo < -hh:
            out.append(ChangePoint(
                at=timestamps[i], kind=ChangeKind.FREQUENCY.value, method="cusum",
                magnitude=abs(s_lo) / sd, before_value=m, after_value=values[i],
                direction="decrease",
                detail=f"CUSUM low accumulator crossed {h:.0f}σ decision interval"))
            s_lo = 0.0
    return out


def ewma(values: Sequence[float], timestamps: Sequence[float], *,
         alpha: float = 0.3, L: float = 3.0) -> List[ChangePoint]:
    """EWMA control chart. The smoothed statistic z_t = α·x_t + (1-α)·z_{t-1}
    is compared to control limits at ±L·σ·sqrt(α/(2-α)). Flags sustained small
    shifts. Emits at most one point per crossing direction change."""
    n = len(values)
    if n < 4:
        return []
    m = util.mean(values)
    sd = util.stdev(values)
    if sd <= 0:
        return []
    limit = L * sd * (alpha / (2 - alpha)) ** 0.5
    z = m
    out: List[ChangePoint] = []
    last_state = 0     # -1 below, 0 in-control, +1 above
    for i in range(n):
        z = alpha * values[i] + (1 - alpha) * z
        dev = z - m
        state = 1 if dev > limit else (-1 if dev < -limit else 0)
        if state != 0 and state != last_state:
            out.append(ChangePoint(
                at=timestamps[i], kind=ChangeKind.FREQUENCY.value, method="ewma",
                magnitude=abs(dev) / sd, before_value=m, after_value=z,
                direction="increase" if state > 0 else "decrease",
                detail=f"EWMA statistic {z:.1f} crossed ±{limit:.1f} control limit"))
        last_state = state
    return out


def detect_change_points(values: Sequence[float], timestamps: Sequence[float], *,
                         zscore_threshold: float = 3.0,
                         merge_tolerance: float = 3 * util.DAY_SECONDS
                         ) -> List[ChangePoint]:
    """Run all three detectors and merge co-located detections (within
    ``merge_tolerance`` seconds). Kept detection keeps the largest magnitude and
    lists every method that fired."""
    if len(values) != len(timestamps) or len(values) < 4:
        return []
    candidates: List[ChangePoint] = []
    candidates += rolling_zscore(values, timestamps, threshold=zscore_threshold)
    candidates += cusum(values, timestamps)
    candidates += ewma(values, timestamps)
    candidates.sort(key=lambda c: c.at)

    merged: List[ChangePoint] = []
    for cp in candidates:
        if merged and abs(cp.at - merged[-1].at) <= merge_tolerance:
            prev = merged[-1]
            methods = set(prev.method.split("+")) | {cp.method}
            prev.method = "+".join(sorted(methods))
            if cp.magnitude > prev.magnitude:
                prev.magnitude = cp.magnitude
                prev.before_value = cp.before_value
                prev.after_value = cp.after_value
                prev.direction = cp.direction
                prev.detail = cp.detail
        else:
            merged.append(cp)
    return merged
