"""
behavioral_intelligence.temporal.seasonality — recurring-period detection.

Given a uniformly-sampled activity series (e.g. daily counts), estimate the
autocorrelation at a range of lags and report lags whose correlation is a local
peak above a threshold — evidence of a recurring rhythm (weekly, monthly). This
is descriptive: "activity recurs on an ~7-day cycle" is an OBSERVED pattern, not
a claim about why.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from .. import util


@dataclass
class SeasonalityResult:
    detected: bool = False
    dominant_lag: int = 0
    strength: float = 0.0
    autocorrelation: Dict[int, float] = field(default_factory=dict)
    candidate_lags: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "detected": self.detected,
            "dominant_lag": self.dominant_lag,
            "strength": round(self.strength, 3),
            "autocorrelation": {k: round(v, 3) for k, v in self.autocorrelation.items()},
            "candidate_lags": self.candidate_lags,
        }


def autocorrelation(values: Sequence[float], lag: int) -> float:
    """Pearson autocorrelation of the series against itself shifted by ``lag``."""
    n = len(values)
    if lag <= 0 or lag >= n:
        return 0.0
    return util.pearson(list(values[:-lag]), list(values[lag:]))


def detect_seasonality(values: Sequence[float], *, max_lag: int = 45,
                       threshold: float = 0.3) -> SeasonalityResult:
    """Scan lags 2..max_lag, keep local peaks in the autocorrelation function
    above ``threshold``. The strongest such lag is the dominant period."""
    n = len(values)
    result = SeasonalityResult()
    if n < 8:
        return result
    upper = min(max_lag, n // 2)
    acf = {lag: autocorrelation(values, lag) for lag in range(2, upper + 1)}
    result.autocorrelation = acf

    peaks: List[int] = []
    lags = sorted(acf)
    for idx, lag in enumerate(lags):
        v = acf[lag]
        if v < threshold:
            continue
        left = acf[lags[idx - 1]] if idx > 0 else -1.0
        right = acf[lags[idx + 1]] if idx + 1 < len(lags) else -1.0
        if v >= left and v >= right:
            peaks.append(lag)
    result.candidate_lags = peaks
    if peaks:
        dominant = max(peaks, key=lambda lag: acf[lag])
        result.detected = True
        result.dominant_lag = dominant
        result.strength = acf[dominant]
    return result
