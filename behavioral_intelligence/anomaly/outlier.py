"""
behavioral_intelligence.anomaly.outlier — univariate outlier detection.

Three robust methods over a numeric series, all stdlib: z-score (mean/σ), IQR
fences (Tukey), and MAD (median absolute deviation, robust to the very spikes we
are looking for). Returns the indices flagged plus the score for each, so the
caller can attach the underlying value as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Sequence

from .. import util


@dataclass
class Outlier:
    index: int
    value: float
    score: float
    method: str

    def to_dict(self) -> Dict[str, object]:
        return {"index": self.index, "value": round(self.value, 3),
                "score": round(self.score, 3), "method": self.method}


def zscore_outliers(values: Sequence[float], *, threshold: float = 3.0
                    ) -> List[Outlier]:
    if len(values) < 3:
        return []
    m = util.mean(values)
    sd = util.stdev(values)
    if sd <= 0:
        return []
    out = []
    for i, v in enumerate(values):
        z = (v - m) / sd
        if abs(z) >= threshold:
            out.append(Outlier(i, v, z, "zscore"))
    return out


def iqr_outliers(values: Sequence[float], *, k: float = 1.5) -> List[Outlier]:
    if len(values) < 4:
        return []
    q1 = util.percentile(values, 25)
    q3 = util.percentile(values, 75)
    iqr = q3 - q1
    if iqr <= 0:
        return []
    lo, hi = q1 - k * iqr, q3 + k * iqr
    out = []
    for i, v in enumerate(values):
        if v < lo or v > hi:
            dist = (v - hi) if v > hi else (lo - v)
            out.append(Outlier(i, v, dist / iqr, "iqr"))
    return out


def mad_outliers(values: Sequence[float], *, threshold: float = 3.5) -> List[Outlier]:
    """Median absolute deviation; the 0.6745 factor makes it comparable to a
    z-score under normality. Robust to a minority of extreme spikes."""
    if len(values) < 3:
        return []
    med = util.median(values)
    deviations = [abs(v - med) for v in values]
    mad = util.median(deviations)
    if mad <= 0:
        return []
    out = []
    for i, v in enumerate(values):
        score = 0.6745 * (v - med) / mad
        if abs(score) >= threshold:
            out.append(Outlier(i, v, score, "mad"))
    return out


def detect_outliers(values: Sequence[float], *, method: str = "mad") -> List[Outlier]:
    dispatch: Dict[str, Callable[[Sequence[float]], List[Outlier]]] = {
        "zscore": zscore_outliers, "iqr": iqr_outliers, "mad": mad_outliers}
    return dispatch.get(method, mad_outliers)(values)
