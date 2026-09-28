"""
behavioral_intelligence.models.anomaly — typed results for baseline, deviation,
drift and anomaly scoring.

Wording discipline (spec §27, §30): an anomaly is "anomalous relative to the
observed baseline", never "malicious" and never a criminality score. The
``AnomalyScore`` is an explainable deviation measure whose contributing features
are always exposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class Baseline:
    """A behavioural baseline built from historical public observations
    (spec §8). Every feature is a plain observed statistic over the window."""
    entity_id: str = ""
    window_days: int = 30
    period_start: float = 0.0
    period_end: float = 0.0
    sample_size: int = 0
    posts_per_day: float = 0.0
    posts_per_hour: float = 0.0
    mean_interval_seconds: float = 0.0
    stdev_interval_seconds: float = 0.0
    language_distribution: Dict[str, float] = field(default_factory=dict)
    platform_distribution: Dict[str, float] = field(default_factory=dict)
    topic_distribution: Dict[str, float] = field(default_factory=dict)
    hashtag_distribution: Dict[str, float] = field(default_factory=dict)
    domain_distribution: Dict[str, float] = field(default_factory=dict)
    hour_histogram: List[int] = field(default_factory=lambda: [0] * 24)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("posts_per_day", "posts_per_hour", "mean_interval_seconds",
                  "stdev_interval_seconds"):
            d[k] = round(d[k], 4)
        for dist in ("language_distribution", "platform_distribution",
                     "topic_distribution", "hashtag_distribution",
                     "domain_distribution"):
            d[dist] = {k: round(v, 3) for k, v in d[dist].items()}
        return d


@dataclass
class Deviation:
    """One feature's deviation from baseline — a line in the anomaly breakdown."""
    feature: str = ""
    observed: float = 0.0
    baseline: float = 0.0
    z_score: float = 0.0
    relative_change: float = 0.0
    contribution: float = 0.0          # points contributed to the anomaly score
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("observed", "baseline", "z_score", "relative_change",
                  "contribution"):
            d[k] = round(d[k], 4)
        return d


# Anomaly-score bands (spec §30). NOT a criminality/threat scale.
ANOMALY_BANDS = [
    (81.0, "high deviation"),
    (61.0, "significant deviation"),
    (41.0, "moderate deviation"),
    (21.0, "minor deviation"),
    (0.0, "normal relative to baseline"),
]


def anomaly_band(score: float) -> str:
    for floor, name in ANOMALY_BANDS:
        if score >= floor:
            return name
    return "normal relative to baseline"


@dataclass
class AnomalyScore:
    """An explainable 0–100 deviation score with its contributing features."""
    entity_id: str = ""
    score: float = 0.0
    band: str = "normal relative to baseline"
    deviations: List[Deviation] = field(default_factory=list)
    baseline_window_days: int = 30
    observed_window_days: float = 0.0
    sample_size: int = 0

    def top_features(self, n: int = 5) -> List[Deviation]:
        return sorted(self.deviations, key=lambda d: abs(d.contribution),
                      reverse=True)[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "score": round(self.score, 1),
            "band": self.band,
            "baseline_window_days": self.baseline_window_days,
            "observed_window_days": round(self.observed_window_days, 2),
            "sample_size": self.sample_size,
            "deviations": [d.to_dict() for d in
                           sorted(self.deviations, key=lambda x: abs(x.contribution),
                                  reverse=True)],
            "note": ("Anomaly score measures deviation from this entity's own "
                     "observed baseline. It is NOT a measure of malice, threat, "
                     "criminality or intent."),
        }


@dataclass
class Anomaly:
    """A discrete flagged change worth an analyst's attention (spec §27)."""
    entity_id: str = ""
    at: float = 0.0
    kind: str = ""                     # frequency_spike | language_shift | ...
    description: str = ""
    severity: str = "info"             # info | notable | significant
    z_score: float = 0.0
    baseline: float = 0.0
    observed: float = 0.0
    platforms: List[str] = field(default_factory=list)
    evidence_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("z_score", "baseline", "observed"):
            d[k] = round(d[k], 4)
        return d


@dataclass
class Drift:
    """Gradual distribution drift between two windows (spec anomaly/drift)."""
    feature: str = ""
    distance: float = 0.0              # Jensen–Shannon distance, 0..1
    early_top: List[str] = field(default_factory=list)
    late_top: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["distance"] = round(self.distance, 4)
        return d
