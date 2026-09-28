"""
behavioral_intelligence.anomaly.drift — distribution drift between two windows.

Measures how much a categorical behaviour distribution (language, topic, hashtag,
domain, platform) has drifted from an earlier window to a later one, using the
Jensen–Shannon distance (symmetric, bounded [0,1]). Reports the top terms on each
side so the drift is explainable rather than a bare number.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from ..models.observation import Observation
from ..models.anomaly import Drift
from ..linguistic.language_switching import distribution as language_distribution
from ..content.domain_behavior import analyze_domains
from .. import util


def _domain_dist(obs: Sequence[Observation]) -> Dict[str, float]:
    domains = analyze_domains(obs, top_n=50)
    return util.shares({d.domain: d.frequency for d in domains})


def _hashtag_dist(obs: Sequence[Observation]) -> Dict[str, float]:
    return util.shares(dict(util.counts(t for o in obs for t in o.hashtags)))


def _platform_dist(obs: Sequence[Observation]) -> Dict[str, float]:
    return util.shares(dict(util.counts(o.platform for o in obs)))


_FEATURES = {
    "language": lambda obs: language_distribution(obs).shares,
    "hashtag": _hashtag_dist,
    "domain": _domain_dist,
    "platform": _platform_dist,
}


def measure_drift(early: Sequence[Observation], late: Sequence[Observation], *,
                  feature: str = "language") -> Drift:
    fn = _FEATURES.get(feature, _FEATURES["language"])
    p = fn(early)
    q = fn(late)
    dist = util.jensen_shannon(p, q)
    early_top = [k for k, _ in util.top_n(p, 5)]
    late_top = [k for k, _ in util.top_n(q, 5)]
    return Drift(feature=feature, distance=dist, early_top=early_top,
                 late_top=late_top)


def measure_all_drift(early: Sequence[Observation], late: Sequence[Observation]
                      ) -> List[Drift]:
    return [measure_drift(early, late, feature=f) for f in _FEATURES]
