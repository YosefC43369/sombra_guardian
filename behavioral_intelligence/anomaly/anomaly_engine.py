"""
behavioral_intelligence.anomaly.anomaly_engine — deviation-from-baseline
analysis (spec §27, §30).

Compares a recent *observed window* against the entity's own historical
``Baseline`` and produces an explainable 0–100 anomaly score whose contributing
features are always exposed, plus discrete ``Anomaly`` records for the notable
deviations. Wording is strict: an anomaly is "anomalous relative to the observed
baseline" — the engine never labels activity malicious, and the score is a
deviation measure, NOT a threat, criminality or intent score.
"""

from __future__ import annotations

import time
from typing import List, Optional, Sequence

from ..models.observation import Observation
from ..models.anomaly import (Baseline, Deviation, AnomalyScore, Anomaly,
                              anomaly_band)
from ..models.confidence import Assertion, AssertionKind, make_confidence
from ..linguistic.language_switching import distribution as language_distribution
from ..content.domain_behavior import analyze_domains, domain_transitions
from .. import util
from .baseline import build_baseline

# Feature weights → contribution to the 0..100 score (sum of caps ≈ 100).
_WEIGHTS = {
    "posting_rate": 30.0,
    "language_mix": 20.0,
    "domain_mix": 15.0,
    "hashtag_mix": 10.0,
    "hour_profile": 15.0,
    "new_domains": 10.0,
}


class AnomalyEngine:
    def __init__(self, *, observed_window_days: float = 7.0,
                 baseline_window_days: int = 30, source_count: int = 1):
        self.observed_window_days = observed_window_days
        self.baseline_window_days = baseline_window_days
        self.source_count = source_count

    def analyze(self, observations: Sequence[Observation], *,
                baseline: Optional[Baseline] = None, entity_id: str = "",
                reference_time: Optional[float] = None):
        """Return (AnomalyScore, [Anomaly], [Assertion]).

        The baseline is built from data *before* the observed window so the
        comparison is prior-behaviour vs. recent-behaviour, not a window against
        itself."""
        timed = sorted((o for o in observations if o.has_time),
                       key=lambda o: o.timestamp)
        ref = reference_time if reference_time is not None else (
            timed[-1].timestamp if timed else time.time())
        obs_lo = ref - self.observed_window_days * util.DAY_SECONDS
        observed = [o for o in timed if obs_lo <= o.timestamp <= ref]
        prior = [o for o in timed if o.timestamp < obs_lo]

        if baseline is None:
            baseline = build_baseline(prior or timed,
                                      window_days=self.baseline_window_days,
                                      entity_id=entity_id, reference_time=obs_lo)

        score = AnomalyScore(entity_id=entity_id,
                             baseline_window_days=baseline.window_days,
                             observed_window_days=self.observed_window_days,
                             sample_size=len(observed))
        anomalies: List[Anomaly] = []

        if not observed or baseline.sample_size == 0:
            score.band = anomaly_band(0.0)
            return score, anomalies, self._assertions(score, anomalies, baseline)

        deviations: List[Deviation] = []
        deviations.append(self._rate_deviation(observed, baseline, anomalies, ref))
        deviations.append(self._language_deviation(observed, baseline, anomalies, ref))
        deviations.append(self._domain_deviation(observed, baseline, anomalies, ref))
        deviations.append(self._hashtag_deviation(observed, baseline, anomalies, ref))
        deviations.append(self._hour_deviation(observed, baseline, anomalies, ref))
        deviations.append(self._new_domain_deviation(prior, observed, anomalies, ref))

        score.deviations = [d for d in deviations if d is not None]
        score.score = min(100.0, sum(d.contribution for d in score.deviations))
        score.band = anomaly_band(score.score)
        return score, anomalies, self._assertions(score, anomalies, baseline)

    # -- individual feature deviations ------------------------------------ #

    def _rate_deviation(self, observed, baseline, anomalies, ref) -> Deviation:
        span = max((observed[-1].timestamp - observed[0].timestamp)
                   / util.DAY_SECONDS, 1.0) if len(observed) > 1 else 1.0
        obs_rate = len(observed) / span
        base_rate = baseline.posts_per_day
        rel = util.safe_div(obs_rate, base_rate, 1.0)
        # z of observed daily rate against a Poisson-ish sqrt(rate) spread
        z = 0.0
        if base_rate > 0:
            z = (obs_rate - base_rate) / max(base_rate ** 0.5, 1e-6)
        contribution = min(_WEIGHTS["posting_rate"],
                           abs(rel - 1.0) * _WEIGHTS["posting_rate"])
        dev = Deviation(feature="posting_rate", observed=obs_rate, baseline=base_rate,
                        z_score=z, relative_change=rel, contribution=contribution,
                        note=f"{obs_rate:.2f}/day vs baseline {base_rate:.2f}/day")
        if rel >= 2.0 or rel <= 0.4:
            anomalies.append(Anomaly(
                entity_id=baseline.entity_id, at=ref, kind="posting_rate_shift",
                description=(f"Posting rate {rel:.1f}× baseline "
                            f"({obs_rate:.2f} vs {base_rate:.2f}/day) — "
                            f"anomalous relative to observed baseline."),
                severity="significant" if (rel >= 3 or rel <= 0.25) else "notable",
                baseline=base_rate, observed=obs_rate,
                platforms=sorted({o.platform for o in observed if o.platform})))
        return dev

    def _dist_deviation(self, feature, obs_dist, base_dist, weight, anomalies,
                        ref, entity_id) -> Deviation:
        dist = util.jensen_shannon(obs_dist, base_dist)
        contribution = dist * weight
        dev = Deviation(feature=feature, observed=dist, baseline=0.0,
                        z_score=0.0, relative_change=dist, contribution=contribution,
                        note=f"Jensen-Shannon distance {dist:.2f} from baseline")
        if dist >= 0.5:
            anomalies.append(Anomaly(
                entity_id=entity_id, at=ref, kind=f"{feature}_shift",
                description=(f"{feature.replace('_',' ').title()} shifted markedly "
                            f"(JS distance {dist:.2f}) — anomalous relative to "
                            f"observed baseline."),
                severity="significant" if dist >= 0.7 else "notable",
                observed=dist, baseline=0.0))
        return dev

    def _language_deviation(self, observed, baseline, anomalies, ref) -> Deviation:
        obs_dist = language_distribution(observed).shares
        return self._dist_deviation("language_mix", obs_dist,
                                    baseline.language_distribution,
                                    _WEIGHTS["language_mix"], anomalies, ref,
                                    baseline.entity_id)

    def _domain_deviation(self, observed, baseline, anomalies, ref) -> Deviation:
        domains = analyze_domains(observed, top_n=50)
        obs_dist = util.shares({d.domain: d.frequency for d in domains})
        return self._dist_deviation("domain_mix", obs_dist,
                                    baseline.domain_distribution,
                                    _WEIGHTS["domain_mix"], anomalies, ref,
                                    baseline.entity_id)

    def _hashtag_deviation(self, observed, baseline, anomalies, ref) -> Deviation:
        obs_dist = util.shares(dict(util.counts(
            t for o in observed for t in o.hashtags)))
        return self._dist_deviation("hashtag_mix", obs_dist,
                                    baseline.hashtag_distribution,
                                    _WEIGHTS["hashtag_mix"], anomalies, ref,
                                    baseline.entity_id)

    def _hour_deviation(self, observed, baseline, anomalies, ref) -> Deviation:
        obs_hist = [0] * 24
        for o in observed:
            if o.timestamp_precision.supports_hour:
                obs_hist[o.hour_utc] += 1
        overlap = util.histogram_intersection(obs_hist, baseline.hour_histogram)
        distance = 1.0 - overlap
        contribution = distance * _WEIGHTS["hour_profile"]
        dev = Deviation(feature="hour_profile", observed=distance, baseline=0.0,
                        z_score=0.0, relative_change=distance,
                        contribution=contribution,
                        note=f"hour-of-day overlap with baseline {overlap:.2f}")
        if distance >= 0.6:
            anomalies.append(Anomaly(
                entity_id=baseline.entity_id, at=ref, kind="hour_profile_shift",
                description=(f"Hour-of-day activity profile diverged from baseline "
                            f"(overlap {overlap:.2f}) — anomalous relative to "
                            f"observed baseline."),
                severity="notable", observed=distance, baseline=0.0))
        return dev

    def _new_domain_deviation(self, prior, observed, anomalies, ref) -> Deviation:
        trans = domain_transitions(prior, observed)
        appeared = trans["appeared"]
        total_obs_domains = len(set(trans["appeared"]) | set(trans["retained"]))
        frac_new = util.safe_div(len(appeared), max(total_obs_domains, 1))
        contribution = frac_new * _WEIGHTS["new_domains"]
        dev = Deviation(feature="new_domains", observed=len(appeared),
                        baseline=0.0, z_score=0.0, relative_change=frac_new,
                        contribution=contribution,
                        note=f"{len(appeared)} newly-appearing domains")
        if len(appeared) >= 3 and frac_new >= 0.5:
            anomalies.append(Anomaly(
                entity_id="", at=ref, kind="new_domains",
                description=(f"{len(appeared)} previously-unseen domains appeared "
                            f"in the observed window — anomalous relative to "
                            f"observed baseline."),
                severity="notable", observed=len(appeared), baseline=0.0,
                platforms=[]))
        return dev

    def _assertions(self, score, anomalies, baseline) -> List[Assertion]:
        conf = make_confidence(sample_size=score.sample_size,
                               period_days=self.observed_window_days,
                               source_count=self.source_count,
                               supporting=[d.feature for d in score.deviations
                                           if d.contribution > 1])
        conf.add_limitation(
            "Anomaly score measures deviation from this entity's own observed "
            "baseline; it is not a measure of malice, threat or intent.", "critical")
        a = Assertion(
            statement=(f"Observed-window behaviour scores {score.score:.0f}/100 on "
                       f"the anomaly scale ({score.band}) relative to the "
                       f"{baseline.window_days}-day baseline."),
            kind=AssertionKind.OBSERVED, confidence=conf,
            observation_period=(baseline.period_start, score.observed_window_days),
            tags=["anomaly_score"], detail=score.to_dict())
        out = [a]
        for an in anomalies[:5]:
            out.append(Assertion(
                statement=an.description, kind=AssertionKind.OBSERVED,
                confidence=make_confidence(sample_size=score.sample_size,
                                           period_days=self.observed_window_days,
                                           source_count=self.source_count),
                tags=["anomaly", an.kind]))
        return out
