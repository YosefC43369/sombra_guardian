"""
behavioral_intelligence.anomaly.baseline — behavioural baseline construction
(spec §8).

Builds a ``Baseline`` from historical public observations over a configurable
window (7 / 30 / 90 days or custom): posting rate, interval statistics, and the
language / platform / topic / hashtag / domain distributions plus the hour-of-day
profile. The baseline is the entity's *own* prior behaviour — the reference the
anomaly engine deviates against — so anomalies are always relative to self, never
to a population norm the engine has not observed.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from ..models.observation import Observation
from ..models.anomaly import Baseline
from ..linguistic.language_switching import distribution as language_distribution
from ..content.domain_behavior import analyze_domains
from ..content.topic_engine import discover_topics
from .. import util


def build_baseline(observations: Sequence[Observation], *, window_days: int = 30,
                   entity_id: str = "", reference_time: Optional[float] = None
                   ) -> Baseline:
    """Build a baseline from observations within ``window_days`` before
    ``reference_time`` (defaults to the latest observation)."""
    timed = sorted((o for o in observations if o.has_time), key=lambda o: o.timestamp)
    baseline = Baseline(entity_id=entity_id, window_days=window_days)
    if not timed:
        return baseline

    ref = reference_time if reference_time is not None else timed[-1].timestamp
    lo = ref - window_days * util.DAY_SECONDS
    window = [o for o in timed if lo <= o.timestamp <= ref]
    if not window:
        return baseline

    baseline.period_start = window[0].timestamp
    baseline.period_end = window[-1].timestamp
    baseline.sample_size = len(window)

    span_days = max((window[-1].timestamp - window[0].timestamp) / util.DAY_SECONDS,
                    1.0)
    baseline.posts_per_day = len(window) / span_days
    baseline.posts_per_hour = baseline.posts_per_day / 24.0

    gaps = [window[i + 1].timestamp - window[i].timestamp
            for i in range(len(window) - 1)]
    if gaps:
        baseline.mean_interval_seconds = util.mean(gaps)
        baseline.stdev_interval_seconds = util.stdev(gaps)

    # hour-of-day profile
    for o in window:
        if o.timestamp_precision.supports_hour:
            baseline.hour_histogram[o.hour_utc] += 1

    # distributions
    lang = language_distribution(window)
    baseline.language_distribution = lang.shares

    plat_counts = util.counts(o.platform for o in window)
    baseline.platform_distribution = util.shares(dict(plat_counts))

    hashtag_counts = util.counts(t for o in window for t in o.hashtags)
    baseline.hashtag_distribution = util.shares(dict(hashtag_counts))

    domains = analyze_domains(window, top_n=30)
    dom_counts = {d.domain: d.frequency for d in domains}
    baseline.domain_distribution = util.shares(dom_counts)

    topics = discover_topics(window, max_topics=10)
    topic_weights = {t.label: t.weight for t in topics}
    baseline.topic_distribution = util.shares(
        {k: int(v) for k, v in topic_weights.items()} if topic_weights else {})

    return baseline


def build_baselines(observations: Sequence[Observation], *,
                    windows: Sequence[int] = (7, 30, 90),
                    entity_id: str = "") -> List[Baseline]:
    """Build a baseline per configured window (spec §8)."""
    return [build_baseline(observations, window_days=w, entity_id=entity_id)
            for w in windows]
