"""
behavioral_intelligence.content.topic_evolution — how public topics change over
time (spec §15).

Slices the observation stream into periods (month by default), computes the top
salient terms in each period, and reports which terms emerged in the latest
period and which faded from it. The output is a set of observed term lists per
period plus the diff — explainable evidence, no interpretation of *why* the
topics changed.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Set

from ..models.observation import Observation
from ..models.topic import TopicPeriod, TopicEvolution
from ..linguistic.keyword_engine import extract_keywords


def _bucket(observations: Sequence[Observation], granularity: str
            ) -> Dict[str, List[Observation]]:
    buckets: Dict[str, List[Observation]] = {}
    for o in observations:
        if not o.has_time:
            continue
        key = o.month_utc if granularity == "month" else o.iso_week_utc
        buckets.setdefault(key, []).append(o)
    return buckets


def analyze_evolution(observations: Sequence[Observation], *,
                      granularity: str = "month", terms_per_period: int = 8
                      ) -> TopicEvolution:
    buckets = _bucket(observations, granularity)
    if not buckets:
        return TopicEvolution()

    periods: List[TopicPeriod] = []
    for key in sorted(buckets):
        obs = buckets[key]
        kws = extract_keywords(obs, top_n=terms_per_period)
        start = min(o.timestamp for o in obs)
        periods.append(TopicPeriod(
            period_label=key, period_start=start,
            top_terms=[(k.term, k.tfidf) for k in kws],
            sample_size=len(obs)))

    evo = TopicEvolution(periods=periods)
    if len(periods) >= 2:
        latest = {t for t, _ in periods[-1].top_terms}
        previous: Set[str] = set()
        for p in periods[:-1]:
            previous |= {t for t, _ in p.top_terms}
        evo.emerged = sorted(latest - previous)
        evo.faded = sorted(previous - latest)
    return evo
