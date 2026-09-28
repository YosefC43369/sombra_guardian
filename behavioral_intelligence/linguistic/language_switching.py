"""
behavioral_intelligence.linguistic.language_switching — language use over time
(spec §10).

Builds the language distribution, the per-period language timeline, the count of
observed switches in dominant language between consecutive posts, and the
platform × language matrix. All of it describes observable *use*; nationality
and ethnicity are never inferred (the caller attaches that standing limitation).
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from ..models.observation import Observation
from ..models.language import (LanguageDistribution, LanguageTimelinePoint,
                               LanguageSwitch)
from .. import util
from . import language_detector


def _language_of(o: Observation) -> str:
    """Prefer a language already recorded on the observation; otherwise detect
    from text. Returns 'und' when neither is available."""
    if o.language and o.language != "und":
        return o.language
    if o.text:
        return language_detector.detect_language(o.text)
    return "und"


def distribution(observations: Sequence[Observation]) -> LanguageDistribution:
    counts: Dict[str, int] = {}
    span_lo = span_hi = 0.0
    sample = 0
    for o in observations:
        lang = _language_of(o)
        if lang == "und":
            continue
        counts[lang] = counts.get(lang, 0) + 1
        sample += 1
        if o.has_time:
            span_lo = o.timestamp if span_lo == 0 else min(span_lo, o.timestamp)
            span_hi = max(span_hi, o.timestamp)
    return LanguageDistribution(shares=util.shares(counts), counts=counts,
                                sample_size=sample, period_start=span_lo,
                                period_end=span_hi)


def timeline(observations: Sequence[Observation], *, granularity: str = "month"
             ) -> List[LanguageTimelinePoint]:
    """Per-period language distribution. ``granularity`` is 'month' or 'week'."""
    buckets: Dict[str, Dict[str, int]] = {}
    bucket_start: Dict[str, float] = {}
    for o in observations:
        if not o.has_time:
            continue
        lang = _language_of(o)
        if lang == "und":
            continue
        key = o.month_utc if granularity == "month" else o.iso_week_utc
        buckets.setdefault(key, {})
        buckets[key][lang] = buckets[key].get(lang, 0) + 1
        bucket_start.setdefault(key, o.timestamp)
        bucket_start[key] = min(bucket_start[key], o.timestamp)

    points: List[LanguageTimelinePoint] = []
    for key in sorted(buckets):
        counts = buckets[key]
        points.append(LanguageTimelinePoint(
            period_label=key, period_start=bucket_start[key],
            distribution=util.shares(counts), sample_size=sum(counts.values())))
    return points


def switches(observations: Sequence[Observation]) -> List[LanguageSwitch]:
    """Observed changes in dominant language between consecutive timed posts."""
    timed = sorted((o for o in observations if o.has_time and (o.text or o.language)),
                   key=lambda o: o.timestamp)
    out: List[LanguageSwitch] = []
    prev_lang = ""
    for o in timed:
        lang = _language_of(o)
        if lang == "und":
            continue
        if prev_lang and lang != prev_lang:
            out.append(LanguageSwitch(at=o.timestamp, from_language=prev_lang,
                                      to_language=lang, platform=o.platform))
        prev_lang = lang
    return out


def switching_frequency(observations: Sequence[Observation]) -> float:
    """Switches per 100 posts — a scale-free measure of code-switching."""
    sw = switches(observations)
    considered = sum(1 for o in observations
                     if (o.text or o.language) and _language_of(o) != "und")
    return util.safe_div(len(sw) * 100.0, max(considered, 1))


def platform_language_matrix(observations: Sequence[Observation]
                             ) -> Dict[str, Dict[str, float]]:
    """{platform: {language: share}} — how language use differs by platform."""
    counts: Dict[str, Dict[str, int]] = {}
    for o in observations:
        if not o.platform:
            continue
        lang = _language_of(o)
        if lang == "und":
            continue
        counts.setdefault(o.platform, {})
        counts[o.platform][lang] = counts[o.platform].get(lang, 0) + 1
    return {p: util.shares(c) for p, c in counts.items()}
