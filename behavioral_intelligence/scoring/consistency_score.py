"""
behavioral_intelligence.scoring.consistency_score — cross-account behavioural
consistency (spec §29).

Given several accounts (each an observation set), compare behavioural signals —
username similarity, declared-location/timezone (hour profile) consistency,
language mix, domain mix, posting schedule, topic mix, avatar hash — and report,
per feature, the supporting and contradicting evidence with a 0..1 agreement
score. The overall score is a weighted blend.

CRITICAL: consistency is NEVER converted into an identity certainty. High
consistency is supporting evidence that accounts *behave alike*; it is not proof
they are the same person. The result carries that limitation, and the identity
question is deferred to Entity Fusion under authorization.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from ..models.observation import Observation
from ..models.behavior import ConsistencyFeature, ConsistencyResult
from ..models.confidence import Assertion, AssertionKind, make_confidence
from ..linguistic.language_switching import distribution as language_distribution
from ..content.domain_behavior import analyze_domains
from .. import util
from ..util import seq_similarity as _seq_similarity


# Per-feature weight in the overall consistency blend.
_WEIGHTS = {
    "username": 0.15, "hour_profile": 0.15, "language_mix": 0.2,
    "domain_mix": 0.2, "posting_schedule": 0.1, "topic_mix": 0.1, "avatar": 0.1,
}


def _hour_profile(obs: Sequence[Observation]) -> List[float]:
    h = [0.0] * 24
    for o in obs:
        if o.has_time and o.timestamp_precision.supports_hour:
            h[o.hour_utc] += 1
    return h


def _language_shares(obs: Sequence[Observation]) -> Dict[str, float]:
    return language_distribution(obs).shares


def _domain_shares(obs: Sequence[Observation]) -> Dict[str, float]:
    return util.shares({d.domain: d.frequency for d in analyze_domains(obs, top_n=50)})


def _pairwise_dist_agreement(dists: List[Dict[str, float]]) -> Tuple[float, List[str]]:
    """Mean pairwise histogram-intersection agreement over distributions."""
    if len(dists) < 2:
        return (0.0, [])
    keys = set().union(*[set(d) for d in dists])
    vecs = [[d.get(k, 0.0) for k in keys] for d in dists]
    sims = []
    notes: List[str] = []
    for i in range(len(vecs)):
        for j in range(i + 1, len(vecs)):
            s = util.histogram_intersection(vecs[i], vecs[j])
            sims.append(s)
    return (util.mean(sims), notes)


def compare_accounts(accounts: Dict[str, Sequence[Observation]], *,
                     usernames: Optional[Dict[str, str]] = None,
                     avatar_hashes: Optional[Dict[str, str]] = None,
                     source_count: int = 1) -> ConsistencyResult:
    """Compare two or more accounts. ``accounts`` maps an account label to its
    observations. ``usernames``/``avatar_hashes`` optionally supply those signals
    (else pulled from the label / observation metadata)."""
    labels = list(accounts)
    result = ConsistencyResult(accounts=labels)
    if len(labels) < 2:
        result.overall = 0.0
        return result

    usernames = usernames or {lbl: lbl.split("/")[-1] for lbl in labels}
    avatar_hashes = avatar_hashes or {}

    features: List[ConsistencyFeature] = []

    # username similarity (mean pairwise)
    uf = ConsistencyFeature(name="username")
    us = []
    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            a, b = usernames.get(labels[i], ""), usernames.get(labels[j], "")
            sim = _seq_similarity(a.casefold(), b.casefold())
            us.append(sim)
            (uf.supporting if sim >= 0.6 else uf.contradicting).append(
                f"{a} ~ {b} = {sim:.2f}")
    uf.score = util.mean(us)
    features.append(uf)

    # hour profile agreement
    hf = ConsistencyFeature(name="hour_profile")
    profiles = [_hour_profile(accounts[lbl]) for lbl in labels]
    hf.score, _ = _pairwise_dist_agreement(
        [{str(i): v for i, v in enumerate(p)} for p in profiles])
    (hf.supporting if hf.score >= 0.5 else hf.contradicting).append(
        f"mean hour-of-day overlap {hf.score:.2f}")
    features.append(hf)

    # language mix
    lf = ConsistencyFeature(name="language_mix")
    lang_dists = [_language_shares(accounts[lbl]) for lbl in labels]
    lf.score, _ = _pairwise_dist_agreement(lang_dists)
    (lf.supporting if lf.score >= 0.5 else lf.contradicting).append(
        f"mean language-mix overlap {lf.score:.2f}")
    features.append(lf)

    # domain mix
    df = ConsistencyFeature(name="domain_mix")
    dom_dists = [_domain_shares(accounts[lbl]) for lbl in labels]
    df.score, _ = _pairwise_dist_agreement(dom_dists)
    (df.supporting if df.score >= 0.4 else df.contradicting).append(
        f"mean domain-mix overlap {df.score:.2f}")
    features.append(df)

    # posting schedule (weekday profile)
    sf = ConsistencyFeature(name="posting_schedule")
    wk = []
    for lbl in labels:
        w = [0.0] * 7
        for o in accounts[lbl]:
            if o.has_time:
                w[o.weekday_utc] += 1
        wk.append({str(i): v for i, v in enumerate(w)})
    sf.score, _ = _pairwise_dist_agreement(wk)
    (sf.supporting if sf.score >= 0.5 else sf.contradicting).append(
        f"mean weekday-profile overlap {sf.score:.2f}")
    features.append(sf)

    # avatar hash exact match (supporting only when equal)
    af = ConsistencyFeature(name="avatar")
    hashes = [avatar_hashes.get(lbl) for lbl in labels if avatar_hashes.get(lbl)]
    if len(hashes) >= 2:
        same = len(set(hashes)) == 1
        af.score = 1.0 if same else 0.0
        (af.supporting if same else af.contradicting).append(
            "identical avatar hash" if same else "avatar hashes differ")
    features.append(af)

    result.features = features
    weighted = sum(_WEIGHTS.get(f.name, 0.0) * f.score for f in features)
    total_w = sum(_WEIGHTS.get(f.name, 0.0) for f in features
                  if f.supporting or f.contradicting)
    result.overall = util.safe_div(weighted, total_w) if total_w else 0.0

    conf = make_confidence(
        sample_size=min(len(list(accounts[lbl])) for lbl in labels),
        period_days=30.0, source_count=source_count,
        supporting=[f.name for f in features if f.score >= 0.5],
        contradicting=[f.name for f in features if f.score < 0.3 and
                       (f.supporting or f.contradicting)])
    conf.add_limitation(
        "Behavioural consistency is supporting evidence that accounts behave "
        "alike; it is NOT proof they belong to the same person. Identity "
        "resolution is deferred to Entity Fusion under authorization.", "critical")
    result.assertion = Assertion(
        statement=(f"{len(labels)} accounts show {result.overall:.2f} overall "
                   f"behavioural consistency across {len(features)} signals."),
        kind=AssertionKind.CORRELATED, confidence=conf, tags=["consistency"])
    return result
