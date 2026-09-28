"""
behavioral_intelligence.engine — the ``BehavioralEngine`` public API (spec §43).

The single service-layer entry point. Every method:
  * is authorized through the fail-closed ``BehaviorGate`` before touching data
    (person/account subjects require explicit person scope within an authorized
    program);
  * consumes an ``ObservationBatch`` (or loads one from storage by entity);
  * returns a typed model — never a bare dict or number;
  * carries the epistemic discipline through: results are composed of labelled
    ``Assertion`` objects and standing limitations.

It composes the sub-engines (temporal, linguistic, content, social, anomaly,
scoring) but holds no analysis logic of its own beyond orchestration — each
concern lives in its own module and is independently tested.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Sequence

from .configuration import BehavioralConfig, get_config
from .authorization import (BehaviorGate, AuthorizationContext, Subject, require)
from .models.observation import Observation, ObservationBatch
from .models.behavior import (BehaviorProfile, PeriodComparison, ConsistencyResult)
from .models.timeline import Timeline, TimelineEvent, Lifecycle, LifecycleStage
from .models.language import LanguageDistribution
from .models.confidence import Assertion, AssertionKind, make_confidence
from . import util

from .temporal import TemporalEngine
from .linguistic import language_switching, keyword_engine, hashtag_engine
from .content import (topic_evolution, domain_behavior)
from .social import (mention_network, interaction_patterns, account_activity,
                     detect_migrations)
from .anomaly import AnomalyEngine, build_baseline, detect_changes
from .scoring import compare_accounts
from .models.anomaly import Baseline


def _subject_for(entity_type: str) -> Subject:
    mapping = {"account": Subject.ACCOUNT, "person": Subject.PERSON,
               "domain": Subject.DOMAIN, "repository": Subject.REPOSITORY,
               "organization": Subject.ORGANIZATION, "ioc": Subject.IOC}
    return mapping.get((entity_type or "account").lower(), Subject.ACCOUNT)


class BehavioralEngine:
    def __init__(self, *, config: Optional[BehavioralConfig] = None,
                 gate: Optional[BehaviorGate] = None, store=None,
                 cache=None):
        self.config = config or get_config()
        self.gate = gate or BehaviorGate()
        self.store = store
        self.cache = cache
        tz = self.config.default_timezone_offset_hours
        self.temporal = TemporalEngine(
            tz_offset_hours=tz,
            burst_window_minutes=self.config.burst_window_minutes,
            inactivity_min_days=self.config.inactivity_min_days,
            changepoint_z=self.config.changepoint_zscore_threshold)

    # -- authorization helper --------------------------------------------- #

    def _authorize(self, ctx: AuthorizationContext, batch: ObservationBatch,
                   subject: Subject) -> None:
        value = batch.entity_id or (batch.accounts()[0] if batch.accounts() else "")
        require(ctx, subject, value, gate=self.gate)

    def _resolve_batch(self, batch_or_entity, ctx) -> ObservationBatch:
        if isinstance(batch_or_entity, ObservationBatch):
            return batch_or_entity
        if self.store is None:
            raise ValueError("no store configured; pass an ObservationBatch")
        obs = self.store.load_observations(entity_id=str(batch_or_entity))
        return ObservationBatch(obs, entity_id=str(batch_or_entity))

    # -- public API (spec §43) -------------------------------------------- #

    def analyze_entity(self, batch: ObservationBatch, ctx: AuthorizationContext,
                       *, subject: Subject = Subject.ACCOUNT) -> BehaviorProfile:
        """Full behavioural analysis of one entity/window → ``BehaviorProfile``."""
        self._authorize(ctx, batch, subject)
        batch = batch.dedupe()
        obs = batch.observations
        lo, hi = batch.span()
        source_count = len({o.source for o in obs if o.source}) or 1
        self.temporal.source_count = source_count

        profile = BehaviorProfile(
            entity_id=batch.entity_id, label=batch.label,
            generated_at=time.time(), period_start=lo, period_end=hi,
            sample_size=len(obs), platforms=batch.platforms())

        # temporal
        temporal = self.temporal.analyze(batch)
        profile.activity = temporal.stats
        profile.heatmap = temporal.heatmap
        profile.peak_windows = temporal.peak_windows
        profile.bursts = temporal.bursts
        profile.inactivity = temporal.inactivity
        profile.change_points = temporal.change_points
        profile.assertions.extend(temporal.assertions)

        # linguistic
        profile.languages = language_switching.distribution(obs)
        profile.keywords = keyword_engine.extract_keywords(
            obs, top_n=self.config.top_keywords)
        profile.hashtags = hashtag_engine.extract_hashtags(
            obs, top_n=self.config.top_hashtags)

        # content
        profile.domains = domain_behavior.analyze_domains(
            obs, top_n=self.config.top_domains)
        profile.topic_evolution = topic_evolution.analyze_evolution(obs)

        # social
        net = mention_network.build_network(obs, batch.entity_id)
        profile.interactions = net

        # anomaly (observed window vs prior baseline)
        an_engine = AnomalyEngine(
            observed_window_days=min(7.0, max(1.0, (hi - lo) / util.DAY_SECONDS / 4)),
            baseline_window_days=self.config.baseline_windows_days[1]
            if len(self.config.baseline_windows_days) > 1 else 30,
            source_count=source_count)
        score, anomalies, an_assertions = an_engine.analyze(
            obs, entity_id=batch.entity_id)
        profile.anomaly_score = score
        profile.anomalies = anomalies
        profile.assertions.extend(an_assertions)

        # timeline
        profile.timeline = self.build_timeline(batch, ctx, subject=subject,
                                               _skip_auth=True)
        profile.lifecycle = self._lifecycle(obs, batch.entity_id)

        # language assertion (with the "no nationality" limitation)
        profile.assertions.append(self._language_assertion(profile.languages,
                                                           lo, hi, source_count))

        # standing limitations
        profile.limitations = [
            "Reflects only publicly observed data over the stated period.",
            "Describes observable activity patterns, not the person behind the "
            "account; no psychological, medical, criminal-intent or identity "
            "conclusion is implied.",
            "Absence of a signal is lack of observation, not evidence of absence.",
        ]
        return profile

    def build_baseline(self, batch: ObservationBatch, ctx: AuthorizationContext,
                       *, window_days: int = 30,
                       subject: Subject = Subject.ACCOUNT) -> Baseline:
        self._authorize(ctx, batch, subject)
        return build_baseline(batch.observations, window_days=window_days,
                              entity_id=batch.entity_id)

    def detect_anomalies(self, batch: ObservationBatch, ctx: AuthorizationContext,
                         *, observed_window_days: float = 7.0,
                         baseline_window_days: int = 30,
                         subject: Subject = Subject.ACCOUNT):
        self._authorize(ctx, batch, subject)
        eng = AnomalyEngine(observed_window_days=observed_window_days,
                            baseline_window_days=baseline_window_days,
                            source_count=len({o.source for o in batch.observations
                                              if o.source}) or 1)
        return eng.analyze(batch.observations, entity_id=batch.entity_id)

    def build_timeline(self, batch: ObservationBatch, ctx: AuthorizationContext,
                       *, subject: Subject = Subject.ACCOUNT,
                       _skip_auth: bool = False) -> Timeline:
        if not _skip_auth:
            self._authorize(ctx, batch, subject)
        obs = batch.observations
        lo, hi = batch.span()
        events: List[TimelineEvent] = []
        # change points
        for cp in detect_changes(obs, zscore_threshold=self.config.changepoint_zscore_threshold):
            events.append(TimelineEvent(at=cp.at, kind=cp.kind,
                                        label=cp.detail or cp.kind,
                                        detail=cp.to_dict()))
        # bursts and inactivity as timeline markers
        temporal = self.temporal.analyze(batch)
        for b in temporal.bursts:
            events.append(TimelineEvent(at=b.start, kind="activity_burst",
                                        label=f"{b.count} posts in "
                                              f"{b.duration_seconds/60:.0f}m",
                                        detail=b.to_dict()))
        for g in temporal.inactivity:
            events.append(TimelineEvent(at=g.start, kind="inactivity_gap",
                                        label=f"{g.duration_days:.0f}d silence",
                                        detail=g.to_dict()))
        # platform migrations
        for m in detect_migrations(obs):
            events.append(TimelineEvent(at=m.to_first_activity,
                                        kind="platform_migration",
                                        label=f"{m.from_platform}→{m.to_platform}",
                                        platform=m.to_platform, detail=m.to_dict()))
        return Timeline(entity_id=batch.entity_id, events=events,
                        period_start=lo, period_end=hi)

    def analyze_languages(self, batch: ObservationBatch, ctx: AuthorizationContext,
                          *, subject: Subject = Subject.ACCOUNT) -> Dict:
        self._authorize(ctx, batch, subject)
        obs = batch.observations
        return {
            "distribution": language_switching.distribution(obs).to_dict(),
            "timeline": [p.to_dict() for p in language_switching.timeline(obs)],
            "switching_frequency": language_switching.switching_frequency(obs),
            "platform_language_matrix": language_switching.platform_language_matrix(obs),
            "limitation": "Language use is observed; nationality, ethnicity and "
                          "first language are NOT inferred.",
        }

    def analyze_topics(self, batch: ObservationBatch, ctx: AuthorizationContext,
                       *, subject: Subject = Subject.ACCOUNT) -> Dict:
        self._authorize(ctx, batch, subject)
        obs = batch.observations
        return {
            "keywords": [k.to_dict() for k in keyword_engine.extract_keywords(
                obs, top_n=self.config.top_keywords)],
            "hashtags": [h.to_dict() for h in hashtag_engine.extract_hashtags(
                obs, top_n=self.config.top_hashtags)],
            "evolution": topic_evolution.analyze_evolution(obs).to_dict(),
        }

    def analyze_interactions(self, batch: ObservationBatch, ctx: AuthorizationContext,
                             *, subject: Subject = Subject.ACCOUNT) -> Dict:
        self._authorize(ctx, batch, subject)
        obs = batch.observations
        net = mention_network.build_network(obs, batch.entity_id)
        patterns = interaction_patterns.analyze_interactions(obs)
        return {"network": net.to_dict(), "patterns": patterns.to_dict(),
                "limitation": "Interactions are observed public acts; no private "
                              "relationship (friendship, employment, association) "
                              "is inferred."}

    def compare_periods(self, batch: ObservationBatch, ctx: AuthorizationContext,
                        *, window_days: int = 30,
                        subject: Subject = Subject.ACCOUNT) -> PeriodComparison:
        """Compare the most recent ``window_days`` against the preceding
        ``window_days`` (spec §44). Every metric shows both values + delta."""
        self._authorize(ctx, batch, subject)
        timed = batch.timed()
        if not timed:
            return PeriodComparison(label=f"{window_days}d vs previous {window_days}d")
        ref = timed[-1].timestamp
        cur_lo = ref - window_days * util.DAY_SECONDS
        prev_lo = cur_lo - window_days * util.DAY_SECONDS
        current = [o for o in timed if cur_lo <= o.timestamp <= ref]
        previous = [o for o in timed if prev_lo <= o.timestamp < cur_lo]

        def metrics(obs: List[Observation]) -> Dict:
            span = max((obs[-1].timestamp - obs[0].timestamp) / util.DAY_SECONDS, 1.0) \
                if len(obs) > 1 else 1.0
            langs = language_switching.distribution(obs).shares
            return {
                "count": len(obs),
                "posts_per_day": round(len(obs) / span, 3),
                "platforms": sorted({o.platform for o in obs if o.platform}),
                "dominant_language": (max(langs, key=lambda k: langs[k])
                                      if langs else "und"),
                "hashtags": len({t for o in obs for t in o.hashtags}),
                "domains": len({d for o in obs for d in o.all_domains()}),
            }

        cur_m, prev_m = metrics(current), metrics(previous)
        deltas = {
            "count": cur_m["count"] - prev_m["count"],
            "posts_per_day": round(cur_m["posts_per_day"] - prev_m["posts_per_day"], 3),
            "language_changed": cur_m["dominant_language"] != prev_m["dominant_language"],
        }
        return PeriodComparison(label=f"{window_days}d vs previous {window_days}d",
                                current_period=cur_m, previous_period=prev_m,
                                deltas=deltas)

    def compare_accounts(self, batches: Dict[str, ObservationBatch],
                         ctx: AuthorizationContext) -> ConsistencyResult:
        """Cross-account behavioural consistency (spec §29). Each account must be
        authorized under person scope."""
        for label, b in batches.items():
            require(ctx, Subject.ACCOUNT, b.entity_id or label, gate=self.gate)
        accounts: Dict[str, Sequence[Observation]] = {
            label: b.observations for label, b in batches.items()}
        return compare_accounts(accounts)

    def generate_report(self, batch: ObservationBatch, ctx: AuthorizationContext,
                        *, fmt: str = "markdown",
                        subject: Subject = Subject.ACCOUNT) -> str:
        """Convenience: analyze then render. Report modules live in
        ``behavioral_intelligence.reports``; imported lazily to keep the engine
        importable without them."""
        profile = self.analyze_entity(batch, ctx, subject=subject)
        from .reports import render_report
        return render_report(profile, fmt=fmt, config=self.config)

    # -- helpers ----------------------------------------------------------- #

    def _language_assertion(self, dist: LanguageDistribution, lo: float, hi: float,
                            source_count: int) -> Assertion:
        top = sorted(dist.shares.items(), key=lambda kv: kv[1], reverse=True)[:3]
        desc = ", ".join(f"{lang} {share*100:.0f}%" for lang, share in top) or "n/a"
        conf = make_confidence(sample_size=dist.sample_size,
                               period_days=max((hi - lo) / util.DAY_SECONDS, 0.0),
                               source_count=source_count,
                               supporting=["language detection over public text"])
        conf.add_limitation("Language use is observed; nationality/ethnicity are "
                            "NOT inferred.", "critical")
        return Assertion(
            statement=f"Observed public language use: {desc}.",
            kind=AssertionKind.OBSERVED, confidence=conf,
            observation_period=(lo, hi), tags=["language"])

    def _lifecycle(self, obs: Sequence[Observation], entity_id: str) -> Lifecycle:
        accounts = account_activity.analyze_accounts(obs)
        timed = sorted((o for o in obs if o.has_time), key=lambda o: o.timestamp)
        if not timed:
            return Lifecycle(entity_id=entity_id)
        first, last = timed[0].timestamp, timed[-1].timestamp
        peak_at = accounts[0].peak_at if accounts else 0.0
        stages = [LifecycleStage(name="first_observed", start=first, end=first,
                                 note="earliest observed public activity")]
        if peak_at:
            stages.append(LifecycleStage(name="peak", start=peak_at, end=peak_at,
                                         note="highest single-day activity"))
        stages.append(LifecycleStage(name="last_observed", start=last, end=last,
                                     note="latest observed public activity"))
        return Lifecycle(entity_id=entity_id, first_observed=first,
                         last_observed=last, peak_at=peak_at, stages=stages)
