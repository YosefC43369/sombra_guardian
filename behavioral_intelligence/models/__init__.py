"""
behavioral_intelligence.models — the typed vocabulary of the engine.

Every engine consumes ``Observation`` batches and returns the dataclasses
defined here. Nothing in the package returns a bare number or an unlabelled
claim: analytical conclusions are ``Assertion`` objects carrying an
``AssertionKind`` (OBSERVED / CORRELATED / INFERRED / UNKNOWN), a
``ConfidenceModel`` and ``EvidenceRef`` provenance.
"""

from .observation import (
    Observation, ObservationBatch, TimestampPrecision, ContentType,
    normalize_text, content_hash, parse_timestamp, new_id,
)
from .confidence import (
    AssertionKind, Assertion, ConfidenceModel, EvidenceRef, Limitation,
    SourceReliability, SourceType, make_confidence, band_for,
    STANDING_LIMITATIONS,
)
from .activity import (
    ActivityStats, IntervalStats, Histogram, Heatmap, ActivityWindow,
    Burst, InactivityGap, TemporalCorrelation,
)
from .language import (
    LanguageDetection, LanguageDistribution, LanguageTimelinePoint,
    LanguageSwitch, TransliterationMatch,
)
from .topic import (
    Keyword, Phrase, Hashtag, TopicPeriod, TopicEvolution, DomainStat,
    URLStat, ContentReuse,
)
from .timeline import (
    ChangeKind, TimelineEvent, Timeline, ChangePoint, LifecycleStage,
    Lifecycle, PlatformMigration,
)
from .anomaly import (
    Baseline, Deviation, AnomalyScore, Anomaly, Drift, anomaly_band,
    ANOMALY_BANDS,
)
from .behavior import (
    InteractionEdge, InteractionNetwork, ConsistencyFeature, ConsistencyResult,
    PeriodComparison, BehaviorProfile,
)

__all__ = [
    # observation
    "Observation", "ObservationBatch", "TimestampPrecision", "ContentType",
    "normalize_text", "content_hash", "parse_timestamp", "new_id",
    # confidence / epistemics
    "AssertionKind", "Assertion", "ConfidenceModel", "EvidenceRef", "Limitation",
    "SourceReliability", "SourceType", "make_confidence", "band_for",
    "STANDING_LIMITATIONS",
    # activity
    "ActivityStats", "IntervalStats", "Histogram", "Heatmap", "ActivityWindow",
    "Burst", "InactivityGap", "TemporalCorrelation",
    # language
    "LanguageDetection", "LanguageDistribution", "LanguageTimelinePoint",
    "LanguageSwitch", "TransliterationMatch",
    # topic / content
    "Keyword", "Phrase", "Hashtag", "TopicPeriod", "TopicEvolution", "DomainStat",
    "URLStat", "ContentReuse",
    # timeline
    "ChangeKind", "TimelineEvent", "Timeline", "ChangePoint", "LifecycleStage",
    "Lifecycle", "PlatformMigration",
    # anomaly
    "Baseline", "Deviation", "AnomalyScore", "Anomaly", "Drift", "anomaly_band",
    "ANOMALY_BANDS",
    # behavior aggregate
    "InteractionEdge", "InteractionNetwork", "ConsistencyFeature",
    "ConsistencyResult", "PeriodComparison", "BehaviorProfile",
]
