"""
behavioral_intelligence.models.behavior — top-level aggregate result plus
interaction / network / consistency models.

``BehaviorProfile`` is what ``BehavioralEngine.analyze_entity`` returns: the
composed result of every sub-engine over one entity and window, expressed as
labelled ``Assertion`` objects so the epistemic status of every statement is
carried through to reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .activity import ActivityStats, Heatmap, ActivityWindow, Burst, InactivityGap
from .language import LanguageDistribution
from .topic import Keyword, Hashtag, DomainStat, TopicEvolution
from .timeline import Timeline, ChangePoint, Lifecycle
from .anomaly import AnomalyScore, Anomaly
from .confidence import Assertion


@dataclass
class InteractionEdge:
    """A directed public interaction A → B (mention/reply/quote) (spec §20–22)."""
    source: str = ""
    target: str = ""
    count: int = 0
    kinds: Dict[str, int] = field(default_factory=dict)  # mention/reply/quote counts
    first_seen: float = 0.0
    last_seen: float = 0.0
    platforms: List[str] = field(default_factory=list)
    sample_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InteractionNetwork:
    """A directed interaction graph with derived, non-relational metrics only.
    The engine reports degrees/reciprocity, never friendship/employment/etc."""
    entity_id: str = ""
    edges: List[InteractionEdge] = field(default_factory=list)
    node_in_degree: Dict[str, int] = field(default_factory=dict)
    node_out_degree: Dict[str, int] = field(default_factory=dict)
    reciprocity: float = 0.0
    communities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "edges": [e.to_dict() for e in self.edges],
            "node_in_degree": self.node_in_degree,
            "node_out_degree": self.node_out_degree,
            "reciprocity": round(self.reciprocity, 3),
            "communities": self.communities,
        }


@dataclass
class ConsistencyFeature:
    name: str = ""
    supporting: List[str] = field(default_factory=list)
    contradicting: List[str] = field(default_factory=list)
    score: float = 0.0                 # 0..1 agreement across compared accounts

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["score"] = round(self.score, 3)
        return d


@dataclass
class ConsistencyResult:
    """Cross-account behavioural consistency (spec §29). Never converts
    consistency into an identity certainty — supporting evidence only."""
    accounts: List[str] = field(default_factory=list)
    features: List[ConsistencyFeature] = field(default_factory=list)
    overall: float = 0.0
    assertion: Optional[Assertion] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accounts": self.accounts,
            "features": [f.to_dict() for f in self.features],
            "overall": round(self.overall, 3),
            "assertion": self.assertion.to_dict() if self.assertion else None,
        }


@dataclass
class PeriodComparison:
    """Compare two windows (spec §44). Every metric shows both values + delta."""
    label: str = ""
    current_period: Dict[str, Any] = field(default_factory=dict)
    previous_period: Dict[str, Any] = field(default_factory=dict)
    deltas: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BehaviorProfile:
    """The composed behavioural analysis of one entity over one window."""
    entity_id: str = ""
    label: str = ""
    generated_at: float = 0.0
    period_start: float = 0.0
    period_end: float = 0.0
    sample_size: int = 0
    platforms: List[str] = field(default_factory=list)

    # sub-results (each optional; a run may not compute all of them)
    activity: Optional[ActivityStats] = None
    heatmap: Optional[Heatmap] = None
    peak_windows: List[ActivityWindow] = field(default_factory=list)
    bursts: List[Burst] = field(default_factory=list)
    inactivity: List[InactivityGap] = field(default_factory=list)
    languages: Optional[LanguageDistribution] = None
    keywords: List[Keyword] = field(default_factory=list)
    hashtags: List[Hashtag] = field(default_factory=list)
    domains: List[DomainStat] = field(default_factory=list)
    topic_evolution: Optional[TopicEvolution] = None
    timeline: Optional[Timeline] = None
    change_points: List[ChangePoint] = field(default_factory=list)
    lifecycle: Optional[Lifecycle] = None
    interactions: Optional[InteractionNetwork] = None
    anomaly_score: Optional[AnomalyScore] = None
    anomalies: List[Anomaly] = field(default_factory=list)

    # every headline finding is also emitted as a labelled assertion
    assertions: List[Assertion] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    provider_status: List[Dict[str, Any]] = field(default_factory=list)

    def add_assertion(self, assertion: Assertion) -> None:
        self.assertions.append(assertion)

    def observed(self) -> List[Assertion]:
        from .confidence import AssertionKind
        return [a for a in self.assertions if a.kind == AssertionKind.OBSERVED]

    def to_dict(self) -> Dict[str, Any]:
        def dd(x: Any) -> Any:
            return x.to_dict() if hasattr(x, "to_dict") else x
        return {
            "entity_id": self.entity_id,
            "label": self.label,
            "generated_at": self.generated_at,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "sample_size": self.sample_size,
            "platforms": self.platforms,
            "activity": dd(self.activity) if self.activity else None,
            "heatmap": dd(self.heatmap) if self.heatmap else None,
            "peak_windows": [w.to_dict() for w in self.peak_windows],
            "bursts": [b.to_dict() for b in self.bursts],
            "inactivity": [g.to_dict() for g in self.inactivity],
            "languages": dd(self.languages) if self.languages else None,
            "keywords": [k.to_dict() for k in self.keywords],
            "hashtags": [h.to_dict() for h in self.hashtags],
            "domains": [d.to_dict() for d in self.domains],
            "topic_evolution": dd(self.topic_evolution) if self.topic_evolution else None,
            "timeline": dd(self.timeline) if self.timeline else None,
            "change_points": [c.to_dict() for c in self.change_points],
            "lifecycle": dd(self.lifecycle) if self.lifecycle else None,
            "interactions": dd(self.interactions) if self.interactions else None,
            "anomaly_score": dd(self.anomaly_score) if self.anomaly_score else None,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "assertions": [a.to_dict() for a in self.assertions],
            "limitations": self.limitations,
            "provider_status": self.provider_status,
        }
