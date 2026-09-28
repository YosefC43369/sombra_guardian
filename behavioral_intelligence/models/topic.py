"""
behavioral_intelligence.models.topic — typed results for content analysis
(keywords, phrases, hashtags, topics, domains, URLs).

All figures are frequencies over an explicit window with first/last-seen
provenance. Topics are described by their observable terms; the engine performs
no psychological or ideological interpretation (spec §12–17).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Tuple


@dataclass
class Keyword:
    term: str = ""
    frequency: int = 0
    tfidf: float = 0.0
    burst_score: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    platforms: List[str] = field(default_factory=list)
    cooccurring: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tfidf"] = round(self.tfidf, 4)
        d["burst_score"] = round(self.burst_score, 3)
        return d


@dataclass
class Phrase:
    text: str = ""
    n: int = 2
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Hashtag:
    tag: str = ""
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    trend: str = "stable"              # rising | declining | stable
    growth: float = 0.0
    cooccurring: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["growth"] = round(self.growth, 3)
        return d


@dataclass
class TopicPeriod:
    period_label: str = ""
    period_start: float = 0.0
    top_terms: List[Tuple[str, float]] = field(default_factory=list)
    sample_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"period_label": self.period_label,
                "period_start": self.period_start,
                "top_terms": [[t, round(w, 4)] for t, w in self.top_terms],
                "sample_size": self.sample_size}


@dataclass
class TopicEvolution:
    """Ordered periods showing how salient terms change over time (spec §15)."""
    periods: List[TopicPeriod] = field(default_factory=list)
    emerged: List[str] = field(default_factory=list)   # terms new in latest period
    faded: List[str] = field(default_factory=list)     # terms gone from latest

    def to_dict(self) -> Dict[str, Any]:
        return {"periods": [p.to_dict() for p in self.periods],
                "emerged": self.emerged, "faded": self.faded}


@dataclass
class DomainStat:
    domain: str = ""
    frequency: int = 0
    url_count: int = 0
    is_shortener: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    platforms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class URLStat:
    url: str = ""
    normalized: str = ""
    domain: str = ""
    frequency: int = 0
    category: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContentReuse:
    """A near-duplicate content pair across posts/platforms (spec §19)."""
    hash_a: str = ""
    hash_b: str = ""
    source_a: str = ""
    source_b: str = ""
    similarity: float = 0.0
    method: str = ""                   # sha256 | simhash | minhash | cosine
    timestamp_a: float = 0.0
    timestamp_b: float = 0.0
    temporal_distance: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["similarity"] = round(self.similarity, 3)
        d["temporal_distance"] = round(self.temporal_distance, 1)
        return d
