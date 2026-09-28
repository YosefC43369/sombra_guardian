"""
news_intelligence.models.topic — topics, clusters and events.

Three closely-related aggregates the clustering layer produces:

  * ``Topic`` — a labelled theme (a set of keyword/entity terms) that articles
    are scored against ("ransomware", "Ivanti CVE-2024-*", "Volt Typhoon").
  * ``Cluster`` — a group of article ids the engine judges to be about the same
    thing, with the *explaining signals* attached (shared CVE, shared actor,
    semantic similarity) so the grouping is auditable.
  * ``NewsEvent`` — a promoted cluster: an identifiable real-world event
    (a disclosure, a breach report, a campaign write-up) with a title, a time
    window and the corroborating sources.

Every one is explainable: a cluster always says *why* its members are together.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class ClusterKind(str, Enum):
    TOPIC = "topic"
    EVENT = "event"
    CAMPAIGN = "campaign"
    DUPLICATE = "duplicate"

    @classmethod
    def coerce(cls, raw: Any) -> "ClusterKind":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.TOPIC


@dataclass
class Topic:
    label: str
    terms: List[str] = field(default_factory=list)
    entity_keys: List[str] = field(default_factory=list)
    article_ids: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    topic_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.topic_id:
            self.topic_id = "top-" + hashlib.sha256(
                self.label.lower().encode("utf-8")).hexdigest()[:16]

    @property
    def size(self) -> int:
        return len(self.article_ids)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["topic_id"] = self.topic_id
        d["size"] = self.size
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Topic":
        return cls(label=str(d.get("label", "")),
                   terms=list(d.get("terms", []) or []),
                   entity_keys=list(d.get("entity_keys", []) or []),
                   article_ids=list(d.get("article_ids", []) or []),
                   first_seen=float(d.get("first_seen", 0.0) or 0.0),
                   last_seen=float(d.get("last_seen", 0.0) or 0.0),
                   topic_id=str(d.get("topic_id", "")),
                   detail=dict(d.get("detail", {}) or {}))


@dataclass
class Cluster:
    kind: ClusterKind = ClusterKind.TOPIC
    label: str = ""
    article_ids: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)   # WHY these are grouped
    entity_keys: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    source_domains: List[str] = field(default_factory=list)
    confidence: Optional[Dict[str, Any]] = None
    cluster_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = ClusterKind.coerce(self.kind)
        if not self.cluster_id:
            seed = "|".join(sorted(self.article_ids)) or self.label or str(time.time())
            self.cluster_id = "clu-" + hashlib.sha256(
                seed.encode("utf-8")).hexdigest()[:18]

    @property
    def size(self) -> int:
        return len(self.article_ids)

    @property
    def independent_sources(self) -> int:
        return len(set(self.source_domains))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["cluster_id"] = self.cluster_id
        d["size"] = self.size
        d["independent_sources"] = self.independent_sources
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Cluster":
        return cls(kind=ClusterKind.coerce(d.get("kind")),
                   label=str(d.get("label", "")),
                   article_ids=list(d.get("article_ids", []) or []),
                   signals=list(d.get("signals", []) or []),
                   entity_keys=list(d.get("entity_keys", []) or []),
                   first_seen=float(d.get("first_seen", 0.0) or 0.0),
                   last_seen=float(d.get("last_seen", 0.0) or 0.0),
                   source_domains=list(d.get("source_domains", []) or []),
                   confidence=d.get("confidence"),
                   cluster_id=str(d.get("cluster_id", "")),
                   detail=dict(d.get("detail", {}) or {}))


@dataclass
class NewsEvent:
    title: str
    cluster_id: str = ""
    article_ids: List[str] = field(default_factory=list)
    window_start: float = 0.0
    window_end: float = 0.0
    entity_keys: List[str] = field(default_factory=list)
    source_domains: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    is_new: bool = True
    confidence: Optional[Dict[str, Any]] = None
    event_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id:
            seed = self.cluster_id or self.title or str(time.time())
            self.event_id = "evt-" + hashlib.sha256(
                seed.encode("utf-8")).hexdigest()[:18]

    @property
    def corroboration(self) -> int:
        return len(set(self.source_domains))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_id"] = self.event_id
        d["corroboration"] = self.corroboration
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NewsEvent":
        return cls(title=str(d.get("title", "")),
                   cluster_id=str(d.get("cluster_id", "")),
                   article_ids=list(d.get("article_ids", []) or []),
                   window_start=float(d.get("window_start", 0.0) or 0.0),
                   window_end=float(d.get("window_end", 0.0) or 0.0),
                   entity_keys=list(d.get("entity_keys", []) or []),
                   source_domains=list(d.get("source_domains", []) or []),
                   signals=list(d.get("signals", []) or []),
                   is_new=bool(d.get("is_new", True)),
                   confidence=d.get("confidence"),
                   event_id=str(d.get("event_id", "")),
                   detail=dict(d.get("detail", {}) or {}))


__all__ = ["ClusterKind", "Topic", "Cluster", "NewsEvent"]
