"""
news_intelligence.correlation.base — the correlation contract + relationship output.

A correlation is an *explainable, evidence-backed* relationship between two things
the corpus mentions (two articles, an actor and a malware family, an IOC across
sources, …). Every correlation the engine emits is a ``NewsRelationship`` carrying:
its endpoints, a relation type, the shared signals that justify it, the supporting
evidence, and a computed confidence. Nothing is asserted as fact; a correlation is
"these co-occur in public reporting", never "X did Y".
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..models.evidence import EvidenceBundle
from ..models.confidence import news_confidence, ConfidenceModel, AssertionKind


@dataclass
class NewsRelationship:
    src_type: str
    src_key: str
    dst_type: str
    dst_key: str
    rel_type: str
    kind: str = AssertionKind.CORRELATED.value
    signals: List[str] = field(default_factory=list)
    article_ids: List[str] = field(default_factory=list)
    source_domains: List[str] = field(default_factory=list)
    weight: float = 0.0
    confidence: Optional[Dict[str, Any]] = None
    rel_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rel_id:
            seed = f"{self.src_key}|{self.rel_type}|{self.dst_key}"
            self.rel_id = "rel-" + hashlib.sha256(
                seed.encode("utf-8")).hexdigest()[:20]

    @property
    def independent_sources(self) -> int:
        return len(set(self.source_domains))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["rel_id"] = self.rel_id
        d["independent_sources"] = self.independent_sources
        return d


class BaseCorrelator:
    name = "base"

    def __init__(self, store, *, now: Optional[float] = None,
                 min_confidence: float = 0.30):
        self.store = store
        self.now = now or time.time()
        self.min_confidence = min_confidence

    def _score(self, bundle: EvidenceBundle) -> ConfidenceModel:
        return news_confidence(bundle, now=self.now)

    def persist(self, rels: List[NewsRelationship]) -> int:
        n = 0
        for r in rels:
            self.store.save_relationship(
                rel_id=r.rel_id, src_type=r.src_type, src_key=r.src_key,
                dst_type=r.dst_type, dst_key=r.dst_key, rel_type=r.rel_type,
                weight=r.weight, detail=r.to_dict())
            n += 1
        return n


__all__ = ["NewsRelationship", "BaseCorrelator"]
