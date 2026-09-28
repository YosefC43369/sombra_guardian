"""
threat_actor_intelligence.correlation.base — shared correlation primitives.

Every correlation engine returns explainable ``Relationship`` objects: an edge
plus the *signal* that produced it, the shared evidence behind it, and a
confidence computed from that evidence via the one shared path. This module holds
the helper that builds such a relationship and the ``CorrelationResult`` wrapper
the orchestrator collects.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models.confidence import (ConfidenceModel, confidence_from_evidence,
                                 AssertionKind, Assertion)
from ..models.evidence import EvidenceBundle, EvidenceRef
from ..models.relation import ObjectType, RelationType, Relationship


def build_relationship(*, src_type: str, src_id: str, rel_type: str,
                       dst_type: str, dst_id: str, signal: str,
                       evidence: Sequence[EvidenceRef], now: Optional[float] = None,
                       weight: float = 1.0) -> Relationship:
    """Construct a confidence-graded relationship from its supporting evidence."""
    now = now if now is not None else time.time()
    bundle = EvidenceBundle()
    for e in evidence:
        bundle.add(e)
    conf: Optional[ConfidenceModel] = None
    if len(bundle):
        conf = confidence_from_evidence(bundle, now=now)
    first = bundle.earliest()
    last = bundle.latest()
    return Relationship(
        src_type=ObjectType.coerce(src_type), src_id=src_id,
        rel_type=RelationType.coerce(rel_type),
        dst_type=ObjectType.coerce(dst_type), dst_id=dst_id,
        signal=signal, weight=weight, confidence=conf, evidence=list(bundle.refs),
        first_seen=first, last_seen=last)


@dataclass
class CorrelationResult:
    """The output of one correlation pass: relationships + human-readable
    assertions + any merge candidates surfaced (alias resolution)."""
    relationships: List[Relationship] = field(default_factory=list)
    assertions: List[Assertion] = field(default_factory=list)
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    def extend(self, other: "CorrelationResult") -> None:
        self.relationships.extend(other.relationships)
        self.assertions.extend(other.assertions)
        self.candidates.extend(other.candidates)

    def add_relationship(self, rel: Relationship) -> None:
        self.relationships.append(rel)

    def top(self, n: int = 20) -> List[Relationship]:
        return sorted(self.relationships, key=lambda r: -r.score)[:n]

    def to_dict(self) -> Dict[str, Any]:
        return {"relationships": [r.to_dict() for r in self.relationships],
                "assertions": [a.to_dict() for a in self.assertions],
                "candidates": list(self.candidates),
                "counts": {"relationships": len(self.relationships),
                           "assertions": len(self.assertions),
                           "candidates": len(self.candidates)}}


def count_multiplier(n: int) -> float:
    """Weight multiplier for the number of shared items backing an overlap: one
    shared item counts for half the attribute's base weight, three or more for
    the full weight. Keeps a single strong shared attribute (infra/campaign)
    above the link threshold while rewarding corroborating overlap."""
    if n <= 0:
        return 0.0
    return min(1.0, 0.5 + 0.25 * (n - 1))


def correlation_assertion(statement: str, kind: str, rels: Sequence[Relationship]
                          ) -> Assertion:
    """Wrap a set of relationships into a single labelled assertion, taking the
    max evidence across them for the confidence."""
    bundle = EvidenceBundle()
    for r in rels:
        for e in r.evidence:
            bundle.add(e)
    conf = confidence_from_evidence(bundle, now=time.time()) if len(bundle) else None
    ev = list(bundle.refs)[:8]
    return Assertion(statement=statement, kind=AssertionKind.coerce(kind),
                     confidence=conf, evidence=ev, tags=["correlation"])


__all__ = ["build_relationship", "CorrelationResult", "correlation_assertion"]
