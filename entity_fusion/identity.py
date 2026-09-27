"""
entity_fusion.identity — the fused identity: one real-world thing assembled from
a cluster of correlated records.

Where ``Entity`` is a single observed record, ``Identity`` is the *conclusion*:
the union of a cluster's members with a chosen canonical representative, the full
alias/source/evidence roll-up, and the attached ``ConfidenceReport`` explaining
how sure the engine is that these records are one thing.

An Identity is what a report renders and what the storage layer persists as the
resolved output of a fusion run.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .entity import Entity, EntityType, new_uuid, merge_entities
from .clustering import Cluster
from .confidence import ConfidenceReport, ConfidenceEngine


@dataclass
class Identity:
    """A correlated real-world entity built from a cluster of records."""
    id: str = field(default_factory=new_uuid)
    label: str = ""
    primary_type: EntityType = EntityType.UNKNOWN
    member_ids: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    values_by_type: Dict[str, List[str]] = field(default_factory=dict)
    providers: List[str] = field(default_factory=list)
    confidence: Optional[ConfidenceReport] = None
    fused: Optional[Entity] = None      # the merged super-entity (full provenance)

    @property
    def score(self) -> float:
        return self.confidence.score if self.confidence else 0.0

    @property
    def band(self) -> str:
        return self.confidence.band if self.confidence else "insufficient"

    def value_of(self, entity_type: str) -> List[str]:
        return self.values_by_type.get(str(entity_type), [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "primary_type": self.primary_type.value,
            "score": round(self.score, 1),
            "band": self.band,
            "member_ids": self.member_ids,
            "aliases": self.aliases,
            "values_by_type": self.values_by_type,
            "providers": self.providers,
            "confidence": self.confidence.to_dict() if self.confidence else None,
        }

    def summary(self) -> str:
        return (f"identity[{self.primary_type.value}] {self.label!r} "
                f"({len(self.member_ids)} records, {self.band} {self.score:.0f}/100)")


class IdentityBuilder:
    """Turn a ``Cluster`` into an ``Identity``, running the confidence engine and
    choosing a sensible canonical label."""

    def __init__(self, confidence_engine: Optional[ConfidenceEngine] = None):
        self.confidence_engine = confidence_engine or ConfidenceEngine()

    def build(self, cluster: Cluster) -> Identity:
        members = cluster.members
        report = self.confidence_engine.assess(cluster)

        values_by_type: Dict[str, List[str]] = {}
        providers: set = set()
        aliases: set = set()
        for m in members:
            values_by_type.setdefault(m.type.value, [])
            if m.value and m.value not in values_by_type[m.type.value]:
                values_by_type[m.type.value].append(m.value)
            providers |= m.providers
            aliases |= m.aliases

        primary_type = self._primary_type(members)
        label = self._label(members, primary_type)
        # Fold members into one super-entity so downstream code has the full,
        # provenance-preserving union available (graph nodes, evidence appendix).
        fused = merge_entities([Entity.from_dict(m.to_dict()) for m in members],
                               note="identity fusion")
        if fused is not None:
            fused.confidence = report.score

        return Identity(
            label=label,
            primary_type=primary_type,
            member_ids=[m.id for m in members],
            aliases=sorted(a for a in aliases if a and a != label),
            values_by_type=values_by_type,
            providers=sorted(providers),
            confidence=report,
            fused=fused,
        )

    @staticmethod
    def _primary_type(members: List[Entity]) -> EntityType:
        """The 'headline' type. Prefer PERSON/ORGANIZATION when present (they are
        the subject of an investigation), else the most common concrete type."""
        types = [m.type for m in members if m.type != EntityType.UNKNOWN]
        for preferred in (EntityType.PERSON, EntityType.ORGANIZATION):
            if preferred in types:
                return preferred
        if not types:
            return EntityType.UNKNOWN
        return Counter(types).most_common(1)[0][0]

    @staticmethod
    def _label(members: List[Entity], primary_type: EntityType) -> str:
        """Choose a human label: a display name if any member has one, else the
        value of a member of the primary type, else the first non-empty value."""
        for m in members:
            for key in ("display_name", "name", "full_name"):
                if m.metadata.get(key):
                    return str(m.metadata[key])
        for m in members:
            if m.type == primary_type and m.value:
                return m.value
        for m in members:
            if m.value:
                return m.value
        return "unknown"


def identities_from_clusters(clusters: List[Cluster],
                             builder: Optional[IdentityBuilder] = None) -> List[Identity]:
    builder = builder or IdentityBuilder()
    identities = [builder.build(c) for c in clusters]
    identities.sort(key=lambda i: (-i.score, -len(i.member_ids)))
    return identities
