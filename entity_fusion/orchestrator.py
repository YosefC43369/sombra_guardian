"""
entity_fusion.orchestrator — the top-level façade that turns a pile of OSINT
records into a set of correlated identities.

This is the one call most callers need:

    engine = FusionEngine()
    result = engine.fuse(records, ctx=AuthorizationContext(program_id=7,
                                                            allow_person_scope=True))
    for identity in result.identities:
        print(identity.summary())

Pipeline stages, in order:

    records/entities
        → normalization      (canonical values, per entity type)
        → authorization gate (fail-closed; drops out-of-scope entities)
        → clustering         (blocking + similarity + union-find)
        → identity building  (confidence scoring, canonical label)
        → graph              (relationship graph with same_as edges)

Authorization runs *before* correlation so out-of-scope records never enter the
similarity engine at all — scope is enforced, not merely reported. The engine is
synchronous and pure over its inputs; the async, network-touching discovery of
*new* records lives in ``entity_fusion.pipeline``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union

from .entity import Entity
from . import normalization as norm
from .authorization import AuthorizationContext, FusionGate, GateDecision
from .clustering import Clusterer, ClusterReport
from .confidence import ConfidenceEngine
from .identity import Identity, IdentityBuilder, identities_from_clusters
from .graph import IdentityGraph
from .similarity import SimilarityEngine

RecordOrEntity = Union[Entity, Dict[str, Any]]


@dataclass
class FusionResult:
    identities: List[Identity] = field(default_factory=list)
    denied: List[GateDecision] = field(default_factory=list)
    cluster_report: Optional[ClusterReport] = None
    graph: Optional[IdentityGraph] = None
    started_at: float = 0.0
    finished_at: float = 0.0
    input_count: int = 0

    @property
    def elapsed_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    def stats(self) -> Dict[str, Any]:
        return {
            "input_records": self.input_count,
            "authorized": sum(len(i.member_ids) for i in self.identities),
            "denied": len(self.denied),
            "identities": len(self.identities),
            "multi_record_identities": sum(1 for i in self.identities
                                           if len(i.member_ids) > 1),
            "clusters": self.cluster_report.stats() if self.cluster_report else {},
            "graph": self.graph.stats() if self.graph else {},
            "elapsed_ms": self.elapsed_ms,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats(),
            "identities": [i.to_dict() for i in self.identities],
            "denied": [d.to_dict() for d in self.denied],
        }

    def top(self, n: int = 10) -> List[Identity]:
        return self.identities[:n]


class FusionEngine:
    """Correlate records into identities under an authorization context."""

    def __init__(self, *,
                 similarity: Optional[SimilarityEngine] = None,
                 clusterer: Optional[Clusterer] = None,
                 confidence: Optional[ConfidenceEngine] = None,
                 gate: Optional[FusionGate] = None,
                 default_cc: str = "",
                 build_graph: bool = True,
                 apply_engines: bool = True):
        self.similarity = similarity or SimilarityEngine()
        self.clusterer = clusterer or Clusterer(self.similarity)
        self.confidence = confidence or ConfidenceEngine()
        self.gate = gate or FusionGate()
        self.identity_builder = IdentityBuilder(self.confidence)
        self.default_cc = default_cc
        self.build_graph = build_graph
        # Offline engines derive correlation keys and extract identifiers
        # embedded in records (an email in a bio, a wallet on a contact page).
        self.apply_engines = apply_engines
        self._engines = None
        if apply_engines:
            from .engines import default_engines
            self._engines = default_engines()

    # -- normalization ----------------------------------------------------- #

    def _to_entity(self, item: RecordOrEntity) -> Entity:
        ent = item if isinstance(item, Entity) else Entity.from_record(dict(item))
        # (re)compute the canonical value for the entity's type
        canon = norm.normalize_value(ent.type.value, ent.value,
                                     default_cc=self.default_cc)
        if canon:
            ent.normalized = canon
        # enrich a few metadata fields into canonical helpers for similarity
        if ent.metadata.get("email"):
            ce = norm.canonical_email(str(ent.metadata["email"]))
            if ce:
                ent.metadata.setdefault("email", ce)
        return ent

    def normalize(self, items: Sequence[RecordOrEntity]) -> List[Entity]:
        """Lift, canonicalize, and (optionally) run offline engines over every
        input. Engines fold derived metadata/evidence onto each entity and may
        extract embedded identifiers as *new* entities (a bio email, a wallet on
        a contact page); those are appended to the candidate set so they too are
        correlated. De-duplicated by (type, normalized)."""
        entities = [self._to_entity(i) for i in items]
        if not self._engines:
            return entities

        from .engines import run_engines
        from .entity import Relationship, RelationType
        by_key = {(e.type.value, e.normalized): e for e in entities}
        discovered: List[Entity] = []
        for ent in list(entities):
            for child in run_engines(ent, self._engines):
                canon = norm.normalize_value(child.type.value, child.value,
                                             default_cc=self.default_cc)
                if canon:
                    child.normalized = canon
                # link the discovered identifier back to its parent record
                child.add_relationship(Relationship(
                    target_id=ent.id, type=RelationType.APPEARED_IN))
                key = (child.type.value, child.normalized)
                existing = by_key.get(key)
                if existing is None:
                    by_key[key] = child
                    discovered.append(child)
                elif existing is not child:
                    # a duplicate of an already-known entity: merge provenance and
                    # relationships into it rather than dropping the discovery.
                    existing.merge(child, note="engine-extracted duplicate")
        return entities + discovered

    # -- the pipeline ------------------------------------------------------ #

    def fuse(self, items: Sequence[RecordOrEntity],
             ctx: Optional[AuthorizationContext] = None) -> FusionResult:
        """Run the full correlation pipeline. ``ctx`` governs scope; if omitted,
        a fail-closed empty context is used (which authorizes nothing except via
        an explicit dev override), keeping the default safe."""
        ctx = ctx or AuthorizationContext()
        result = FusionResult(started_at=time.monotonic(), input_count=len(items))

        entities = self.normalize(items)
        allowed, denied = self.gate.partition(ctx, entities)
        result.denied = denied

        if not allowed:
            result.finished_at = time.monotonic()
            result.cluster_report = ClusterReport(clusters=[],
                                                   threshold=self.clusterer.threshold)
            if self.build_graph:
                result.graph = IdentityGraph()
            return result

        report = self.clusterer.cluster(allowed)
        result.cluster_report = report
        result.identities = identities_from_clusters(report.clusters,
                                                      self.identity_builder)

        if self.build_graph:
            graph = IdentityGraph().build_from_entities(allowed)
            for ident in result.identities:
                graph.link_cluster(ident.member_ids)
            result.graph = graph

        result.finished_at = time.monotonic()
        return result

    def fuse_records(self, records: Sequence[Dict[str, Any]],
                     ctx: Optional[AuthorizationContext] = None) -> FusionResult:
        """Convenience entry for the loosely-typed record dicts emitted by the
        ``osint`` sources and SOCMINT modules."""
        return self.fuse(records, ctx=ctx)
