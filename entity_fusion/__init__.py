"""
entity_fusion/ — the Entity Fusion Engine for Sombra Guardian.

WHAT THIS IS
------------
An identity-correlation framework: given many fragmented OSINT/SOCMINT records
(usernames, emails, phones, domains, IPs, ASNs, certificates, wallets, websites,
GitHub accounts, …), it normalises them, correlates them with an explainable
multi-factor similarity model, clusters records that refer to the same
real-world entity, scores the correlation confidence, builds a relationship
graph, and renders an investigation dossier.

It is built for the same authorized use as the rest of this repository: red-team
reconnaissance of infrastructure you are authorized to assess, SOCMINT/threat
investigations, IOC enrichment and incident-response attribution — using PUBLIC
information only.

SCOPE AND POSTURE (read this)
-----------------------------
This engine inherits, and enforces in code, the deliberate scope line the
``osint`` package already draws: it is asset/infrastructure-oriented, and it is
NOT an unrestricted person-profiling / de-anonymisation tool for arbitrary
private individuals. Concretely:

  * PUBLIC DATA ONLY. Every enricher reads already-public data (certificate
    transparency, public DNS, RDAP, public profiles, public threat feeds). There
    is no credential access, no authentication bypass, no private-profile
    access.
  * NO BIOMETRICS. The avatar correlation is perceptual/cryptographic *hashing*
    of public images (detecting a reused picture); it performs NO facial
    recognition and NO biometric identification of individuals.
  * FAIL-CLOSED AUTHORIZATION. ``entity_fusion.authorization.FusionGate`` gates
    every entity. Infrastructure targets are checked against the repo's reviewed
    ``scope_policy``; person-level correlation additionally requires an explicit,
    separately-set ``allow_person_scope`` flag tied to an authorized program —
    off by default. Nothing correlates outside an authorized program.

DESIGN
------
Async- and stdlib-first, layered on the ``osint`` framework's HTTP backbone
(shared rate limiting / retry). ``networkx`` and ``httpx`` are optional: the pure
correlation core (normalisation, similarity, clustering, confidence, graph
export, storage, reports) runs and is fully tested with zero third-party
dependencies; the network enrichers activate when the HTTP stack is present.

QUICK START
-----------
    from entity_fusion import FusionEngine, AuthorizationContext
    engine = FusionEngine()
    result = engine.fuse(records, ctx=AuthorizationContext(program_id=7,
                                                            allow_person_scope=True))
    print(result.stats())
    for identity in result.top(5):
        print(identity.summary())
"""

from .entity import (Entity, EntityType, RelationType, SourceRef, Evidence,
                     Relationship, merge_entities)
from .authorization import (AuthorizationContext, FusionGate, GateDecision,
                            HAVE_SCOPE_POLICY)
from .similarity import SimilarityEngine, SimilarityResult
from .clustering import Clusterer, Cluster, ClusterReport
from .confidence import ConfidenceEngine, ConfidenceReport
from .identity import Identity, IdentityBuilder, identities_from_clusters
from .graph import IdentityGraph, HAVE_NETWORKX
from .orchestrator import FusionEngine, FusionResult
from .pipeline import RecursivePipeline, PipelineConfig, PipelineResult
from .history import HistoryEngine, TimelineEvent, ChangeKind
from . import normalization

__all__ = [
    "Entity", "EntityType", "RelationType", "SourceRef", "Evidence",
    "Relationship", "merge_entities",
    "AuthorizationContext", "FusionGate", "GateDecision", "HAVE_SCOPE_POLICY",
    "SimilarityEngine", "SimilarityResult",
    "Clusterer", "Cluster", "ClusterReport",
    "ConfidenceEngine", "ConfidenceReport",
    "Identity", "IdentityBuilder", "identities_from_clusters",
    "IdentityGraph", "HAVE_NETWORKX",
    "FusionEngine", "FusionResult",
    "RecursivePipeline", "PipelineConfig", "PipelineResult",
    "HistoryEngine", "TimelineEvent", "ChangeKind",
    "normalization",
]

__version__ = "1.0.0"
