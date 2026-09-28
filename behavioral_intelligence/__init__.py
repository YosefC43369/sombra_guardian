"""
behavioral_intelligence/ — the Behavioral Intelligence Engine for Sombra Guardian.

WHAT THIS IS
------------
A subsystem that analyses patterns in publicly-available OSINT/SOCMINT activity:
*when* an actor is publicly active (temporal), *how they write* (linguistic),
*what they post about and link to* (content), *who they publicly interact with*
(social), *what infrastructure they reference* (infrastructure), and *how all of
that deviates from their own baseline* (anomaly) — rendered as an investigation
dossier with evidence, confidence and explicit limitations on every conclusion.

It is built for the same authorized use as the rest of this repository: red-team
reconnaissance of infrastructure you are authorized to assess, authorized
SOCMINT/threat investigations, IOC enrichment and incident-response attribution
— using PUBLIC information only.

CORE PRINCIPLE (enforced in code, not just documented)
------------------------------------------------------
The engine describes *observable behaviour in public information*. It does NOT
determine mental state, diagnosis, personality, criminal intent, guilt, ideology
as identity, or other sensitive attributes. Every analytical output is an
``Assertion`` carrying an ``AssertionKind`` (OBSERVED / CORRELATED / INFERRED /
UNKNOWN), a ``ConfidenceModel`` (sample size, observation period, source count,
supporting and contradicting signals) and explicit ``Limitation`` lines. Peak
activity is stated as a UTC window with its share — never as "the person is
nocturnal". Language use is reported — never nationality. Consistency across
accounts is supporting evidence — never proof of identity.

SCOPE AND POSTURE
-----------------
  * PUBLIC DATA ONLY. Providers are passive and read-only: no authentication
    bypass, no paywalls, no stolen sessions/cookies, no brute force. robots.txt,
    provider terms and rate limits are respected (spec §52).
  * NO BIOMETRICS. Media analysis counts publicly-declared attachments; it does
    no facial recognition or biometric identification.
  * FAIL-CLOSED AUTHORIZATION. ``behavioral_intelligence.authorization`` gates
    every run, delegating to the shared ``entity_fusion`` scope gate so there is
    a single scope decision in the codebase. Account/person-level analysis
    requires an explicit ``allow_person_scope`` tied to a reviewed authorization
    — off by default.

DESIGN
------
Async- and stdlib-first, layered on the ``osint`` framework's HTTP backbone.
``httpx``, ``networkx`` and ``matplotlib`` are optional: the pure analytical core
(temporal, linguistic, content, social, anomaly, scoring, storage, reports) runs
and is fully tested with zero third-party dependencies; the network providers and
plot renderers activate when those libraries are present.

QUICK START
-----------
    from behavioral_intelligence import BehavioralEngine, ObservationBatch
    from behavioral_intelligence.authorization import AuthorizationContext
    from behavioral_intelligence.models import Observation

    engine = BehavioralEngine()
    batch = ObservationBatch([...Observation...], entity_id="actor-7")
    ctx = AuthorizationContext(program_id=7, allow_person_scope=True)
    profile = engine.analyze_entity(batch, ctx)
    print(engine.generate_report(batch, ctx, fmt="markdown"))
"""

from .configuration import BehavioralConfig, get_config
from .authorization import (BehaviorGate, AuthorizationContext, Subject,
                            GateDecision, require, HAVE_FUSION_GATE)
from .models import (Observation, ObservationBatch, Assertion, AssertionKind,
                     ConfidenceModel, EvidenceRef, BehaviorProfile)
from .engine import BehavioralEngine
from .orchestrator import BehavioralOrchestrator, CollectionResult
from .pipeline import IncrementalPipeline, PipelineConfig, PipelineResult
from .scheduler import SnapshotScheduler, SnapshotDiff, diff_snapshots
from .storage import SQLiteStore, ObservationStore
from .cache import CalculationCache, fingerprint

__all__ = [
    "BehavioralConfig", "get_config",
    "BehaviorGate", "AuthorizationContext", "Subject", "GateDecision", "require",
    "HAVE_FUSION_GATE",
    "Observation", "ObservationBatch", "Assertion", "AssertionKind",
    "ConfidenceModel", "EvidenceRef", "BehaviorProfile",
    "BehavioralEngine", "BehavioralOrchestrator", "CollectionResult",
    "IncrementalPipeline", "PipelineConfig", "PipelineResult",
    "SnapshotScheduler", "SnapshotDiff", "diff_snapshots",
    "SQLiteStore", "ObservationStore", "CalculationCache", "fingerprint",
]

__version__ = "1.0.0"
