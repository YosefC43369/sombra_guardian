"""
cybersecurity_intelligence — the CTI Analysis Engine for Sombra Guardian.

This package is the *analytic layer* that sits on top of
``threat_actor_intelligence``. It does not re-implement ingestion, IOC/CVE
extraction, the MITRE knowledge base, storage of actors/campaigns/malware or the
graph — those already exist and are reused verbatim (see
``threat_actor_intelligence.models.evidence`` and ``.confidence``). What this
package adds is the discipline that turns collected public data into *finished
intelligence*:

  * source-reliability grading (HIGH / MEDIUM / LOW / UNKNOWN, always with the
    reasons that produced the grade — never an absolute "true/false" verdict);
  * an explicit ``Claim`` taxonomy — OBSERVED / REPORTED / CORROBORATED /
    INFERRED / DISPUTED / UNKNOWN — so a single-source report is never silently
    promoted to a confirmed fact;
  * cross-source corroboration with independence checks, so twenty copies of one
    wire story do not count as twenty pieces of evidence;
  * contradiction detection across claims (conflicting attribution, timelines,
    exploitation status, …), surfaced rather than resolved unilaterally;
  * explainable confidence built on the existing ``ConfidenceModel``;
  * structured assessments that separate FACT, SOURCE CLAIM, ANALYTIC INFERENCE
    and UNCERTAINTY.

Everything is standard-library only, deterministic, and offline-testable. The
public surface is intentionally small and stable; import engines/models directly
for finer control.

Design guardrails (enforced in code, not just documented):
  * Evidence first — every claim carries at least one ``EvidenceRef``.
  * Provenance everywhere — a claim can always be traced to its source(s).
  * Correlation before conclusion; confidence before assertion.
  * No single signal (shared IP, shared name, shared country) is ever treated as
    definitive attribution.
"""

from __future__ import annotations

from .config import CTIConfig, get_config
from .constants import (
    ReliabilityGrade,
    Priority,
    ProductType,
    AssessmentStatementType,
)
from .exceptions import (
    CTIError,
    CTIConfigError,
    CTIStorageError,
    CTITransformError,
)
from .models.claim import Claim, ClaimType
from .models.source import SourceRecord, ReliabilityAssessment
from .models.contradiction import Contradiction, ContradictionType
from .models.assessment import Assessment, AssessmentStatement
from .engine import CTIAnalysisEngine, AnalysisResult
from .storage import CTIStore
from .transform import ArticleTransformer

__all__ = [
    "CTIConfig",
    "get_config",
    "CTIAnalysisEngine",
    "AnalysisResult",
    "CTIStore",
    "ArticleTransformer",
    "ReliabilityGrade",
    "Priority",
    "ProductType",
    "AssessmentStatementType",
    "CTIError",
    "CTIConfigError",
    "CTIStorageError",
    "CTITransformError",
    "Claim",
    "ClaimType",
    "SourceRecord",
    "ReliabilityAssessment",
    "Contradiction",
    "ContradictionType",
    "Assessment",
    "AssessmentStatement",
]

__version__ = "2.0.0"
