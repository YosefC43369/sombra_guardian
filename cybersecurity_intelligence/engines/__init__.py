"""
cybersecurity_intelligence.engines — the analytic engines.

Each engine does one job and is deterministic and offline-testable:

  * ``SourceReliabilityEngine`` — grade a publisher/citation (with reasons).
  * ``EvidenceEngine``          — consolidate claims, judge source independence,
                                  promote REPORTED → CORROBORATED.
  * ``ConfidenceEngine``        — compute explainable confidence (claim-type
                                  ceiling on top of the evidence model).
  * ``ContradictionEngine``     — detect conflicts across claims (never resolve).
  * ``AssessmentEngine``        — assemble the finished, typed assessment.
"""

from __future__ import annotations

from .source_reliability import SourceReliabilityEngine
from .evidence_engine import EvidenceEngine, registrable_host
from .confidence_engine import ConfidenceEngine
from .contradiction_engine import ContradictionEngine
from .assessment_engine import AssessmentEngine

__all__ = [
    "SourceReliabilityEngine",
    "EvidenceEngine",
    "registrable_host",
    "ConfidenceEngine",
    "ContradictionEngine",
    "AssessmentEngine",
]
