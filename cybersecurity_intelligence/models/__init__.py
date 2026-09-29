"""
cybersecurity_intelligence.models — the analytic data model.

These models layer on top of the provenance/confidence primitives already
defined in ``threat_actor_intelligence.models`` (``EvidenceRef``,
``EvidenceBundle``, ``ConfidenceModel``, ``TLP``, ``SourceClass``) rather than
redefining them, so a citation or a confidence score can move freely between the
actor engine and this analysis layer.
"""

from __future__ import annotations

from .claim import Claim, ClaimType, ClaimSubject
from .source import (
    SourceRecord,
    ReliabilityAssessment,
    ReliabilityFactor,
    source_id_for,
)
from .contradiction import (
    Contradiction,
    ContradictionType,
    ContradictionPosition,
)
from .assessment import Assessment, AssessmentStatement

__all__ = [
    "Claim",
    "ClaimType",
    "ClaimSubject",
    "SourceRecord",
    "ReliabilityAssessment",
    "ReliabilityFactor",
    "source_id_for",
    "Contradiction",
    "ContradictionType",
    "ContradictionPosition",
    "Assessment",
    "AssessmentStatement",
]
