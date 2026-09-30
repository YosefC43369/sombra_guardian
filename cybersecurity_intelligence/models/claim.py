"""
cybersecurity_intelligence.models.claim — the atom of finished intelligence.

A :class:`Claim` is a single labelled statement about a subject, backed by
evidence and carrying an epistemic *type*. It is deliberately richer than
``threat_actor_intelligence.models.confidence.Assertion``: that module tracks
OBSERVED / CORRELATED / INFERRED / UNKNOWN for the actor engine, while finished
CTI products need to distinguish a single-source *report* from an independently
*corroborated* one, and to mark a *disputed* claim where sources conflict. So
:class:`ClaimType` adds REPORTED, CORROBORATED and DISPUTED, and every claim maps
cleanly back onto the upstream ``AssertionKind`` for interop with the actor
engine's reports and graph.

Invariants (checked in ``validate``):
  * a claim always has a subject and a non-empty statement;
  * a non-UNKNOWN claim carries at least one evidence citation (evidence first).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from threat_actor_intelligence.models.evidence import EvidenceBundle, EvidenceRef
from threat_actor_intelligence.models.confidence import (
    AssertionKind,
    ConfidenceModel,
)

from ..constants import CLAIM_TYPE_CONFIDENCE_CEILING
from ..exceptions import CTIValidationError


class ClaimType(str, Enum):
    """The epistemic status of a claim — the label a reader sees first.

    Promotion between types is *earned*, never assumed: the evidence/confidence
    engine promotes REPORTED → CORROBORATED only when enough *independent*
    sources agree, and marks DISPUTED only when a contradiction is detected. The
    engine never silently turns REPORTED into OBSERVED.
    """
    OBSERVED = "observed"          # the fact is directly present in a source
    REPORTED = "reported"          # a source asserts it (single-source claim)
    CORROBORATED = "corroborated"  # >= N independent sources assert it
    INFERRED = "inferred"          # our analytic interpretation of evidence
    DISPUTED = "disputed"          # sources conflict on this claim
    UNKNOWN = "unknown"            # public data cannot establish it

    @classmethod
    def coerce(cls, raw: Any) -> "ClaimType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN

    @property
    def confidence_ceiling(self) -> float:
        """The maximum confidence this claim type permits regardless of how
        strong the evidence looks. A single-source REPORTED claim can never be
        'very high'; an INFERRED claim is capped below 'high'."""
        return CLAIM_TYPE_CONFIDENCE_CEILING.get(self.value, 1.0)

    def to_assertion_kind(self) -> AssertionKind:
        """Map to the upstream actor-engine taxonomy so a Claim can flow into
        ``threat_actor_intelligence`` reports/graph without losing meaning."""
        return {
            ClaimType.OBSERVED: AssertionKind.OBSERVED,
            ClaimType.REPORTED: AssertionKind.OBSERVED,
            ClaimType.CORROBORATED: AssertionKind.CORRELATED,
            ClaimType.INFERRED: AssertionKind.INFERRED,
            ClaimType.DISPUTED: AssertionKind.INFERRED,
            ClaimType.UNKNOWN: AssertionKind.UNKNOWN,
        }[self]


@dataclass
class ClaimSubject:
    """What a claim is *about*: a typed reference into the intelligence graph.

    ``ref_type`` is one of the record kinds the platform knows (cve, ioc,
    malware, actor, campaign, ttp, infrastructure, relationship, incident, …).
    ``ref_value`` is the canonical identifier/value; ``display`` is the
    human-facing label. A relationship subject uses ``ref_type='relationship'``
    with ``ref_value`` like ``"actor:APT29->malware:SUNBURST"``.
    """
    ref_type: str
    ref_value: str
    display: str = ""

    def key(self) -> str:
        return f"{self.ref_type}:{self.ref_value}".lower()

    def to_dict(self) -> Dict[str, Any]:
        return {"ref_type": self.ref_type, "ref_value": self.ref_value,
                "display": self.display or self.ref_value}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ClaimSubject":
        return cls(ref_type=str(d.get("ref_type", "")),
                   ref_value=str(d.get("ref_value", "")),
                   display=str(d.get("display", "")))


@dataclass
class Claim:
    """One evidence-backed, typed intelligence statement.

    The confidence is not set at construction time — it is computed by
    ``ConfidenceEngine`` from the evidence bundle and the claim type, so scoring
    stays in one place and is identical for every claim.
    """

    subject: ClaimSubject
    statement: str
    claim_type: ClaimType = ClaimType.REPORTED
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[ConfidenceModel] = None
    predicate: str = ""                      # short relation verb, e.g. "exploits"
    observed_at: float = 0.0                 # when the underlying event occurred
    first_seen: float = 0.0                  # first time we recorded this claim
    last_seen: float = 0.0
    tags: List[str] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.claim_type = ClaimType.coerce(self.claim_type)
        now = time.time()
        if not self.first_seen:
            self.first_seen = self.observed_at or now
        if not self.last_seen:
            self.last_seen = max(self.first_seen, self.observed_at)

    @property
    def claim_id(self) -> str:
        """Stable id from the subject + normalized statement, so the same claim
        from two sources deduplicates to one row whose evidence accumulates."""
        basis = f"{self.subject.key()}|{self.predicate.lower()}|" \
                f"{' '.join(self.statement.lower().split())}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]

    @property
    def score(self) -> float:
        return self.confidence.score if self.confidence else 0.0

    @property
    def band(self) -> str:
        return self.confidence.band if self.confidence else "very low"

    def independent_source_count(self) -> int:
        """Distinct providers backing this claim (upper bound on independence;
        the evidence engine applies the finer independence rules)."""
        return self.evidence.distinct_count()

    def validate(self) -> "Claim":
        if not self.subject.ref_value:
            raise CTIValidationError("claim has no subject")
        if not self.statement.strip():
            raise CTIValidationError("claim has an empty statement")
        if self.claim_type is not ClaimType.UNKNOWN and len(self.evidence) == 0:
            raise CTIValidationError(
                f"non-UNKNOWN claim ({self.claim_type.value}) must carry evidence")
        return self

    def merge(self, other: "Claim") -> "Claim":
        """Fold another instance of the same claim into this one: accumulate
        evidence, widen the observed window, union tags. Confidence must be
        recomputed by the caller afterwards."""
        if other.claim_id != self.claim_id:
            raise CTIValidationError("cannot merge claims with different ids")
        self.evidence.extend(list(other.evidence))
        self.first_seen = min(self.first_seen or other.first_seen, other.first_seen or self.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        if other.observed_at and (not self.observed_at or other.observed_at < self.observed_at):
            self.observed_at = other.observed_at
        self.tags = sorted(set(self.tags) | set(other.tags))
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "subject": self.subject.to_dict(),
            "statement": self.statement,
            "predicate": self.predicate,
            "claim_type": self.claim_type.value,
            "assertion_kind": self.claim_type.to_assertion_kind().value,
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "score": round(self.score, 4),
            "band": self.band,
            "independent_sources": self.independent_source_count(),
            "evidence": self.evidence.to_list(),
            "observed_at": self.observed_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": list(self.tags),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Claim":
        c = cls(
            subject=ClaimSubject.from_dict(d.get("subject", {}) or {}),
            statement=str(d.get("statement", "")),
            claim_type=ClaimType.coerce(d.get("claim_type")),
            evidence=EvidenceBundle.from_list(d.get("evidence", []) or []),
            confidence=(ConfidenceModel.from_dict(d["confidence"])
                        if d.get("confidence") else None),
            predicate=str(d.get("predicate", "")),
            observed_at=float(d.get("observed_at", 0.0) or 0.0),
            first_seen=float(d.get("first_seen", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            tags=list(d.get("tags", []) or []),
            detail=dict(d.get("detail", {}) or {}),
        )
        return c

    def render(self) -> str:
        conf = f" (confidence {self.score:.2f} {self.band})" if self.confidence else ""
        return f"[{self.claim_type.value.upper()}] {self.statement}{conf}"


__all__ = ["ClaimType", "ClaimSubject", "Claim"]
