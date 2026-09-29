"""
cybersecurity_intelligence.models.assessment — finished, structured intelligence.

An :class:`Assessment` is the product the whole pipeline exists to produce. Its
defining feature is that every line is *typed* by epistemic register
(:class:`~cybersecurity_intelligence.constants.AssessmentStatementType`): FACT,
SOURCE CLAIM, ANALYTIC INFERENCE, or UNCERTAINTY. A reader can therefore never
mistake "vendor A linked exploitation to campaign B" (a source claim) for "the
CVE was publicly disclosed" (a fact) or for "the campaigns may share
infrastructure" (an analytic inference). This is the guardrail from spec §26–§27.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from threat_actor_intelligence.models.evidence import EvidenceRef
from threat_actor_intelligence.models.confidence import ConfidenceModel

from ..constants import AssessmentStatementType, Priority, ProductType


@dataclass
class AssessmentStatement:
    """One typed line of an assessment, optionally backed by evidence/claim."""
    statement_type: AssessmentStatementType
    text: str
    claim_id: str = ""
    confidence: Optional[ConfidenceModel] = None
    evidence: List[EvidenceRef] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.statement_type = AssessmentStatementType.coerce(self.statement_type)

    @property
    def score(self) -> float:
        return self.confidence.score if self.confidence else 0.0

    def render(self) -> str:
        label = self.statement_type.value.replace("_", " ").upper()
        conf = f" [{self.confidence.band}]" if self.confidence else ""
        return f"{label}: {self.text}{conf}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "statement_type": self.statement_type.value,
            "text": self.text,
            "claim_id": self.claim_id,
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AssessmentStatement":
        return cls(
            statement_type=AssessmentStatementType.coerce(d.get("statement_type")),
            text=str(d.get("text", "")),
            claim_id=str(d.get("claim_id", "")),
            confidence=(ConfidenceModel.from_dict(d["confidence"])
                        if d.get("confidence") else None),
            evidence=[EvidenceRef.from_dict(e) for e in d.get("evidence", []) or []],
        )


@dataclass
class Assessment:
    """A finished intelligence assessment about one subject."""
    title: str
    subject_key: str
    summary: str = ""                      # BLUF — bottom line up front
    statements: List[AssessmentStatement] = field(default_factory=list)
    overall_confidence: Optional[ConfidenceModel] = None
    priority: Priority = Priority.INFORMATIONAL
    product_types: List[ProductType] = field(default_factory=list)
    contradiction_ids: List[str] = field(default_factory=list)
    knowledge_gaps: List[str] = field(default_factory=list)
    collection_start: float = 0.0
    collection_end: float = 0.0
    created_at: float = field(default_factory=time.time)
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.priority = Priority.coerce(self.priority)
        self.product_types = [ProductType.coerce(p) for p in self.product_types]

    @property
    def assessment_id(self) -> str:
        basis = f"{self.subject_key.lower()}|{int(self.created_at)}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]

    def statements_of(self, stype: AssessmentStatementType
                      ) -> List[AssessmentStatement]:
        stype = AssessmentStatementType.coerce(stype)
        return [s for s in self.statements if s.statement_type is stype]

    @property
    def facts(self) -> List[AssessmentStatement]:
        return self.statements_of(AssessmentStatementType.FACT)

    @property
    def source_claims(self) -> List[AssessmentStatement]:
        return self.statements_of(AssessmentStatementType.SOURCE_CLAIM)

    @property
    def inferences(self) -> List[AssessmentStatement]:
        return self.statements_of(AssessmentStatementType.ANALYTIC_INFERENCE)

    @property
    def uncertainties(self) -> List[AssessmentStatement]:
        return self.statements_of(AssessmentStatementType.UNCERTAINTY)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "title": self.title,
            "subject_key": self.subject_key,
            "summary": self.summary,
            "statements": [s.to_dict() for s in self.statements],
            "overall_confidence": (self.overall_confidence.to_dict()
                                   if self.overall_confidence else None),
            "priority": self.priority.value,
            "product_types": [p.value for p in self.product_types],
            "contradiction_ids": list(self.contradiction_ids),
            "knowledge_gaps": list(self.knowledge_gaps),
            "collection_start": self.collection_start,
            "collection_end": self.collection_end,
            "created_at": self.created_at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Assessment":
        a = cls(
            title=str(d.get("title", "")),
            subject_key=str(d.get("subject_key", "")),
            summary=str(d.get("summary", "")),
            statements=[AssessmentStatement.from_dict(s)
                        for s in d.get("statements", []) or []],
            overall_confidence=(ConfidenceModel.from_dict(d["overall_confidence"])
                                if d.get("overall_confidence") else None),
            priority=Priority.coerce(d.get("priority")),
            product_types=[ProductType.coerce(p) for p in d.get("product_types", []) or []],
            contradiction_ids=list(d.get("contradiction_ids", []) or []),
            knowledge_gaps=list(d.get("knowledge_gaps", []) or []),
            collection_start=float(d.get("collection_start", 0.0) or 0.0),
            collection_end=float(d.get("collection_end", 0.0) or 0.0),
            created_at=float(d.get("created_at", time.time()) or time.time()),
            detail=dict(d.get("detail", {}) or {}),
        )
        return a


__all__ = ["AssessmentStatement", "Assessment"]
