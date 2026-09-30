"""
cybersecurity_intelligence.engines.assessment_engine — finished intelligence.

Takes the consolidated, scored claims (and any contradictions) about one subject
and produces a structured :class:`Assessment`: a BLUF, an explainable overall
confidence, an operational priority, the product tiers it serves, and — the core
discipline — every finding sorted into its epistemic register (FACT / SOURCE
CLAIM / ANALYTIC INFERENCE / UNCERTAINTY) so nothing analytic masquerades as fact
(spec §26–§27).

Priority is derived only from *defensive* signals present in the evidence
(exploitation reported, severity, known-ransomware association) and never from any
judgement about an actor's intent (spec §57). Every priority carries its reason.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Sequence

from threat_actor_intelligence.models.confidence import (
    ConfidenceModel,
    Limitation,
    confidence_from_evidence,
)
from threat_actor_intelligence.models.evidence import EvidenceBundle

from ..constants import AssessmentStatementType, Priority, ProductType
from ..models.assessment import Assessment, AssessmentStatement
from ..models.claim import Claim, ClaimType
from ..models.contradiction import Contradiction

# claim type -> assessment statement register
_REGISTER = {
    ClaimType.OBSERVED: AssessmentStatementType.FACT,
    ClaimType.REPORTED: AssessmentStatementType.SOURCE_CLAIM,
    ClaimType.CORROBORATED: AssessmentStatementType.SOURCE_CLAIM,
    ClaimType.INFERRED: AssessmentStatementType.ANALYTIC_INFERENCE,
    ClaimType.DISPUTED: AssessmentStatementType.SOURCE_CLAIM,
    ClaimType.UNKNOWN: AssessmentStatementType.UNCERTAINTY,
}

# subject ref_type -> the CTI product tiers it naturally serves
_PRODUCT_TIERS: Dict[str, List[ProductType]] = {
    "cve": [ProductType.TECHNICAL, ProductType.TACTICAL],
    "vulnerability": [ProductType.TECHNICAL, ProductType.TACTICAL],
    "ioc": [ProductType.TECHNICAL],
    "ip": [ProductType.TECHNICAL],
    "domain": [ProductType.TECHNICAL],
    "url": [ProductType.TECHNICAL],
    "hash": [ProductType.TECHNICAL],
    "sha256": [ProductType.TECHNICAL],
    "ttp": [ProductType.TACTICAL],
    "technique": [ProductType.TACTICAL],
    "malware": [ProductType.TACTICAL, ProductType.OPERATIONAL],
    "actor": [ProductType.OPERATIONAL],
    "campaign": [ProductType.OPERATIONAL],
    "infrastructure": [ProductType.TECHNICAL, ProductType.OPERATIONAL],
    "incident": [ProductType.OPERATIONAL],
    "sector": [ProductType.STRATEGIC],
    "trend": [ProductType.STRATEGIC],
}

_EXPLOITED_STATUSES = {"exploited", "active exploitation", "in the wild",
                       "actively exploited", "known exploited"}
_CRITICAL_SEVERITIES = {"critical"}
_HIGH_SEVERITIES = {"high", "important"}


class AssessmentEngine:
    """Builds a structured assessment for a single subject."""

    def __init__(self, *, now: Optional[float] = None) -> None:
        self._now = now

    def _clock(self) -> float:
        return self._now if self._now is not None else time.time()

    def build(self, subject_key: str, subject_display: str,
              claims: Sequence[Claim],
              *, contradictions: Optional[Sequence[Contradiction]] = None,
              title: str = "") -> Assessment:
        contradictions = list(contradictions or [])
        subject_claims = [c for c in claims if c.subject.key() == subject_key]

        statements = [self._statement_for(c) for c in subject_claims]
        overall = self._overall_confidence(subject_claims, contradictions)
        priority, priority_reason = self._priority(subject_claims)
        product_types = self._product_types(subject_key, subject_claims)
        gaps = self._knowledge_gaps(subject_claims, contradictions)

        window = self._collection_window(subject_claims)
        subj_type = subject_key.split(":", 1)[0] if ":" in subject_key else ""

        assessment = Assessment(
            title=title or f"Assessment: {subject_display or subject_key}",
            subject_key=subject_key,
            summary=self._bluf(subject_display or subject_key, subject_claims,
                               overall, contradictions),
            statements=statements,
            overall_confidence=overall,
            priority=priority,
            product_types=product_types,
            contradiction_ids=[c.contradiction_id for c in contradictions
                               if c.subject_key == subject_key],
            knowledge_gaps=gaps,
            collection_start=window[0],
            collection_end=window[1],
            created_at=self._clock(),
            detail={"priority_reason": priority_reason,
                    "subject_type": subj_type,
                    "claim_count": len(subject_claims)},
        )
        return assessment

    # -- statement construction -------------------------------------------- #

    def _statement_for(self, claim: Claim) -> AssessmentStatement:
        register = _REGISTER.get(claim.claim_type, AssessmentStatementType.UNCERTAINTY)
        text = claim.statement
        if claim.claim_type is ClaimType.CORROBORATED:
            n = claim.detail.get("independence", {}).get("independent_count", 0)
            text = f"{text} (corroborated by {n} independent sources)"
        elif claim.claim_type is ClaimType.DISPUTED:
            text = f"{text} (sources conflict — see contradictions)"
        elif claim.claim_type is ClaimType.REPORTED:
            provs = claim.evidence.providers()
            src = provs[0] if provs else "a single source"
            text = f"{text} (reported by {src})"
        return AssessmentStatement(
            statement_type=register,
            text=text,
            claim_id=claim.claim_id,
            confidence=claim.confidence,
            evidence=list(claim.evidence),
        )

    # -- overall confidence ------------------------------------------------ #

    def _overall_confidence(self, claims: Sequence[Claim],
                            contradictions: Sequence[Contradiction]
                            ) -> ConfidenceModel:
        union = EvidenceBundle()
        contradicting: List[str] = []
        for c in claims:
            if c.claim_type in (ClaimType.UNKNOWN,):
                continue
            union.extend(list(c.evidence))
        for ct in contradictions:
            for pos in ct.positions:
                contradicting.extend(pos.sources)
        extra: List[Limitation] = []
        if contradictions:
            extra.append(Limitation(
                "The evidence base contains unresolved contradictions between "
                "sources; the overall confidence reflects that discount.",
                "caution"))
        if len(union) == 0:
            extra.append(Limitation(
                "No corroborating public evidence was available for this subject.",
                "critical"))
        return confidence_from_evidence(
            union, now=self._clock(),
            contradicting=sorted(set(contradicting)) or None,
            extra_limitations=extra)

    # -- priority (defensive signals only) --------------------------------- #

    def _priority(self, claims: Sequence[Claim]) -> tuple[Priority, str]:
        exploited = False
        critical = False
        high = False
        ransomware = False
        for c in claims:
            status = str(c.detail.get("exploitation_status", "")).lower()
            if status in _EXPLOITED_STATUSES:
                exploited = True
            sev = str(c.detail.get("severity", "")).lower()
            if sev in _CRITICAL_SEVERITIES:
                critical = True
            elif sev in _HIGH_SEVERITIES:
                high = True
            if c.detail.get("known_ransomware"):
                ransomware = True

        if exploited and (critical or ransomware):
            return Priority.CRITICAL, ("public exploitation reported for a "
                                       "critical/known-ransomware vulnerability")
        if exploited:
            return Priority.HIGH, "public exploitation reported"
        if critical:
            return Priority.HIGH, "critical severity reported"
        if high:
            return Priority.MEDIUM, "high severity reported"
        if any(c.claim_type is ClaimType.CORROBORATED for c in claims):
            return Priority.MEDIUM, "corroborated activity across independent sources"
        if claims:
            return Priority.LOW, "single-source or unconfirmed reporting"
        return Priority.INFORMATIONAL, "no actionable signals in the evidence"

    # -- product tiers ----------------------------------------------------- #

    def _product_types(self, subject_key: str,
                       claims: Sequence[Claim]) -> List[ProductType]:
        subj_type = subject_key.split(":", 1)[0] if ":" in subject_key else ""
        tiers = list(_PRODUCT_TIERS.get(subj_type, [ProductType.TECHNICAL]))
        # Corroborated multi-actor/campaign activity also feeds strategic view.
        if any(c.detail.get("sector") for c in claims) and ProductType.STRATEGIC not in tiers:
            tiers.append(ProductType.STRATEGIC)
        return tiers

    # -- knowledge gaps ---------------------------------------------------- #

    def _knowledge_gaps(self, claims: Sequence[Claim],
                        contradictions: Sequence[Contradiction]) -> List[str]:
        gaps: List[str] = []
        for c in claims:
            if c.claim_type is ClaimType.UNKNOWN:
                gaps.append(f"Unresolved: {c.statement}")
            elif c.claim_type is ClaimType.REPORTED:
                gaps.append(
                    f"Single-source claim awaiting corroboration: {c.statement}")
        for ct in contradictions:
            gaps.append(f"Unresolved contradiction: {ct.summary}")
        if not any(c.detail.get("exploitation_status") for c in claims):
            # only meaningful for vulnerability subjects
            if any(c.subject.ref_type in ("cve", "vulnerability") for c in claims):
                gaps.append("Public exploitation status was not established by the "
                            "available sources.")
        # de-dup, keep order
        seen: set[str] = set()
        uniq: List[str] = []
        for g in gaps:
            if g not in seen:
                seen.add(g)
                uniq.append(g)
        return uniq

    # -- BLUF -------------------------------------------------------------- #

    def _bluf(self, subject_display: str, claims: Sequence[Claim],
              overall: ConfidenceModel, contradictions: Sequence[Contradiction]
              ) -> str:
        facts = [c for c in claims if c.claim_type is ClaimType.OBSERVED]
        corrob = [c for c in claims if c.claim_type is ClaimType.CORROBORATED]
        lead = facts[0].statement if facts else (
            corrob[0].statement if corrob else (
                claims[0].statement if claims else
                f"No public reporting was found for {subject_display}."))
        parts = [lead.rstrip(".") + "."]
        if corrob:
            parts.append(f"{len(corrob)} finding(s) are corroborated across "
                         f"independent sources.")
        if contradictions:
            parts.append(f"{len(contradictions)} unresolved contradiction(s) "
                         f"remain between sources.")
        parts.append(f"Overall assessment confidence is {overall.band} "
                     f"({overall.score:.2f}).")
        return " ".join(parts)

    # -- collection window ------------------------------------------------- #

    def _collection_window(self, claims: Sequence[Claim]) -> tuple[float, float]:
        starts = [c.first_seen for c in claims if c.first_seen]
        ends = [c.last_seen for c in claims if c.last_seen]
        return (min(starts) if starts else 0.0, max(ends) if ends else 0.0)


__all__ = ["AssessmentEngine"]
