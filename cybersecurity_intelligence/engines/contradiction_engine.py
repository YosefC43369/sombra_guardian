"""
cybersecurity_intelligence.engines.contradiction_engine — detect, never adjudicate.

Given a set of consolidated claims, this finds where sources disagree and records
the disagreement as a :class:`Contradiction` with every competing position and its
sources intact. It does **not** choose a winner (spec §25): a contradiction is a
first-class output that a report renders in full so an analyst decides with the
evidence in view.

Detection is structured, not free-text guessing. The transform/ingestion layer
tags a claim's ``detail`` with the comparable attribute it asserts — e.g.
``attribution``, ``exploitation_status``, ``severity``, ``malware_name`` — and
this engine groups claims by (subject, dimension) and flags any subject on which
two or more *distinct* normalized values are asserted. That keeps detection
precise: no attribute tag, no false contradiction.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Set, Tuple

from ..models.claim import Claim
from ..models.contradiction import (
    Contradiction,
    ContradictionPosition,
    ContradictionType,
)

# Each dimension: the contradiction type it produces, the claim.detail key that
# carries the comparable value, and a human label for the summary line.
_DIMENSIONS: List[Tuple[ContradictionType, str, str]] = [
    (ContradictionType.ATTRIBUTION, "attribution", "attribution"),
    (ContradictionType.CVE_EXPLOITATION, "exploitation_status", "exploitation status"),
    (ContradictionType.SEVERITY, "severity", "severity rating"),
    (ContradictionType.MALWARE_NAMING, "malware_name", "malware name"),
    (ContradictionType.TARGET, "target", "target"),
    (ContradictionType.INFRASTRUCTURE, "infrastructure_owner", "infrastructure ownership"),
    (ContradictionType.TIMELINE, "event_date", "event date"),
]


def _value_key(raw: str) -> str:
    return " ".join(str(raw).strip().lower().split())


class ContradictionEngine:
    """Finds conflicts across claims. Stateless and deterministic."""

    def detect(self, claims: Sequence[Claim]) -> List[Contradiction]:
        contradictions: List[Contradiction] = []
        for ctype, detail_key, label in _DIMENSIONS:
            contradictions.extend(self._detect_dimension(claims, ctype, detail_key, label))
        # Deduplicate by contradiction_id (a subject can only conflict once per
        # dimension/value-set).
        seen: Set[str] = set()
        uniq: List[Contradiction] = []
        for c in contradictions:
            if c.contradiction_id not in seen:
                seen.add(c.contradiction_id)
                uniq.append(c)
        return uniq

    def _detect_dimension(self, claims: Sequence[Claim],
                          ctype: ContradictionType, detail_key: str, label: str
                          ) -> List[Contradiction]:
        # subject_key -> value_key -> {"display": str, "claims": [Claim]}
        by_subject: Dict[str, Dict[str, Dict[str, object]]] = {}
        for c in claims:
            raw = c.detail.get(detail_key)
            if not raw:
                continue
            skey = c.subject.key()
            vkey = _value_key(str(raw))
            if not vkey:
                continue
            bucket = by_subject.setdefault(skey, {}).setdefault(
                vkey, {"display": str(raw), "claims": []})
            bucket["claims"].append(c)  # type: ignore[union-attr]

        out: List[Contradiction] = []
        for skey, values in by_subject.items():
            if len(values) < 2:
                continue  # everyone agrees (or only one value asserted)
            positions: List[ContradictionPosition] = []
            for vkey, info in sorted(values.items()):
                group: List[Claim] = info["claims"]  # type: ignore[assignment]
                sources: List[str] = sorted({
                    ref.provider for cl in group for ref in cl.evidence if ref.provider})
                best = max(group, key=lambda cl: cl.score)
                positions.append(ContradictionPosition(
                    value=str(info["display"]),
                    claim_id=best.claim_id,
                    sources=sources,
                    band=best.band,
                ))
            subject_display = self._subject_display(values)
            summary = (f"Sources disagree on the {label} of {subject_display}: "
                       + " vs. ".join(f"'{p.value}'" for p in positions))
            out.append(Contradiction(
                contradiction_type=ctype,
                subject_key=skey,
                summary=summary,
                positions=positions,
            ))
        return out

    @staticmethod
    def _subject_display(values: Dict[str, Dict[str, object]]) -> str:
        for info in values.values():
            claims: List[Claim] = info["claims"]  # type: ignore[assignment]
            if claims:
                return claims[0].subject.display or claims[0].subject.ref_value
        return "the subject"

    # -- helpers for the facade ------------------------------------------- #

    @staticmethod
    def disputed_claim_ids(contradictions: Sequence[Contradiction]) -> Set[str]:
        ids: Set[str] = set()
        for c in contradictions:
            ids.update(c.claim_ids)
        return ids

    @staticmethod
    def disputed_subject_keys(contradictions: Sequence[Contradiction]) -> Set[str]:
        return {c.subject_key for c in contradictions}

    @staticmethod
    def contradicting_providers_for(claim: Claim,
                                    contradictions: Sequence[Contradiction]
                                    ) -> List[str]:
        """Providers that assert a *different* position on this claim's subject —
        the ones the confidence engine should penalize."""
        own = {ref.provider for ref in claim.evidence if ref.provider}
        others: Set[str] = set()
        for c in contradictions:
            if c.subject_key != claim.subject.key():
                continue
            for pos in c.positions:
                if pos.claim_id == claim.claim_id:
                    continue
                others.update(p for p in pos.sources if p not in own)
        return sorted(others)


__all__ = ["ContradictionEngine"]
