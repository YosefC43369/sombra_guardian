"""
cybersecurity_intelligence.engine — the CTI Analysis Engine facade.

One object that wires the analytic pipeline together and is the entry point the
Telegram layer, the CLI and other Sombra Guardian modules call:

    transform → consolidate → detect contradictions → score → assess → report

It works with or without persistence: pass a :class:`CTIStore` to durably record
sources/claims/contradictions/assessments, or omit it for a pure in-memory
analysis (used heavily in tests and for one-off `/analyze` calls).

The ordering here is deliberate and load-bearing: contradictions are detected and
disputed claims re-typed *before* confidence is scored, so a DISPUTED claim gets
the DISPUTED confidence ceiling rather than the REPORTED one.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .config import CTIConfig, get_config
from .engines import (
    AssessmentEngine,
    ConfidenceEngine,
    ContradictionEngine,
    EvidenceEngine,
    SourceReliabilityEngine,
)
from .models.assessment import Assessment
from .models.claim import Claim
from .models.contradiction import Contradiction
from .models.source import SourceRecord
from .reports import render_json, render_markdown, render_telegram
from .storage import CTIStore
from .transform import ArticleTransformer


@dataclass
class AnalysisResult:
    """The result of analyzing a batch of articles."""
    claims: List[Claim] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)
    sources: List[SourceRecord] = field(default_factory=list)
    dropped: int = 0

    def subjects(self) -> List[str]:
        return sorted({c.subject.key() for c in self.claims})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claims": [c.to_dict() for c in self.claims],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "sources": [s.to_dict() for s in self.sources],
            "dropped": self.dropped,
            "subjects": self.subjects(),
        }


class CTIAnalysisEngine:
    """Facade over the CTI analytic pipeline."""

    def __init__(self, *, config: Optional[CTIConfig] = None,
                 store: Optional[CTIStore] = None,
                 now: Optional[float] = None) -> None:
        self.config = config or get_config()
        self.store = store
        self._now = now
        self.transformer = ArticleTransformer(self.config)
        self.reliability = SourceReliabilityEngine(now=now)
        self.evidence = EvidenceEngine(
            min_independent=self.config.corroboration_min_independent_sources)
        self.confidence = ConfidenceEngine(now=now)
        self.contradiction = ContradictionEngine()
        self.assessment = AssessmentEngine(now=now)

    def _clock(self) -> float:
        return self._now if self._now is not None else time.time()

    # -- analysis ---------------------------------------------------------- #

    def analyze_articles(self, articles: Sequence[Dict[str, Any]],
                         *, persist: bool = True) -> AnalysisResult:
        """Transform → consolidate → detect contradictions → score. Optionally
        persist sources/claims/contradictions."""
        results = self.transformer.transform_many(list(articles))
        raw_claims: List[Claim] = []
        sources: Dict[str, SourceRecord] = {}
        dropped = 0

        for r in results:
            if r.is_empty():
                dropped += 1
            raw_claims.extend(r.claims)
            sources.setdefault(r.source.source_id, r.source)

        # grade each source from a sample of its own citations
        for src in sources.values():
            sample = [ref for c in raw_claims for ref in c.evidence
                      if ref.provider in (src.name, "")][:20]
            src.reliability = self.reliability.grade_source(src, sample_refs=sample)

        graded = self.analyze_claims(raw_claims)

        result = AnalysisResult(
            claims=graded["claims"],
            contradictions=graded["contradictions"],
            sources=list(sources.values()),
            dropped=dropped,
        )
        if persist and self.store is not None:
            self._persist(result)
        return result

    def analyze_claims(self, claims: List[Claim]) -> Dict[str, Any]:
        """Consolidate, detect contradictions, re-type disputed claims, then
        score. Pure function over the claim list (no persistence)."""
        consolidated = self.evidence.consolidate(claims)
        contradictions = self.contradiction.detect(consolidated)
        disputed = self.contradiction.disputed_claim_ids(contradictions)
        for c in consolidated:
            if c.claim_id in disputed:
                self.evidence.mark_disputed(c)
        for c in consolidated:
            contra = self.contradiction.contradicting_providers_for(c, contradictions)
            self.confidence.score_claim(c, contradicting=contra or None)
        return {"claims": consolidated, "contradictions": contradictions}

    # -- assessment -------------------------------------------------------- #

    def assess(self, subject_key: str, *, subject_display: str = "",
               claims: Optional[Sequence[Claim]] = None,
               contradictions: Optional[Sequence[Contradiction]] = None,
               persist: bool = True, title: str = "") -> Assessment:
        """Build an assessment for a subject. Claims/contradictions come from the
        arguments, else from the store, else an empty assessment is produced."""
        subject_key = subject_key.lower()
        if claims is None:
            claims = (self.store.claims_for_subject(subject_key)
                      if self.store is not None else [])
        if contradictions is None:
            contradictions = (self.store.contradictions_for_subject(subject_key)
                              if self.store is not None else [])
        if not subject_display:
            for c in claims:
                if c.subject.key() == subject_key and c.subject.display:
                    subject_display = c.subject.display
                    break
            else:
                subject_display = subject_key.split(":", 1)[-1]

        assessment = self.assessment.build(
            subject_key, subject_display, list(claims),
            contradictions=list(contradictions), title=title)
        if persist and self.store is not None:
            self.store.save_assessment(assessment)
        return assessment

    def analyze_and_assess(self, articles: Sequence[Dict[str, Any]],
                           subject_key: str, *, persist: bool = True) -> Assessment:
        """Convenience: run the full pipeline over ``articles`` and immediately
        assess one subject from the freshly-analyzed claims."""
        result = self.analyze_articles(articles, persist=persist)
        return self.assess(subject_key, claims=result.claims,
                           contradictions=result.contradictions, persist=persist)

    # -- persistence ------------------------------------------------------- #

    def _persist(self, result: AnalysisResult) -> None:
        if self.store is None:
            return
        for s in result.sources:
            self.store.save_source(s)
        self.store.save_claims(result.claims)
        self.store.save_contradictions(result.contradictions)

    # -- search / reporting / health -------------------------------------- #

    def search(self, query: str, *, limit: int = 50) -> List[Claim]:
        if self.store is None:
            return []
        return self.store.search_claims(query, limit=limit)

    def render(self, assessment: Assessment,
               contradictions: Optional[Sequence[Contradiction]] = None,
               *, fmt: str = "markdown") -> str:
        fmt = fmt.lower()
        if fmt in ("md", "markdown"):
            return render_markdown(assessment, contradictions)
        if fmt == "json":
            return render_json(assessment, contradictions)
        if fmt in ("telegram", "text", "txt"):
            return render_telegram(assessment, contradictions)
        raise ValueError(f"unknown report format: {fmt}")

    def grade_source(self, source: SourceRecord) -> SourceRecord:
        source.reliability = self.reliability.grade_source(source)
        if self.store is not None:
            self.store.save_source(source)
        return source

    def health(self) -> Dict[str, Any]:
        h: Dict[str, Any] = {
            "enabled": self.config.enabled,
            "store": None,
            "engines": ["reliability", "evidence", "confidence",
                        "contradiction", "assessment"],
        }
        if self.store is not None:
            try:
                h["store"] = self.store.stats()
            except Exception as exc:  # pragma: no cover - defensive
                h["store"] = {"error": str(exc)}
        return h


__all__ = ["CTIAnalysisEngine", "AnalysisResult"]
