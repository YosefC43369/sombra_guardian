"""
cybersecurity_intelligence.transform.news_transform — article → intelligence.

``ArticleTransformer`` takes a normalized article/advisory/report dict and emits:

  * a :class:`SourceRecord` for the publisher, and
  * a list of typed, evidence-backed :class:`Claim` objects.

It reuses ``threat_actor_intelligence.ingestion.extract.extract`` for the actual
IOC/CVE/TTP mining, so extraction stays in one place. The transform's own value is
*epistemic typing*: a CVE simply mentioned is an OBSERVED fact ("this CVE is
referenced here"); a CVE the text says is *exploited* becomes a separate REPORTED
claim carrying an ``exploitation_status`` so the contradiction and priority engines
can reason about it; an attribution phrase ("attributed to X") becomes an
attribution claim on the article's primary subject so conflicting attributions
across articles are detectable.

Every produced claim carries exactly one citation: the article itself. Corroboration
across articles happens later, in the ``EvidenceEngine``, by merging same-id claims.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from threat_actor_intelligence.ingestion.extract import extract
from threat_actor_intelligence.models.evidence import (
    EvidenceBundle,
    EvidenceRef,
    SourceClass,
)

from ..config import CTIConfig, get_config
from ..constants import ReliabilityGrade
from ..exceptions import CTITransformError
from ..models.claim import Claim, ClaimSubject, ClaimType
from ..models.source import SourceRecord

# --- exploitation / severity language ------------------------------------- #
_RE_EXPLOIT_WILD = re.compile(
    r"\b(exploited in the wild|actively exploited|active exploitation|"
    r"being exploited|exploitation (?:has been )?observed|"
    r"known exploited)\b", re.IGNORECASE)
_RE_EXPLOIT_POC = re.compile(
    r"\b(proof[- ]of[- ]concept|\bpoc\b(?: exploit| code)?|public exploit(?: code)?)\b",
    re.IGNORECASE)
_RE_NO_EXPLOIT = re.compile(
    r"\b(no (?:known|public|observed|active) exploitation|"
    r"not (?:been )?exploited|no exploitation (?:has been )?observed)\b",
    re.IGNORECASE)
_RE_CRITICAL = re.compile(r"\bcritical(?:ly)?\b", re.IGNORECASE)
_RE_HIGH = re.compile(r"\bhigh[- ]severity\b|\bseverity[: ]+high\b", re.IGNORECASE)
_RE_RANSOMWARE = re.compile(r"\bransomware\b", re.IGNORECASE)
_RE_ATTRIB = re.compile(
    r"\b(?:attributed to|linked to|blamed on|associated with|tied to)\s+"
    r"([A-Z][A-Za-z0-9 _\-]{2,40})", re.IGNORECASE)

_EXCERPT_CHARS = 280


@dataclass
class TransformResult:
    """The output of transforming one article."""
    source: SourceRecord
    claims: List[Claim] = field(default_factory=list)
    article_id: str = ""
    dropped_reason: str = ""

    def is_empty(self) -> bool:
        return not self.claims

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "article_id": self.article_id,
            "claims": [c.to_dict() for c in self.claims],
            "dropped_reason": self.dropped_reason,
        }


class ArticleTransformer:
    """Deterministic article → claims transformer."""

    def __init__(self, config: Optional[CTIConfig] = None) -> None:
        self.config = config or get_config()

    # -- public ------------------------------------------------------------ #

    def transform(self, article: Dict[str, Any]) -> TransformResult:
        title = str(article.get("title", "")).strip()
        content = self._content(article)
        if not title and not content:
            raise CTITransformError("article has neither title nor content")
        if len(content.encode("utf-8", "ignore")) > self.config.max_article_size_bytes:
            content = content[: self.config.max_article_size_bytes]

        source = self._source_record(article)
        provider = self._provider(article, source)
        observed_at = self._published_at(article)
        url = str(article.get("url", "") or article.get("link", "")).strip()
        excerpt = (content or title)[:_EXCERPT_CHARS]

        def make_ref() -> EvidenceRef:
            return EvidenceRef(
                provider=provider,
                source_class=source.source_class,
                title=title or provider,
                source_url=url,
                external_id=str(article.get("external_id", "") or ""),
                excerpt=excerpt,
                observed_at=observed_at,
                collected_at=time.time(),
            )

        text = f"{title}\n{content}"
        ex = extract(text, mine_names=True)

        claims: List[Claim] = []
        primary_subject = self._primary_subject(ex, title)

        # CVE claims: an OBSERVED "referenced here" fact + optional REPORTED
        # exploitation claim carrying status/severity.
        for cve in ex.cve_ids:
            subj = ClaimSubject("cve", cve, cve)
            claims.append(Claim(
                subj, f"{cve} is referenced in public threat reporting.",
                ClaimType.OBSERVED, EvidenceBundle([make_ref()]),
                predicate="referenced_in", observed_at=observed_at,
                tags=["cve"]))
            status = self._exploitation_status(text)
            if status:
                detail: Dict[str, Any] = {"exploitation_status": status}
                sev = self._severity(text)
                if sev:
                    detail["severity"] = sev
                if _RE_RANSOMWARE.search(text):
                    detail["known_ransomware"] = True
                claims.append(Claim(
                    subj,
                    f"{cve} is reported as '{status}'.",
                    ClaimType.REPORTED, EvidenceBundle([make_ref()]),
                    predicate="exploitation", observed_at=observed_at,
                    tags=["cve", "exploitation"], detail=detail))

        # IOC claims (technical intelligence).
        for ioc in ex.iocs:
            subj = ClaimSubject(ioc.ioc_type.value, ioc.value, ioc.value)
            claims.append(Claim(
                subj,
                f"{ioc.ioc_type.value} indicator {ioc.value} is reported in public "
                f"threat intelligence.",
                ClaimType.REPORTED, EvidenceBundle([make_ref()]),
                predicate="indicator", observed_at=observed_at,
                tags=["ioc", ioc.ioc_type.value],
                detail={"ioc_type": ioc.ioc_type.value}))

        # ATT&CK technique references (tactical).
        for tid in ex.technique_ids:
            subj = ClaimSubject("ttp", tid, tid)
            claims.append(Claim(
                subj, f"ATT&CK technique {tid} is referenced in public threat reporting.",
                ClaimType.OBSERVED, EvidenceBundle([make_ref()]),
                predicate="referenced_in", observed_at=observed_at, tags=["ttp"]))

        # Actor / malware mentions (operational), plus attribution claim.
        for name in ex.actor_names:
            subj = ClaimSubject("actor", name.lower(), name)
            claims.append(Claim(
                subj, f"Threat actor '{name}' is referenced in public threat reporting.",
                ClaimType.REPORTED, EvidenceBundle([make_ref()]),
                predicate="referenced_in", observed_at=observed_at, tags=["actor"]))
        for name in ex.malware_names:
            subj = ClaimSubject("malware", name.lower(), name)
            claims.append(Claim(
                subj, f"Malware '{name}' is referenced in public threat reporting.",
                ClaimType.REPORTED, EvidenceBundle([make_ref()]),
                predicate="referenced_in", observed_at=observed_at, tags=["malware"]))

        attribution = self._attribution(text)
        if attribution and primary_subject is not None:
            claims.append(Claim(
                primary_subject,
                f"{primary_subject.display} is attributed to {attribution}.",
                ClaimType.REPORTED, EvidenceBundle([make_ref()]),
                predicate="attributed_to", observed_at=observed_at,
                tags=["attribution"], detail={"attribution": attribution}))

        for c in claims:
            c.validate()

        result = TransformResult(source=source, claims=claims,
                                 article_id=make_ref().ref_id)
        if not claims:
            result.dropped_reason = "no extractable intelligence entities"
        return result

    def transform_many(self, articles: List[Dict[str, Any]]) -> List[TransformResult]:
        out: List[TransformResult] = []
        for a in articles:
            try:
                out.append(self.transform(a))
            except CTITransformError:
                continue
        return out

    # -- helpers ----------------------------------------------------------- #

    def _content(self, article: Dict[str, Any]) -> str:
        for key in ("content", "text", "summary", "description", "body"):
            v = article.get(key)
            if v:
                return str(v)
        return ""

    def _provider(self, article: Dict[str, Any], source: SourceRecord) -> str:
        return (str(article.get("provider", "")).strip()
                or source.name
                or "unknown")

    def _source_record(self, article: Dict[str, Any]) -> SourceRecord:
        name = (str(article.get("source", "")).strip()
                or str(article.get("source_name", "")).strip()
                or str(article.get("publisher", "")).strip()
                or "unknown")
        return SourceRecord(
            name=name,
            url=str(article.get("source_url", "") or article.get("url", "")).strip(),
            source_class=SourceClass.coerce(article.get("source_class")),
            publisher=str(article.get("publisher", "")).strip(),
            language=str(article.get("language", "")).strip(),
            article_count=int(article.get("article_count", 0) or 0),
        )

    def _published_at(self, article: Dict[str, Any]) -> float:
        raw = article.get("published_at") or article.get("published") or \
            article.get("pubDate") or article.get("date")
        if raw is None:
            return 0.0
        if isinstance(raw, (int, float)):
            return float(raw)
        s = str(raw).strip()
        if not s:
            return 0.0
        # try epoch string
        try:
            return float(s)
        except ValueError:
            pass
        # try ISO 8601 (with trailing Z)
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return 0.0

    def _exploitation_status(self, text: str) -> str:
        if _RE_NO_EXPLOIT.search(text):
            return "no known exploitation"
        if _RE_EXPLOIT_WILD.search(text):
            return "exploited"
        if _RE_EXPLOIT_POC.search(text):
            return "proof-of-concept available"
        return ""

    def _severity(self, text: str) -> str:
        if _RE_CRITICAL.search(text):
            return "critical"
        if _RE_HIGH.search(text):
            return "high"
        return ""

    def _attribution(self, text: str) -> str:
        m = _RE_ATTRIB.search(text)
        if not m:
            return ""
        cand = m.group(1).strip().rstrip(".,;:")
        # keep it short and stop at the first sentence-ish boundary
        cand = re.split(r"\s+(?:in|for|which|that|and|using|with)\b", cand,
                        maxsplit=1)[0].strip()
        return cand

    def _primary_subject(self, extraction, title: str) -> Optional[ClaimSubject]:
        if extraction.cve_ids:
            cve = extraction.cve_ids[0]
            return ClaimSubject("cve", cve, cve)
        # Attribution must attach to a non-actor subject so conflicting
        # attributions across reports collide on one key; a title-derived
        # incident slug is that stable subject when no CVE anchors the report.
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        if slug:
            return ClaimSubject("incident", slug[:64], title[:80])
        return None


__all__ = ["ArticleTransformer", "TransformResult"]
