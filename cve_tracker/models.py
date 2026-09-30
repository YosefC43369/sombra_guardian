"""
cve_tracker.models — the normalized value objects the whole pipeline moves.

A design promise runs through every model here: **never destroy source data**.
Each source contributes a :class:`SourceRecord` (its raw payload + the subset it
asserted), and the merged :class:`CVERecord` keeps provenance for every scalar
fact via :class:`ProvenancedValue`, so conflict resolution is a *display*
decision, not a lossy overwrite (rule §55/§56).

Everything is a plain dataclass with explicit ``to_dict``/``from_dict`` so it
serializes straight into the storage layer's JSON columns without pulling in
pydantic (the repo doesn't depend on it, and the models are simple enough not
to need it).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .enums import (
    Severity,
    CVSSVersion,
    SourceKind,
    ReferenceType,
    ExploitMaturity,
    AIProcessingState,
    NotificationState,
    ChangeKind,
    Priority,
)
from .utils import (
    normalize_cve_id,
    normalize_url,
    now_epoch,
    dedupe_preserve_order,
    slugify,
)


# ---------------- Provenance ----------------

@dataclass
class ProvenancedValue:
    """A single scalar fact plus the source that asserted it and the trust
    weight of that source. Lets the merger keep every source's value while
    picking one for display deterministically."""

    value: Any
    source: str = ""
    trust: int = 0
    observed_at: int = field(default_factory=now_epoch)

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "source": self.source,
                "trust": self.trust, "observed_at": self.observed_at}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProvenancedValue":
        return cls(value=d.get("value"), source=d.get("source", ""),
                   trust=int(d.get("trust", 0) or 0),
                   observed_at=int(d.get("observed_at", now_epoch()) or now_epoch()))


# ---------------- CVSS ----------------

@dataclass
class CVSSScore:
    """One CVSS assessment from one source. Multiple can coexist on a CVE
    (different versions, or the same version from different sources)."""

    version: str                       # CVSSVersion value
    base_score: Optional[float] = None
    base_severity: str = Severity.UNKNOWN.value
    vector: str = ""
    source: str = ""
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    # Decoded metric labels (human-readable), populated by enrichment.cvss.
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CVSSScore":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})

    @property
    def is_complete(self) -> bool:
        return self.base_score is not None and bool(self.vector)


# ---------------- Weaknesses / products / references ----------------

@dataclass
class Weakness:
    """A CWE association."""

    cwe_id: str
    name: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Weakness":
        return cls(cwe_id=d.get("cwe_id", ""), name=d.get("name", ""),
                   source=d.get("source", ""))


@dataclass
class AffectedProduct:
    """A vendor/product (optionally with version range) named as affected."""

    vendor: str = ""
    product: str = ""
    cpe: str = ""
    versions_affected: List[str] = field(default_factory=list)
    versions_fixed: List[str] = field(default_factory=list)
    version_start_including: str = ""
    version_start_excluding: str = ""
    version_end_including: str = ""
    version_end_excluding: str = ""
    default_status: str = ""            # "affected" / "unaffected" / "unknown"
    source: str = ""

    @property
    def key(self) -> str:
        """Stable identity for de-duplication across sources."""
        return f"{slugify(self.vendor)}/{slugify(self.product)}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AffectedProduct":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


@dataclass
class Reference:
    """An external reference URL and what it is (classification only — the
    subsystem never fetches it)."""

    url: str
    ref_type: str = ReferenceType.UNKNOWN.value
    title: str = ""
    tags: List[str] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Reference":
        return cls(
            url=d.get("url", ""),
            ref_type=d.get("ref_type", ReferenceType.UNKNOWN.value),
            title=d.get("title", ""),
            tags=list(d.get("tags", []) or []),
            source=d.get("source", ""),
        )


@dataclass
class KEVInfo:
    """CISA Known Exploited Vulnerabilities record for this CVE. Its presence
    is a *fact* (exploited in the wild per CISA), never an AI judgement."""

    in_kev: bool = False
    date_added: Optional[int] = None
    due_date: Optional[int] = None
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    required_action: str = ""
    known_ransomware: str = ""          # CISA's "knownRansomwareCampaignUse"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "KEVInfo":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


@dataclass
class TimelineEntry:
    """One dated milestone in a CVE's lifecycle."""

    at: int
    kind: str                           # e.g. "published", "kev_added"
    label: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TimelineEntry":
        return cls(at=int(d.get("at", 0) or 0), kind=d.get("kind", ""),
                   label=d.get("label", ""), source=d.get("source", ""))


# ---------------- Per-source record ----------------

@dataclass
class SourceRecord:
    """What ONE source said about ONE CVE, at ingest time. Retained whole so we
    can re-derive the merged view, audit a source, or re-run enrichment without
    re-fetching."""

    source: str                         # source name (nvd/cisa_kev/…)
    source_kind: str = SourceKind.OTHER.value
    source_id: str = ""                 # the id in that source (GHSA-…, etc.)
    source_url: str = ""
    fetched_at: int = field(default_factory=now_epoch)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SourceRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


# ---------------- Merged CVE record ----------------

@dataclass
class CVERecord:
    """The normalized, merged view of a vulnerability across all sources.

    Scalars that sources can disagree on carry provenance in ``provenance`` so
    the display layer can show 'NVD: 8.8 / Vendor: 9.1' honestly. List facts
    (references, products, cwes, cvss_scores) are unioned, de-duplicated by
    their natural key, and tagged with their contributing source.
    """

    cve_id: str
    title: str = ""
    description: str = ""

    published_at: Optional[int] = None
    last_modified_at: Optional[int] = None

    # Display-chosen scalars (highest-trust source wins); full set lives in the
    # respective lists / provenance map.
    severity: str = Severity.UNKNOWN.value
    cvss_score: Optional[float] = None
    cvss_version: str = ""
    cvss_vector: str = ""

    cvss_scores: List[CVSSScore] = field(default_factory=list)
    weaknesses: List[Weakness] = field(default_factory=list)
    products: List[AffectedProduct] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)

    kev: KEVInfo = field(default_factory=KEVInfo)
    exploit_maturity: str = ExploitMaturity.UNKNOWN.value

    # Aliases this CVE is known by in other schemes (GHSA-…, vendor SA ids).
    aliases: List[str] = field(default_factory=list)

    # Provenance for the display scalars: field name -> ProvenancedValue.
    provenance: Dict[str, ProvenancedValue] = field(default_factory=dict)

    # Which sources contributed, newest fetch first.
    sources: List[SourceRecord] = field(default_factory=list)

    # Processing state.
    ai_state: str = AIProcessingState.PENDING.value
    first_seen_at: int = field(default_factory=now_epoch)
    enriched_at: Optional[int] = None

    # Internal intelligence signal (NOT an official score — see enums.Priority).
    priority: str = Priority.INFO.value
    priority_score: int = 0
    priority_reasons: List[str] = field(default_factory=list)

    # ------------- convenience accessors -------------

    @property
    def source_names(self) -> List[str]:
        return dedupe_preserve_order([s.source for s in self.sources])

    @property
    def vendors(self) -> List[str]:
        return dedupe_preserve_order(
            [p.vendor for p in self.products if p.vendor])

    @property
    def product_names(self) -> List[str]:
        return dedupe_preserve_order(
            [p.product for p in self.products if p.product])

    @property
    def cwe_ids(self) -> List[str]:
        return dedupe_preserve_order(
            [w.cwe_id for w in self.weaknesses if w.cwe_id])

    @property
    def in_kev(self) -> bool:
        return bool(self.kev and self.kev.in_kev)

    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL.value

    @property
    def primary_url(self) -> str:
        """Best single link for the Telegram '🔗 รายละเอียดเพิ่มเติม' line."""
        for sr in self.sources:
            if sr.source == "nvd" and sr.source_url:
                return sr.source_url
        for ref in self.references:
            if ref.ref_type in (
                ReferenceType.ADVISORY.value, ReferenceType.VENDOR_ADVISORY.value):
                return ref.url
        if self.references:
            return self.references[0].url
        for sr in self.sources:
            if sr.source_url:
                return sr.source_url
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    def __post_init__(self):
        norm = normalize_cve_id(self.cve_id)
        if norm:
            self.cve_id = norm

    # ------------- serialization -------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "published_at": self.published_at,
            "last_modified_at": self.last_modified_at,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "cvss_scores": [c.to_dict() for c in self.cvss_scores],
            "weaknesses": [w.to_dict() for w in self.weaknesses],
            "products": [p.to_dict() for p in self.products],
            "references": [r.to_dict() for r in self.references],
            "timeline": [t.to_dict() for t in self.timeline],
            "kev": self.kev.to_dict(),
            "exploit_maturity": self.exploit_maturity,
            "aliases": list(self.aliases),
            "provenance": {k: v.to_dict() for k, v in self.provenance.items()},
            "sources": [s.to_dict() for s in self.sources],
            "ai_state": self.ai_state,
            "first_seen_at": self.first_seen_at,
            "enriched_at": self.enriched_at,
            "priority": self.priority,
            "priority_score": self.priority_score,
            "priority_reasons": list(self.priority_reasons),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CVERecord":
        d = d or {}
        rec = cls(cve_id=d.get("cve_id", ""))
        rec.title = d.get("title", "")
        rec.description = d.get("description", "")
        rec.published_at = d.get("published_at")
        rec.last_modified_at = d.get("last_modified_at")
        rec.severity = d.get("severity", Severity.UNKNOWN.value)
        rec.cvss_score = d.get("cvss_score")
        rec.cvss_version = d.get("cvss_version", "")
        rec.cvss_vector = d.get("cvss_vector", "")
        rec.cvss_scores = [CVSSScore.from_dict(x) for x in d.get("cvss_scores", []) or []]
        rec.weaknesses = [Weakness.from_dict(x) for x in d.get("weaknesses", []) or []]
        rec.products = [AffectedProduct.from_dict(x) for x in d.get("products", []) or []]
        rec.references = [Reference.from_dict(x) for x in d.get("references", []) or []]
        rec.timeline = [TimelineEntry.from_dict(x) for x in d.get("timeline", []) or []]
        rec.kev = KEVInfo.from_dict(d.get("kev", {}) or {})
        rec.exploit_maturity = d.get("exploit_maturity", ExploitMaturity.UNKNOWN.value)
        rec.aliases = list(d.get("aliases", []) or [])
        rec.provenance = {
            k: ProvenancedValue.from_dict(v)
            for k, v in (d.get("provenance", {}) or {}).items()
        }
        rec.sources = [SourceRecord.from_dict(x) for x in d.get("sources", []) or []]
        rec.ai_state = d.get("ai_state", AIProcessingState.PENDING.value)
        rec.first_seen_at = int(d.get("first_seen_at", now_epoch()) or now_epoch())
        rec.enriched_at = d.get("enriched_at")
        rec.priority = d.get("priority", Priority.INFO.value)
        rec.priority_score = int(d.get("priority_score", 0) or 0)
        rec.priority_reasons = list(d.get("priority_reasons", []) or [])
        return rec


# ---------------- Change detection ----------------

@dataclass
class FieldChange:
    kind: str                           # ChangeKind value
    before: Any = None
    after: Any = None
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def is_significant(self) -> bool:
        """Severity/CVSS/KEV/exploit changes are always significant; textual
        drift (description) is not, unless explicitly flagged."""
        return self.kind in (
            ChangeKind.SEVERITY.value, ChangeKind.CVSS.value,
            ChangeKind.KEV_STATUS.value, ChangeKind.EXPLOIT_STATUS.value,
        )


@dataclass
class ChangeSet:
    cve_id: str
    changes: List[FieldChange] = field(default_factory=list)
    detected_at: int = field(default_factory=now_epoch)

    @property
    def has_significant(self) -> bool:
        return any(c.is_significant for c in self.changes)

    def of_kind(self, kind: str) -> Optional[FieldChange]:
        for c in self.changes:
            if c.kind == kind:
                return c
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {"cve_id": self.cve_id,
                "changes": [c.to_dict() for c in self.changes],
                "detected_at": self.detected_at}


# ---------------- AI summary ----------------

@dataclass
class AISummary:
    """The AI-produced Thai rendering of a CVE, plus the provenance of how it
    was produced (which provider/model, whether it passed validation or fell
    back to the deterministic template)."""

    cve_id: str
    language: str = "th"
    title_th: str = ""
    summary_th: str = ""
    impact_th: str = ""
    recommendation_th: str = ""
    body_th: str = ""                   # fully-rendered message body
    provider: str = ""
    model: str = ""
    state: str = AIProcessingState.PENDING.value
    validated: bool = False
    fallback_used: bool = False
    created_at: int = field(default_factory=now_epoch)
    input_hash: str = ""                # cache key of the structured input

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AISummary":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


# ---------------- Subscription / notification ----------------

@dataclass
class Subscription:
    """A chat's CVE notification preferences."""

    chat_id: int
    topic_id: Optional[int] = None
    enabled: bool = True
    min_cvss: float = 0.0
    min_severity: str = Severity.MEDIUM.value
    kev_only: bool = False
    vendors: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    include_updates: bool = True
    ai_summary: bool = True
    created_at: int = field(default_factory=now_epoch)
    updated_at: int = field(default_factory=now_epoch)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Subscription":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


@dataclass
class Notification:
    """One CVE→chat delivery attempt record (idempotency + audit)."""

    cve_id: str
    chat_id: int
    topic_id: Optional[int] = None
    reason: str = ""                    # why this chat got it (which filter)
    state: str = NotificationState.PENDING.value
    priority: str = Priority.INFO.value
    is_update: bool = False
    attempts: int = 0
    created_at: int = field(default_factory=now_epoch)
    sent_at: Optional[int] = None
    error: str = ""

    @property
    def dedupe_key(self) -> str:
        """Same CVE + chat + (update vs. new) should never send twice."""
        suffix = "u" if self.is_update else "n"
        topic = self.topic_id if self.topic_id else 0
        return f"{self.cve_id}:{self.chat_id}:{topic}:{suffix}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Notification":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


@dataclass
class SourceState:
    """Per-source ingestion checkpoint + rolling health, persisted so restarts
    resume incrementally instead of re-scanning from scratch."""

    source: str
    enabled: bool = True
    last_success_at: Optional[int] = None
    last_failure_at: Optional[int] = None
    last_cursor: str = ""               # source-specific checkpoint
    last_modified_seen: Optional[int] = None
    etag: str = ""
    http_last_modified: str = ""
    consecutive_failures: int = 0
    total_runs: int = 0
    records_seen: int = 0
    records_new: int = 0
    records_updated: int = 0
    records_duplicate: int = 0
    last_latency_ms: int = 0
    health: str = "unknown"
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SourceState":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in (d or {}).items() if k in known})
