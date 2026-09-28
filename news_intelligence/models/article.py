"""
news_intelligence.models.article — the normalized news article, the engine's atom.

An ``Article`` is one publicly-published news/intelligence item after
normalization, deduplication and enrichment. It preserves everything the spec's
CORE DATA MODEL requires and — critically — anchors every extracted fact to the
article itself via ``as_evidence()`` so provenance is never lost. The engine
never fabricates an article, a source, or an attribution: an ``Article`` only
exists because a public source published it, and its ``url`` always points back
to that primary source.

Deduplication keys:
  * ``content_hash`` — SHA256 over title+summary+domain (near-duplicate detection
    layers SimHash/MinHash on top, see ``clustering.duplicate_cluster``).
  * ``canonical_url`` — the publisher's own canonical link when present, so a
    syndicated copy folds onto the original.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .evidence import EvidenceRef, SourceClass, TLP
from .entity import EntityMention, EntityType, dedupe_mentions
from .source import domain_of


def content_hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").strip().lower().encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


@dataclass
class Article:
    title: str
    url: str = ""
    canonical_url: str = ""
    summary: str = ""
    body: str = ""                       # bounded normalized body text
    source_name: str = ""
    source_id: str = ""
    source_domain: str = ""
    source_class: SourceClass = SourceClass.UNKNOWN
    author: str = ""
    authors: List[str] = field(default_factory=list)
    language: str = ""
    publication_date: float = 0.0
    ingestion_date: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    tlp: TLP = TLP.CLEAR
    # entity mention buckets (values are normalized entity values)
    entity_mentions: List[EntityMention] = field(default_factory=list)
    cve_mentions: List[str] = field(default_factory=list)
    malware_mentions: List[str] = field(default_factory=list)
    actor_mentions: List[str] = field(default_factory=list)
    organization_mentions: List[str] = field(default_factory=list)
    country_mentions: List[str] = field(default_factory=list)
    infrastructure_mentions: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    # provenance / dedup
    content_hash: str = ""
    simhash: int = 0
    etag: str = ""
    last_modified: str = ""
    # epistemics
    confidence: Optional[Dict[str, Any]] = None   # ConfidenceModel.to_dict()
    evidence: List[Dict[str, Any]] = field(default_factory=list)  # EvidenceRef dicts
    article_id: str = ""
    duplicate_of: str = ""               # article_id of the canonical original
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.source_class = SourceClass.coerce(self.source_class)
        self.tlp = TLP.coerce(self.tlp)
        if self.author and self.author not in self.authors:
            self.authors.insert(0, self.author)
        if self.authors and not self.author:
            self.author = self.authors[0]
        if not self.source_domain:
            self.source_domain = domain_of(self.canonical_url or self.url)
        if not self.content_hash:
            self.content_hash = content_hash(self.title, self.summary,
                                             self.source_domain)
        if not self.article_id:
            seed = (self.canonical_url or self.url or self.content_hash)
            self.article_id = "art-" + hashlib.sha256(
                seed.encode("utf-8")).hexdigest()[:20]

    # -- provenance ------------------------------------------------------- #

    def as_evidence(self, *, excerpt: str = "") -> EvidenceRef:
        """A citation pointing back at this article, for attaching to every fact
        extracted from it."""
        return EvidenceRef(
            provider=self.source_name or self.source_domain or "news",
            source_class=self.source_class, title=self.title,
            source_url=self.canonical_url or self.url, external_id=self.article_id,
            excerpt=excerpt or (self.summary or self.title)[:280],
            content_hash=self.content_hash, tlp=self.tlp,
            observed_at=self.publication_date or self.ingestion_date,
            collected_at=self.ingestion_date)

    # -- mention management ---------------------------------------------- #

    def add_mentions(self, mentions: List[EntityMention]) -> None:
        """Attach extracted mentions and populate the typed convenience buckets."""
        self.entity_mentions = dedupe_mentions(list(self.entity_mentions) + mentions)
        self._rebuild_buckets()

    def _rebuild_buckets(self) -> None:
        cve, mal, act, org, cty, infra, ioc, tech = ([] for _ in range(8))
        for m in self.entity_mentions:
            t, v = m.entity_type, m.value
            if not v:
                continue
            if t == EntityType.CVE:
                cve.append(v)
            elif t == EntityType.MALWARE_FAMILY:
                mal.append(v)
            elif t == EntityType.THREAT_ACTOR:
                act.append(v)
            elif t in (EntityType.ORGANIZATION, EntityType.COMPANY,
                       EntityType.GOVERNMENT_AGENCY):
                org.append(v)
            elif t == EntityType.COUNTRY:
                cty.append(v)
            elif t == EntityType.ATTACK_TECHNIQUE:
                tech.append(v)
            if t in (EntityType.DOMAIN, EntityType.IP, EntityType.URL,
                     EntityType.EMAIL, EntityType.HASH, EntityType.ASN):
                ioc.append(v)
                if t in (EntityType.DOMAIN, EntityType.IP, EntityType.ASN):
                    infra.append(v)
        self.cve_mentions = sorted(set(cve))
        self.malware_mentions = sorted(set(mal))
        self.actor_mentions = sorted(set(act))
        self.organization_mentions = sorted(set(org))
        self.country_mentions = sorted(set(cty))
        self.infrastructure_mentions = sorted(set(infra))
        self.iocs = sorted(set(ioc))
        self.mitre_techniques = sorted(set(tech))

    def entities_of(self, entity_type: EntityType) -> List[EntityMention]:
        et = EntityType.coerce(entity_type)
        return [m for m in self.entity_mentions if m.entity_type == et]

    @property
    def age_days(self) -> float:
        ref = self.publication_date or self.ingestion_date
        return max(0.0, (time.time() - ref) / 86400.0)

    @property
    def dedup_key(self) -> str:
        """Prefer canonical URL, else content hash — used by the dedup cluster."""
        return (self.canonical_url or self.content_hash).lower()

    # -- serialization ---------------------------------------------------- #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "article_id": self.article_id, "title": self.title, "url": self.url,
            "canonical_url": self.canonical_url, "summary": self.summary,
            "body": self.body, "source_name": self.source_name,
            "source_id": self.source_id, "source_domain": self.source_domain,
            "source_class": self.source_class.value, "author": self.author,
            "authors": list(self.authors), "language": self.language,
            "publication_date": self.publication_date,
            "ingestion_date": self.ingestion_date, "tags": list(self.tags),
            "tlp": self.tlp.value,
            "entity_mentions": [m.to_dict() for m in self.entity_mentions],
            "cve_mentions": list(self.cve_mentions),
            "malware_mentions": list(self.malware_mentions),
            "actor_mentions": list(self.actor_mentions),
            "organization_mentions": list(self.organization_mentions),
            "country_mentions": list(self.country_mentions),
            "infrastructure_mentions": list(self.infrastructure_mentions),
            "iocs": list(self.iocs), "mitre_techniques": list(self.mitre_techniques),
            "content_hash": self.content_hash, "simhash": self.simhash,
            "etag": self.etag, "last_modified": self.last_modified,
            "confidence": self.confidence, "evidence": list(self.evidence),
            "duplicate_of": self.duplicate_of, "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Article":
        art = cls(
            title=str(d.get("title", "")), url=str(d.get("url", "")),
            canonical_url=str(d.get("canonical_url", "")),
            summary=str(d.get("summary", "")), body=str(d.get("body", "")),
            source_name=str(d.get("source_name", "")),
            source_id=str(d.get("source_id", "")),
            source_domain=str(d.get("source_domain", "")),
            source_class=SourceClass.coerce(d.get("source_class")),
            author=str(d.get("author", "")),
            authors=list(d.get("authors", []) or []),
            language=str(d.get("language", "")),
            publication_date=float(d.get("publication_date", 0.0) or 0.0),
            ingestion_date=float(d.get("ingestion_date", time.time())
                                 or time.time()),
            tags=list(d.get("tags", []) or []), tlp=TLP.coerce(d.get("tlp")),
            entity_mentions=[EntityMention.from_dict(m)
                             for m in d.get("entity_mentions", []) or []],
            content_hash=str(d.get("content_hash", "")),
            simhash=int(d.get("simhash", 0) or 0),
            etag=str(d.get("etag", "")),
            last_modified=str(d.get("last_modified", "")),
            confidence=d.get("confidence"),
            evidence=list(d.get("evidence", []) or []),
            article_id=str(d.get("article_id", "")),
            duplicate_of=str(d.get("duplicate_of", "")),
            detail=dict(d.get("detail", {}) or {}),
        )
        # trust stored buckets if present, else rebuild from mentions
        for bucket in ("cve_mentions", "malware_mentions", "actor_mentions",
                       "organization_mentions", "country_mentions",
                       "infrastructure_mentions", "iocs", "mitre_techniques"):
            if d.get(bucket):
                setattr(art, bucket, list(d[bucket]))
        if not d.get("cve_mentions") and art.entity_mentions:
            art._rebuild_buckets()
        return art


__all__ = ["Article", "content_hash"]
