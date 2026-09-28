"""
threat_actor_intelligence.models.report — an ingested public CTI report.

A ``Report`` is the provenance root of almost everything else: an advisory, a
vendor blog post, a research paper, a feed item. It records the source and, once
parsed, the entities it references (actors/campaigns/malware/IOCs/techniques).
The ``content_hash`` + ``etag``/``last_modified`` fields drive incremental
ingestion — a report already stored with the same content hash is skipped.

The report never stores the full article body verbatim beyond a bounded summary
and the extracted structured facts; it stores the ``url`` so a reader can always
reach the primary source.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .evidence import EvidenceRef, SourceClass, TLP


def content_fingerprint(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


@dataclass
class Report:
    title: str
    url: str = ""
    vendor: str = ""                 # publishing organization
    source: str = ""                 # ingestor/provider name
    source_class: SourceClass = SourceClass.UNKNOWN
    published_at: float = 0.0
    collected_at: float = field(default_factory=time.time)
    summary: str = ""
    authors: List[str] = field(default_factory=list)
    tlp: TLP = TLP.CLEAR
    language: str = ""
    # extracted structured facts (ids into their respective stores)
    actor_ids: List[str] = field(default_factory=list)
    campaign_ids: List[str] = field(default_factory=list)
    family_ids: List[str] = field(default_factory=list)
    ioc_ids: List[str] = field(default_factory=list)
    technique_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    # raw extracted names before resolution (preserve source wording)
    actor_names: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    # incremental-ingestion provenance
    content_hash: str = ""
    etag: str = ""
    last_modified: str = ""
    provider_version: str = ""
    report_id: str = ""

    def __post_init__(self) -> None:
        self.source_class = SourceClass.coerce(self.source_class)
        self.tlp = TLP.coerce(self.tlp)
        if not self.content_hash:
            self.content_hash = content_fingerprint(self.title, self.url, self.summary)
        if not self.report_id:
            self.report_id = "rep-" + hashlib.sha256(
                (self.url or self.title).encode("utf-8")).hexdigest()[:20]

    def as_evidence(self, *, excerpt: str = "") -> EvidenceRef:
        """Build an ``EvidenceRef`` citing this report, for attaching to the
        entities extracted from it."""
        return EvidenceRef(
            provider=self.source or self.vendor or "report",
            source_class=self.source_class, title=self.title, source_url=self.url,
            external_id=self.report_id, excerpt=excerpt or self.summary[:280],
            content_hash=self.content_hash, tlp=self.tlp,
            observed_at=self.published_at or self.collected_at,
            collected_at=self.collected_at)

    def link(self, field_name: str, value: str) -> None:
        lst = getattr(self, field_name, None)
        if isinstance(lst, list) and value and value not in lst:
            lst.append(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id, "title": self.title, "url": self.url,
            "vendor": self.vendor, "source": self.source,
            "source_class": self.source_class.value,
            "published_at": self.published_at, "collected_at": self.collected_at,
            "summary": self.summary, "authors": list(self.authors),
            "tlp": self.tlp.value, "language": self.language,
            "actor_ids": list(self.actor_ids), "campaign_ids": list(self.campaign_ids),
            "family_ids": list(self.family_ids), "ioc_ids": list(self.ioc_ids),
            "technique_ids": list(self.technique_ids), "cve_ids": list(self.cve_ids),
            "actor_names": list(self.actor_names),
            "malware_names": list(self.malware_names),
            "tags": list(self.tags), "references": list(self.references),
            "content_hash": self.content_hash, "etag": self.etag,
            "last_modified": self.last_modified,
            "provider_version": self.provider_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Report":
        return cls(
            title=str(d.get("title", "")), url=str(d.get("url", "")),
            vendor=str(d.get("vendor", "")), source=str(d.get("source", "")),
            source_class=SourceClass.coerce(d.get("source_class")),
            published_at=float(d.get("published_at", 0.0) or 0.0),
            collected_at=float(d.get("collected_at", time.time()) or time.time()),
            summary=str(d.get("summary", "")), authors=list(d.get("authors", []) or []),
            tlp=TLP.coerce(d.get("tlp")), language=str(d.get("language", "")),
            actor_ids=list(d.get("actor_ids", []) or []),
            campaign_ids=list(d.get("campaign_ids", []) or []),
            family_ids=list(d.get("family_ids", []) or []),
            ioc_ids=list(d.get("ioc_ids", []) or []),
            technique_ids=list(d.get("technique_ids", []) or []),
            cve_ids=list(d.get("cve_ids", []) or []),
            actor_names=list(d.get("actor_names", []) or []),
            malware_names=list(d.get("malware_names", []) or []),
            tags=list(d.get("tags", []) or []),
            references=list(d.get("references", []) or []),
            content_hash=str(d.get("content_hash", "")), etag=str(d.get("etag", "")),
            last_modified=str(d.get("last_modified", "")),
            provider_version=str(d.get("provider_version", "")),
            report_id=str(d.get("report_id", "")),
        )


__all__ = ["Report", "content_fingerprint"]
