"""
threat_actor_intelligence.models.infrastructure — adversary infrastructure nodes.

An ``Infrastructure`` node groups the public network facts that reporting ties
together: a domain and the IPs it resolved to, an ASN and hosting provider, TLS
certificate fingerprints, and any geo/cloud-region hints (populated via the
Geo-OSINT engine where available). Infrastructure is what lets campaigns be
correlated by *overlap* — two campaigns pointing at the same certificate or the
same /24 is an explainable, evidence-backed link, not an assertion of identity.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .confidence import ConfidenceModel, confidence_from_evidence
from .evidence import EvidenceBundle


class InfraType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    NETBLOCK = "netblock"            # CIDR
    ASN = "asn"
    CERTIFICATE = "certificate"
    HOSTING = "hosting"             # provider/registrar
    NAMESERVER = "nameserver"
    URL = "url"
    SERVER = "server"                # abstract C2/staging server node

    @classmethod
    def coerce(cls, raw: Any) -> "InfraType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.SERVER


@dataclass
class Infrastructure:
    infra_type: InfraType
    value: str                       # canonical (domain, ip, AS####, fingerprint)
    role: str = ""                   # c2 | staging | phishing | redirector | ...
    asn: str = ""
    hosting_provider: str = ""
    country: str = ""                # ISO-3166 alpha-2 (from Geo-OSINT), as reported
    cloud_region: str = ""
    resolves_to: List[str] = field(default_factory=list)   # ip values
    domains: List[str] = field(default_factory=list)        # domains on this node
    certificates: List[str] = field(default_factory=list)   # fingerprints
    campaigns: List[str] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    references: List[str] = field(default_factory=list)
    report_ids: List[str] = field(default_factory=list)
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[ConfidenceModel] = None

    def __post_init__(self) -> None:
        self.infra_type = InfraType.coerce(self.infra_type)
        if isinstance(self.evidence, list):
            self.evidence = EvidenceBundle.from_list(self.evidence)
        if self.country:
            self.country = self.country.strip().upper()[:2]

    @property
    def infra_id(self) -> str:
        return "infra-" + hashlib.sha256(
            f"{self.infra_type.value}|{self.value}".encode("utf-8")
        ).hexdigest()[:20]

    def overlap_keys(self) -> List[str]:
        """Keys that, if shared with another node, imply infrastructure overlap.
        Used by the infrastructure correlation engine."""
        keys: List[str] = []
        if self.asn:
            keys.append(f"asn:{self.asn}")
        for c in self.certificates:
            keys.append(f"cert:{c}")
        for ip in self.resolves_to:
            keys.append(f"ip:{ip}")
        if self.infra_type == InfraType.IP:
            keys.append(f"ip:{self.value}")
        for d in self.domains:
            keys.append(f"domain:{d}")
        if self.hosting_provider:
            keys.append(f"host:{self.hosting_provider.lower()}")
        return sorted(set(keys))

    def touch(self, when: float) -> None:
        self.first_seen = when if not self.first_seen else min(self.first_seen, when)
        self.last_seen = max(self.last_seen, when)

    def link(self, field_name: str, value: str) -> None:
        lst = getattr(self, field_name, None)
        if isinstance(lst, list) and value and value not in lst:
            lst.append(value)

    def recompute_confidence(self, *, now: Optional[float] = None) -> ConfidenceModel:
        now = now if now is not None else time.time()
        self.confidence = confidence_from_evidence(self.evidence, now=now)
        return self.confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "infra_id": self.infra_id, "infra_type": self.infra_type.value,
            "value": self.value, "role": self.role, "asn": self.asn,
            "hosting_provider": self.hosting_provider, "country": self.country,
            "cloud_region": self.cloud_region, "resolves_to": list(self.resolves_to),
            "domains": list(self.domains), "certificates": list(self.certificates),
            "campaigns": list(self.campaigns), "actors": list(self.actors),
            "malware_families": list(self.malware_families),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "references": list(self.references), "report_ids": list(self.report_ids),
            "evidence": self.evidence.to_list(),
            "confidence": self.confidence.to_dict() if self.confidence else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Infrastructure":
        node = cls(
            infra_type=InfraType.coerce(d.get("infra_type")),
            value=str(d.get("value", "")), role=str(d.get("role", "")),
            asn=str(d.get("asn", "")),
            hosting_provider=str(d.get("hosting_provider", "")),
            country=str(d.get("country", "")),
            cloud_region=str(d.get("cloud_region", "")),
            resolves_to=list(d.get("resolves_to", []) or []),
            domains=list(d.get("domains", []) or []),
            certificates=list(d.get("certificates", []) or []),
            campaigns=list(d.get("campaigns", []) or []),
            actors=list(d.get("actors", []) or []),
            malware_families=list(d.get("malware_families", []) or []),
            first_seen=float(d.get("first_seen", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            references=list(d.get("references", []) or []),
            report_ids=list(d.get("report_ids", []) or []),
            evidence=EvidenceBundle.from_list(d.get("evidence", []) or []),
        )
        if d.get("confidence"):
            node.confidence = ConfidenceModel.from_dict(d["confidence"])
        return node


__all__ = ["InfraType", "Infrastructure"]
