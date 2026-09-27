"""
entity_fusion.engines.certificate_engine — correlate identities via public TLS
certificates.

Certificate Transparency (the same public log the ``osint`` crt.sh source and
the repo's integrity_ledger use) exposes, for every issued cert: subject, SAN
list, issuer, fingerprint and validity window. A shared fingerprint or an
overlapping SAN set is a strong infrastructure-correlation signal. This engine
normalises a certificate record and emits the SAN hostnames as discovered domain
entities linked back to the certificate. It reads the record it is given — the
CT fetch itself is an enricher.
"""

from __future__ import annotations

import re

from ..entity import Entity, EntityType, Evidence, SourceRef, RelationType, Relationship
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult


def _fingerprint(raw: str) -> str:
    """Normalise a fingerprint to lower-case hex without separators."""
    return re.sub(r"[^0-9a-f]", "", (raw or "").lower())


class CertificateEngine(CorrelationEngine):
    name = "certificate_engine"
    handles = (EntityType.CERTIFICATE,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        fp = _fingerprint(entity.value) or _fingerprint(
            str(entity.metadata.get("fingerprint", "")))
        if fp:
            entity.normalized = fp
            result.derived["certificate_fingerprint"] = fp

        # SAN list may arrive as a list or a comma/space separated string
        raw_sans = entity.metadata.get("san") or entity.metadata.get("dns_names") or []
        if isinstance(raw_sans, str):
            raw_sans = re.split(r"[,\s]+", raw_sans)
        sans = []
        for name in raw_sans:
            d = norm.canonical_domain(str(name))
            if d and d not in sans:
                sans.append(d)
        if sans:
            result.derived["san"] = sans
            for d in sans:
                child = Entity(type=EntityType.DOMAIN, value=d)
                child.add_source(SourceRef(provider="certificate",
                                           detail="SAN entry"))
                child.add_relationship(Relationship(
                    target_id=entity.id, type=RelationType.SHARES_CERTIFICATE))
                result.entities.append(child)
            result.evidence.append(Evidence(
                kind="certificate_sans", value=str(len(sans)), weight=0.1,
                note=f"{len(sans)} SAN host(s) linked to this certificate"))

        subject = entity.metadata.get("subject") or entity.metadata.get("cn")
        if subject:
            result.derived["cert_subject"] = str(subject)
        return result
