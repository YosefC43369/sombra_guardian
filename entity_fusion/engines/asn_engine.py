"""
entity_fusion.engines.asn_engine — normalize an ASN record to a canonical
integer key offline (``AS15169`` / ``as15169`` / ``15169`` → ``15169``),
reusing ``osint.utils.validators.normalize_asn`` when available. BGP/prefix
enrichment (via the BGPView source) is an enricher, not this engine.
"""

from __future__ import annotations

import re

from ..entity import Entity, EntityType, Evidence
from .base import CorrelationEngine, EngineResult

_ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)


def normalize_asn(raw: str):
    try:
        from osint.utils.validators import normalize_asn as _n
        return _n(raw)
    except Exception:
        m = _ASN_RE.match((raw or "").strip())
        if not m:
            return None
        value = int(m.group(1))
        return value if 0 < value < 4294967295 else None


class ASNEngine(CorrelationEngine):
    name = "asn_engine"
    handles = (EntityType.ASN,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        asn = normalize_asn(entity.value)
        if asn is None:
            result.evidence.append(Evidence(
                kind="asn_invalid", value=entity.value, weight=-0.2,
                note="not a valid public ASN"))
            return result
        entity.normalized = f"as{asn}"
        result.derived["asn"] = asn
        result.derived["asn_label"] = f"AS{asn}"
        entity.add_alias(f"AS{asn}")
        return result
