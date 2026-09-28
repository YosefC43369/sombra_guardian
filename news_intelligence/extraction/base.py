"""
news_intelligence.extraction.base — the extractor contract and shared helpers.

Every extractor is PURE: it takes text (and optional article context) and returns
a list of ``EntityMention``. No network, no storage — so each is unit-tested
offline against fixtures. The base wires in the Threat Actor Intelligence Engine's
proven ``extract`` miner (IOCs/CVEs/techniques) so the news engine never
re-implements indicator parsing (spec: "avoid duplicate extraction logic").
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models.entity import EntityMention, EntityType

# Reuse the CTI engine's battle-tested indicator miner where present.
try:
    from threat_actor_intelligence.ingestion.extract import extract as _tai_extract
    from threat_actor_intelligence.models.ioc import IOCType as _TAIIOCType
    HAVE_TAI_EXTRACT = True
except Exception:  # pragma: no cover
    _tai_extract = None
    _TAIIOCType = None
    HAVE_TAI_EXTRACT = False


# Map the CTI IOCType names onto our EntityType.
_IOCTYPE_TO_ENTITY = {
    "url": EntityType.URL,
    "domain": EntityType.DOMAIN,
    "ip": EntityType.IP,
    "ipv4": EntityType.IP,
    "ipv6": EntityType.IP,
    "email": EntityType.EMAIL,
    "md5": EntityType.HASH,
    "sha1": EntityType.HASH,
    "sha256": EntityType.HASH,
    "asn": EntityType.ASN,
}


def context_of(text: str, start: int, end: int, *, radius: int = 60) -> str:
    if start < 0 or end < 0:
        return ""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return re.sub(r"\s+", " ", text[lo:hi]).strip()


class BaseExtractor:
    name = "base"
    entity_types: List[EntityType] = []

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- shared helper: run the CTI miner once and cache on the call site -- #
    @staticmethod
    def _tai(text: str):
        if HAVE_TAI_EXTRACT and text:
            try:
                return _tai_extract(text, mine_names=False)
            except Exception:
                return None
        return None


def _mk(entity_type: EntityType, value: str, *, surface: str = "",
        extractor: str = "", weight: float = 1.0, text: str = "",
        span: Optional[Any] = None, detail: Optional[Dict[str, Any]] = None
        ) -> EntityMention:
    start = end = -1
    ctx = ""
    if span is not None:
        start, end = span
        ctx = context_of(text, start, end)
    return EntityMention(entity_type=entity_type, value=value,
                         surface=surface or value, extractor=extractor,
                         weight=weight, start=start, end=end, context=ctx,
                         detail=detail or {})


__all__ = ["BaseExtractor", "context_of", "HAVE_TAI_EXTRACT",
           "_IOCTYPE_TO_ENTITY", "_mk"]
