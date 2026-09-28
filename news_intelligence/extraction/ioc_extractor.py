"""
news_intelligence.extraction.ioc_extractor — publicly-reported IOC extraction.

Extracts domains, IPs, URLs, emails, hashes and ASNs from article text and emits
them as ``EntityMention`` objects. It delegates the hard indicator-parsing (defang
handling, canonicalization, false-positive domain filtering) to the Threat Actor
Intelligence Engine's ``extract`` miner so both engines dedupe indicators
identically. A stdlib fallback keeps IOC extraction working if the CTI miner is
absent.

SECURITY BOUNDARY: these are *references* to publicly-reported indicators. Nothing
here downloads a sample, resolves a domain, or contacts an indicator.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from ..models.entity import EntityMention, EntityType
from .base import BaseExtractor, HAVE_TAI_EXTRACT, _IOCTYPE_TO_ENTITY, _mk

# stdlib fallback patterns (used only when the CTI miner is unavailable)
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\[?\.\]?)){3}"
                    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_URL_RE = re.compile(r"\b(?:h[xX]{2}ps?|https?)://[^\s<>\"')]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.\[\]-]+\.[a-z]{2,}\b", re.IGNORECASE)
_ASN_RE = re.compile(r"\bAS\d{2,7}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?))+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|us|uk|de|fr|nl))\b",
    re.IGNORECASE)
_FP = {"attack.mitre.org", "cve.mitre.org", "nvd.nist.gov", "cisa.gov",
       "github.com", "twitter.com", "example.com", "microsoft.com"}


def _defang(v: str) -> str:
    return v.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")


class IOCExtractor(BaseExtractor):
    name = "ioc"
    entity_types = [EntityType.DOMAIN, EntityType.IP, EntityType.URL,
                    EntityType.EMAIL, EntityType.HASH, EntityType.ASN]

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        if HAVE_TAI_EXTRACT:
            return self._extract_via_tai(text)
        return self._extract_fallback(text)

    def _extract_via_tai(self, text: str) -> List[EntityMention]:
        ex = self._tai(text)
        out: List[EntityMention] = []
        if ex is None:
            return self._extract_fallback(text)
        for ioc in ex.iocs:
            itype = getattr(ioc.ioc_type, "value", str(ioc.ioc_type)).lower()
            et = _IOCTYPE_TO_ENTITY.get(itype)
            if et is None:
                continue
            detail = {"ioc_type": itype}
            out.append(_mk(et, ioc.value, extractor=self.name, weight=0.9,
                           detail=detail))
        return out

    def _extract_fallback(self, text: str) -> List[EntityMention]:
        out: List[EntityMention] = []
        for m in _URL_RE.finditer(text):
            out.append(_mk(EntityType.URL, _defang(m.group(0)).lower(),
                           surface=m.group(0), extractor=self.name, weight=0.85,
                           text=text, span=m.span()))
        for m in _EMAIL_RE.finditer(text):
            out.append(_mk(EntityType.EMAIL, _defang(m.group(0)).lower(),
                           surface=m.group(0), extractor=self.name, weight=0.85,
                           text=text, span=m.span()))
        for m in _HASH_RE.finditer(text):
            out.append(_mk(EntityType.HASH, m.group(0).lower(),
                           surface=m.group(0), extractor=self.name, weight=0.9,
                           text=text, span=m.span()))
        for m in _IP_RE.finditer(text):
            out.append(_mk(EntityType.IP, _defang(m.group(0)),
                           surface=m.group(0), extractor=self.name, weight=0.85,
                           text=text, span=m.span()))
        for m in _ASN_RE.finditer(text):
            out.append(_mk(EntityType.ASN, m.group(0).upper(),
                           surface=m.group(0), extractor=self.name, weight=0.8,
                           text=text, span=m.span()))
        for m in _DOMAIN_RE.finditer(text):
            val = _defang(m.group(0)).lower()
            if val in _FP:
                continue
            out.append(_mk(EntityType.DOMAIN, val, surface=m.group(0),
                           extractor=self.name, weight=0.75, text=text,
                           span=m.span()))
        return out


__all__ = ["IOCExtractor"]
