"""
news_intelligence.extraction.cve_extractor — CVE / CWE / CAPEC identifier mining.

Extracts and normalizes vulnerability identifiers from article text: CVE ids
(CVE-YYYY-NNNN+), CWE ids (CWE-NNN) and CAPEC ids (CAPEC-NNN). Emits
``EntityMention`` objects with the surrounding context so downstream layers can
tell "patched CVE-… " from "actively exploited CVE-…" without re-reading the body.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from ..models.entity import EntityMention, EntityType
from .base import BaseExtractor, _mk

_CVE_RE = re.compile(r"\bCVE[-\s]?(\d{4})[-\s]?(\d{4,7})\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE[-\s]?(\d{1,4})\b", re.IGNORECASE)
_CAPEC_RE = re.compile(r"\bCAPEC[-\s]?(\d{1,4})\b", re.IGNORECASE)

# cue words that hint a CVE is described as exploited (recorded in detail, not
# asserted by the engine — the reader/report decides how to treat it).
_EXPLOIT_CUES = re.compile(
    r"(?i)\b(exploit|exploited|in the wild|actively|zero[- ]day|0[- ]day|"
    r"weaponiz|proof[- ]of[- ]concept|poc)\b")
_PATCH_CUES = re.compile(r"(?i)\b(patch|fixed|mitigat|update available|advisory)\b")


class CVEExtractor(BaseExtractor):
    name = "cve"
    entity_types = [EntityType.CVE, EntityType.CWE, EntityType.CAPEC]

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        out: List[EntityMention] = []
        for m in _CVE_RE.finditer(text):
            value = f"CVE-{m.group(1)}-{m.group(2)}"
            lo = max(0, m.start() - 80)
            hi = min(len(text), m.end() + 80)
            window = text[lo:hi]
            detail = {
                "exploit_context": bool(_EXPLOIT_CUES.search(window)),
                "patch_context": bool(_PATCH_CUES.search(window)),
            }
            out.append(_mk(EntityType.CVE, value, surface=m.group(0),
                           extractor=self.name, weight=0.97, text=text,
                           span=m.span(), detail=detail))
        for m in _CWE_RE.finditer(text):
            out.append(_mk(EntityType.CWE, f"CWE-{int(m.group(1))}",
                           surface=m.group(0), extractor=self.name, weight=0.9,
                           text=text, span=m.span()))
        for m in _CAPEC_RE.finditer(text):
            out.append(_mk(EntityType.CAPEC, f"CAPEC-{int(m.group(1))}",
                           surface=m.group(0), extractor=self.name, weight=0.9,
                           text=text, span=m.span()))
        return out


__all__ = ["CVEExtractor"]
