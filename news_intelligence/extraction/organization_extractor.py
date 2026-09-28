"""
news_intelligence.extraction.organization_extractor — org / company / agency /
cloud-provider mining.

Dictionary track over ``reference.ORGANIZATIONS`` / ``GOVERNMENT_AGENCIES`` /
``CLOUD_PROVIDERS`` (vendors, security firms, national agencies, cloud platforms),
plus a conservative pattern track for corporate suffixes (Inc, Ltd, GmbH, Corp,
LLC) that catches victim/organization names news reports commonly use. Government
agencies and cloud providers get their own ``EntityType`` so the country/vendor
comparison layers can separate an advisory issuer from a victim.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Set

from ..models.entity import EntityMention, EntityType
from .base import BaseExtractor, _mk
from .reference import ORGANIZATIONS, GOVERNMENT_AGENCIES, CLOUD_PROVIDERS

_CORP_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.\-]+(?:\s[A-Z][A-Za-z0-9&.\-]+){0,3})\s+"
    r"(Inc\.?|Incorporated|Ltd\.?|Limited|LLC|GmbH|Corp\.?|Corporation|"
    r"Group|Holdings|Technologies|Systems|Solutions|AG|S\.A\.|PLC)\b")
_STOP = {"The", "This", "A", "An", "Threat", "Security"}


class OrganizationExtractor(BaseExtractor):
    name = "organization"
    entity_types = [EntityType.ORGANIZATION, EntityType.COMPANY,
                    EntityType.GOVERNMENT_AGENCY, EntityType.CLOUD_PROVIDER]

    def __init__(self) -> None:
        self._orgs: Set[str] = {o.lower() for o in ORGANIZATIONS}
        self._agencies: Set[str] = {o.lower() for o in GOVERNMENT_AGENCIES}
        self._cloud: Set[str] = {o.lower() for o in CLOUD_PROVIDERS}
        self._display = {}
        for o in ORGANIZATIONS | GOVERNMENT_AGENCIES | CLOUD_PROVIDERS:
            self._display[o.lower()] = o

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        out: List[EntityMention] = []
        seen_spans: List[tuple] = []
        lowered = text.lower()

        for name_lc, display in self._display.items():
            start = 0
            while True:
                pos = lowered.find(name_lc, start)
                if pos < 0:
                    break
                before = text[pos - 1] if pos > 0 else " "
                after = (text[pos + len(name_lc)]
                         if pos + len(name_lc) < len(text) else " ")
                if (not before.isalnum()) and (not after.isalnum()):
                    if name_lc in self._agencies:
                        et = EntityType.GOVERNMENT_AGENCY
                    elif name_lc in self._cloud:
                        et = EntityType.CLOUD_PROVIDER
                    else:
                        et = EntityType.ORGANIZATION
                    out.append(_mk(et, display,
                                   surface=text[pos:pos + len(name_lc)],
                                   extractor=self.name + ":dict", weight=0.85,
                                   text=text, span=(pos, pos + len(name_lc))))
                    seen_spans.append((pos, pos + len(name_lc)))
                start = pos + len(name_lc)

        for m in _CORP_RE.finditer(text):
            if self._overlaps(m.span(1), seen_spans):
                continue
            cand = m.group(1).strip()
            if cand.split()[0] in _STOP:
                continue
            full = f"{cand} {m.group(2)}".strip()
            out.append(_mk(EntityType.COMPANY, full, surface=full,
                           extractor=self.name + ":suffix", weight=0.6,
                           text=text, span=(m.start(1), m.end(2))))
        return out

    @staticmethod
    def _overlaps(span, spans) -> bool:
        s, e = span
        return any(not (e <= a or s >= b) for a, b in spans)


__all__ = ["OrganizationExtractor"]
