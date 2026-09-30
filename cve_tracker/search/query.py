"""
cve_tracker.search.query — parse a user query string into a structured query.

Supports the command grammar from rule §19: a bare CVE id, free text, or
field tokens (``severity:critical``, ``cvss:9``, ``vendor:microsoft``,
``cwe:CWE-79``, ``kev``, ``recent``). The parser is forgiving — unknown tokens
fold into the free-text term — so a user never gets a syntax error, just the
closest reasonable search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from ..utils import normalize_cve_id, normalize_cwe_id


@dataclass
class SearchQuery:
    raw: str = ""
    cve_id: Optional[str] = None
    text: str = ""
    severity: Optional[str] = None
    min_cvss: Optional[float] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    cwe: Optional[str] = None
    kev_only: bool = False
    recent: bool = False
    terms: List[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not any([
            self.cve_id, self.text, self.severity, self.min_cvss, self.vendor,
            self.product, self.cwe, self.kev_only, self.recent,
        ])

    @property
    def kind(self) -> str:
        """The single dominant intent, used to pick the best index path."""
        if self.cve_id:
            return "cve_id"
        if self.kev_only:
            return "kev"
        if self.cwe:
            return "cwe"
        if self.vendor:
            return "vendor"
        if self.product:
            return "product"
        if self.severity:
            return "severity"
        if self.min_cvss is not None:
            return "cvss"
        if self.recent:
            return "recent"
        return "text"


_SEVERITIES = {"critical", "high", "medium", "low", "none"}
_FIELD_RE = re.compile(r"(\w+):(\S+)")


def parse(text: str) -> SearchQuery:
    q = SearchQuery(raw=(text or "").strip())
    if not q.raw:
        q.recent = True
        return q

    # A bare CVE id short-circuits.
    cid = normalize_cve_id(q.raw)
    if cid:
        q.cve_id = cid
        return q

    remaining_terms: List[str] = []
    for token in q.raw.split():
        low = token.lower()
        m = _FIELD_RE.match(token)
        if m:
            key, val = m.group(1).lower(), m.group(2)
            if _apply_field(q, key, val):
                continue
        if low in ("kev", "known-exploited", "exploited"):
            q.kev_only = True
            continue
        if low in ("recent", "latest", "new", "ล่าสุด"):
            q.recent = True
            continue
        if low in _SEVERITIES:
            q.severity = low.upper()
            continue
        cid2 = normalize_cve_id(token)
        if cid2:
            q.cve_id = cid2
            continue
        cwe = normalize_cwe_id(token)
        if cwe:
            q.cwe = cwe
            continue
        remaining_terms.append(token)

    q.terms = remaining_terms
    q.text = " ".join(remaining_terms).strip()
    return q


def _apply_field(q: SearchQuery, key: str, val: str) -> bool:
    if key in ("severity", "sev"):
        if val.lower() in _SEVERITIES:
            q.severity = val.upper()
            return True
    elif key in ("cvss", "score"):
        try:
            q.min_cvss = float(val.lstrip(">=").strip())
            return True
        except ValueError:
            return False
    elif key in ("vendor",):
        q.vendor = val
        return True
    elif key in ("product", "prod"):
        q.product = val
        return True
    elif key in ("cwe",):
        q.cwe = normalize_cwe_id(val) or val
        return True
    return False
