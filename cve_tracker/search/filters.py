"""
cve_tracker.search.filters — in-memory refinement predicates.

The repository's indexed queries do the heavy lifting (never a full scan — rule
§47), but a query can carry several constraints at once (e.g. ``vendor:cisco
severity:critical``). After the primary indexed fetch, these predicates refine
the candidate set for the secondary constraints, which is cheap because the
candidate set is already bounded by the index.
"""

from __future__ import annotations

from typing import List

from ..enums import Severity
from ..models import CVERecord
from ..enrichment.vendors import match_vendor
from ..enrichment.products import match_product
from .query import SearchQuery


def apply(records: List[CVERecord], q: SearchQuery) -> List[CVERecord]:
    out = records
    if q.severity:
        out = [r for r in out if (r.severity or "").upper() == q.severity.upper()]
    if q.min_cvss is not None:
        out = [r for r in out if r.cvss_score is not None and r.cvss_score >= q.min_cvss]
    if q.kev_only:
        out = [r for r in out if r.in_kev]
    if q.vendor:
        out = [r for r in out if any(match_vendor(v, [q.vendor]) for v in r.vendors)]
    if q.product:
        out = [r for r in out
               if any(match_product(p.product, [q.product]) for p in r.products)]
    if q.cwe:
        out = [r for r in out if q.cwe in r.cwe_ids]
    if q.text and not (q.vendor or q.product):
        low = q.text.lower()
        out = [r for r in out
               if low in (r.cve_id.lower() + " " + (r.title or "").lower()
                          + " " + (r.description or "").lower())]
    return out
