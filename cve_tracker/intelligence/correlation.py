"""
cve_tracker.intelligence.correlation — relate a CVE to vendors/products/CWEs/KEV.

Thin query layer over the repository's indexed child tables (rule §18). It
answers 'CVEs related to Microsoft', 'CVEs with CWE-79', 'CVEs with CVSS >= 9',
'CVEs added to KEV' by delegating to the indexed queries — never a full scan and
never loading the whole table into memory (rule §47).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..models import CVERecord
from ..storage.repository import CVERepository


@dataclass
class CorrelationResult:
    kind: str
    key: str
    records: List[CVERecord] = field(default_factory=list)
    total: int = 0


class CorrelationEngine:
    def __init__(self, repo: CVERepository):
        self.repo = repo

    def related_by_vendor(self, vendor: str, *, limit: int = 20) -> CorrelationResult:
        recs = self.repo.by_vendor(vendor, limit=limit)
        return CorrelationResult("vendor", vendor, recs, len(recs))

    def related_by_product(self, product: str, *, limit: int = 20) -> CorrelationResult:
        recs = self.repo.by_product(product, limit=limit)
        return CorrelationResult("product", product, recs, len(recs))

    def related_by_cwe(self, cwe_id: str, *, limit: int = 20) -> CorrelationResult:
        recs = self.repo.by_cwe(cwe_id, limit=limit)
        return CorrelationResult("cwe", cwe_id, recs, len(recs))

    def with_min_cvss(self, min_cvss: float, *, limit: int = 20) -> CorrelationResult:
        recs = self.repo.by_min_cvss(min_cvss, limit=limit)
        return CorrelationResult("cvss", f">={min_cvss}", recs, len(recs))

    def in_kev(self, *, limit: int = 20) -> CorrelationResult:
        recs = self.repo.kev_records(limit=limit)
        return CorrelationResult("kev", "known-exploited", recs, len(recs))

    def affected_by(self, product: str, version: str, *, vendor: str = "",
                    limit: int = 20) -> List[CVERecord]:
        """CVEs whose affected-version ranges cover ``version`` for a given
        product (rule §18 + version matching). Only records where the range
        check is a definite match are returned — an 'undetermined' (None) range
        is excluded so we never claim a version is affected without evidence."""
        from ..enrichment.products import is_version_affected, match_product
        from ..enrichment.vendors import match_vendor
        candidates = self.repo.by_product(product, limit=max(limit * 3, 60))
        out: List[CVERecord] = []
        for rec in candidates:
            if vendor and not any(match_vendor(v, [vendor]) for v in rec.vendors):
                continue
            hit = False
            for p in rec.products:
                if not match_product(p.product, [product]):
                    continue
                if is_version_affected(p, version) is True:
                    hit = True
                    break
            if hit:
                out.append(rec)
            if len(out) >= limit:
                break
        return out

    def related_to(self, record: CVERecord, *, limit: int = 8) -> List[CVERecord]:
        """Find CVEs sharing this record's first vendor or first CWE, excluding
        the record itself. A cheap 'see also' for the detail view."""
        seen = {record.cve_id}
        out: List[CVERecord] = []
        for vendor in record.vendors[:1]:
            for r in self.repo.by_vendor(vendor, limit=limit + 1):
                if r.cve_id not in seen:
                    out.append(r)
                    seen.add(r.cve_id)
        for cwe in record.cwe_ids[:1]:
            if len(out) >= limit:
                break
            for r in self.repo.by_cwe(cwe, limit=limit + 1):
                if r.cve_id not in seen:
                    out.append(r)
                    seen.add(r.cve_id)
        return out[:limit]
