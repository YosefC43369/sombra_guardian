"""
cve_tracker.search.ranking — order search results by relevance (rule §52).

Relevance is a transparent additive score over signals the user actually cares
about: an exact CVE-id match, exact product/vendor match, title match,
description match, then severity and recency as tie-breakers. This is a *search
relevance* score only — it is deliberately NOT the intelligence priority score
and never leaks into the record (rule §52: 'do not create a fake security
score').
"""

from __future__ import annotations

from typing import List

from ..models import CVERecord
from ..utils import slugify
from .query import SearchQuery


def score(record: CVERecord, q: SearchQuery) -> float:
    s = 0.0
    text = (q.text or q.raw or "").lower().strip()
    tslug = slugify(text)

    if q.cve_id and record.cve_id == q.cve_id:
        s += 1000.0
    if text:
        if text == record.cve_id.lower():
            s += 800.0
        # exact product / vendor
        for p in record.products:
            if slugify(p.product) == tslug and tslug:
                s += 200.0
            elif tslug and tslug in slugify(p.product):
                s += 60.0
            if slugify(p.vendor) == tslug and tslug:
                s += 150.0
        # title / description
        title = (record.title or "").lower()
        desc = (record.description or "").lower()
        if text in title:
            s += 80.0
        for term in q.terms:
            tl = term.lower()
            if tl in title:
                s += 25.0
            elif tl in desc:
                s += 8.0

    # severity weight (mild)
    sev_weight = {"CRITICAL": 20, "HIGH": 14, "MEDIUM": 8, "LOW": 3}.get(record.severity, 0)
    s += sev_weight
    if record.in_kev:
        s += 15.0
    # recency tie-breaker (small, normalized)
    ref = record.published_at or record.first_seen_at or 0
    s += min(ref / 1e12, 10.0)
    return s


def rank(records: List[CVERecord], q: SearchQuery) -> List[CVERecord]:
    return sorted(records, key=lambda r: score(r, q), reverse=True)
