"""
cve_tracker.enrichment — turn a normalized record into a fully-enriched one.

The public entry point is :func:`enrich`, which runs every enrichment engine in
order over a :class:`CVERecord`:

    1. canonicalise vendor names on products
    2. decode / choose the primary CVSS score and copy display scalars
    3. fill CWE names from the catalogue
    4. (references are classified during ingestion; here we just recount)
    5. compute exploit maturity from facts (KEV + references)
    6. rebuild the timeline

It is idempotent and side-effect-free beyond mutating the passed record, so it
can be re-run whenever new source data arrives.
"""

from __future__ import annotations

from typing import Optional

from ..enums import Severity
from ..models import CVERecord
from ..utils import now_epoch
from . import cvss as cvss_engine
from . import cwe as cwe_engine
from . import exploit_status
from . import products as products_engine
from . import timeline as timeline_engine

# Re-export the sub-engines so callers can `from cve_tracker.enrichment import cvss`.
from . import cvss, cwe, cpe, kev, references, vendors, products, exploit_status as exploit  # noqa: F401
from . import timeline, epss  # noqa: F401


def enrich(record: CVERecord, *, cvss_e_token: Optional[str] = None) -> CVERecord:
    """Run all enrichment over ``record`` in place and return it."""
    # 1. vendor canonicalisation
    products_engine.canonicalize_products(record.products)

    # 2. CVSS: pick the primary and copy display scalars (never invent)
    primary = cvss_engine.pick_primary(record.cvss_scores)
    if primary is not None:
        record.cvss_score = primary.base_score
        record.cvss_version = primary.version
        record.cvss_vector = primary.vector
        if primary.base_severity and primary.base_severity != Severity.UNKNOWN.value:
            record.severity = primary.base_severity
        elif primary.base_score is not None:
            record.severity = Severity.from_cvss_score(
                primary.base_score, version=primary.version).value
    # If no CVSS at all, leave severity as whatever a source asserted (or UNKNOWN).

    # 3. CWE names
    record.weaknesses = cwe_engine.merge_weaknesses(record.weaknesses)
    for w in record.weaknesses:
        if not w.name:
            w.name = cwe_engine.catalog_name(w.cwe_id)

    # 5. exploit maturity (references already classified upstream)
    exploit_status.compute(record, cvss_e_token=cvss_e_token)

    # 6. timeline
    timeline_engine.rebuild(record)

    record.enriched_at = now_epoch()
    return record


__all__ = [
    "enrich",
    "cvss", "cwe", "cpe", "kev", "references", "vendors", "products",
    "exploit_status", "timeline", "epss",
]
