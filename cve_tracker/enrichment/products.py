"""
cve_tracker.enrichment.products — product-name normalization and matching.

Complements :mod:`vendors`: canonicalises the vendor field on every
:class:`AffectedProduct` in place, provides a product matcher for subscription
filters ('notify me about Apache HTTP Server'), and an affected-version check
that leans on :mod:`cve_tracker.utils.versioning`.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import AffectedProduct
from ..utils import slugify, version_in_range
from .vendors import canonical_vendor


def canonicalize_products(products: List[AffectedProduct]) -> List[AffectedProduct]:
    """Rewrite each product's vendor to its canonical form in place and return
    the list (for chaining). The original per-source value already lives in the
    source record's raw payload, so this is non-destructive overall."""
    for p in products or []:
        if p.vendor:
            p.vendor = canonical_vendor(p.vendor)
    return products or []


def product_key(name: str) -> str:
    return slugify(name)


def match_product(candidate: str, wanted: List[str]) -> bool:
    """True if a product name matches any wanted product (slug equality or
    substring, so 'apache' matches 'Apache HTTP Server')."""
    if not candidate or not wanted:
        return False
    cslug = slugify(candidate)
    for w in wanted:
        wslug = slugify(w)
        if not wslug:
            continue
        if wslug == cslug or wslug in cslug or cslug in wslug:
            return True
    return False


def any_product_matches(products: List[AffectedProduct], wanted: List[str]) -> bool:
    return any(match_product(p.product, wanted) or match_product(p.vendor, wanted)
               for p in products or [])


def is_version_affected(product: AffectedProduct, version: str) -> Optional[bool]:
    """Is a concrete version affected per this product's ranges? Returns None
    when it cannot be determined (never a misleading False)."""
    if version in (product.versions_fixed or []):
        return False
    if version in (product.versions_affected or []):
        return True
    return version_in_range(
        version,
        version_start_including=product.version_start_including or None,
        version_start_excluding=product.version_start_excluding or None,
        version_end_including=product.version_end_including or None,
        version_end_excluding=product.version_end_excluding or None,
    )


def top_products(products: List[AffectedProduct], limit: int = 8) -> List[AffectedProduct]:
    """Products most worth showing: those with a concrete vendor+product first,
    then by having a version range, capped at ``limit``."""
    def score(p: AffectedProduct) -> int:
        s = 0
        if p.vendor:
            s += 2
        if p.product:
            s += 2
        if any((p.version_end_excluding, p.version_end_including,
                p.version_start_including, p.versions_affected)):
            s += 1
        return s
    return sorted(products or [], key=score, reverse=True)[:limit]
