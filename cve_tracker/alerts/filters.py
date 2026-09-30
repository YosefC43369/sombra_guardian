"""
cve_tracker.alerts.filters — decide whether a record matches a subscription.

A chat opts into CVEs with a :class:`Subscription` (severity/CVSS floor, KEV-only,
vendor/product/CWE/keyword filters — rule §21). :func:`matches` evaluates a
record against one subscription and returns (matched, reason); the reason is
stored on the notification so an operator can see *why* a chat received a CVE
(rule §22). The global config floor (``CVE_ALERT_MIN_CVSS`` / min severity) is
applied first so nothing below the platform floor is ever sent, regardless of a
looser subscription.
"""

from __future__ import annotations

from typing import Tuple

from ..enums import Severity
from ..models import CVERecord, Subscription
from ..enrichment.vendors import match_vendor
from ..enrichment.products import match_product, any_product_matches
from ..utils import normalize_cwe_id


def _severity_ok(record: CVERecord, min_severity: str) -> bool:
    rec_sev = Severity.coerce(record.severity, default=Severity.UNKNOWN)
    min_sev = Severity.coerce(min_severity, default=Severity.MEDIUM)
    if rec_sev == Severity.UNKNOWN:
        # Unknown severity passes only when the floor is NONE/UNKNOWN or the CVE
        # has a KEV/exploit signal (handled by the caller's KEV path).
        return min_sev.rank <= Severity.LOW.rank
    return rec_sev.rank >= min_sev.rank


def matches(sub: Subscription, record: CVERecord) -> Tuple[bool, str]:
    """Return (matched, reason). The first satisfied *positive* filter wins the
    reason; gate filters (severity/cvss) must all pass first."""
    if not sub.enabled:
        return False, "subscription-disabled"

    # KEV-only subscriptions: the single gate is KEV membership.
    if sub.kev_only:
        if record.in_kev:
            return True, "kev"
        return False, "not-kev"

    # CVSS floor.
    if sub.min_cvss and sub.min_cvss > 0:
        if record.cvss_score is None or record.cvss_score < sub.min_cvss:
            # a KEV record bypasses the CVSS floor — exploited-in-the-wild wins
            if not record.in_kev:
                return False, f"below-cvss({sub.min_cvss})"

    # Severity floor.
    if not _severity_ok(record, sub.min_severity) and not record.in_kev:
        return False, f"below-severity({sub.min_severity})"

    # If the subscription has specific interest filters, at least one must hit.
    has_specific = bool(sub.vendors or sub.products or sub.cwes or sub.keywords)
    if not has_specific:
        # a broad subscription: passing the gates is enough
        reason = "kev" if record.in_kev else "severity/cvss"
        return True, reason

    # vendor
    for v in sub.vendors:
        if match_vendor_any(record, v):
            return True, f"vendor:{v}"
    # product
    if sub.products and (any_product_matches(record.products, sub.products)):
        return True, "product"
    # cwe
    rec_cwes = set(record.cwe_ids)
    for c in sub.cwes:
        norm = normalize_cwe_id(c) or c
        if norm in rec_cwes:
            return True, f"cwe:{norm}"
    # keyword (title/description/cve id)
    hay = f"{record.cve_id} {record.title} {record.description}".lower()
    for kw in sub.keywords:
        if kw.lower().strip() and kw.lower().strip() in hay:
            return True, f"keyword:{kw}"

    return False, "no-filter-match"


def match_vendor_any(record: CVERecord, wanted: str) -> bool:
    return match_vendor(" ".join(record.vendors), [wanted]) or any(
        match_vendor(v, [wanted]) for v in record.vendors)


def passes_global_floor(record: CVERecord, *, min_cvss: float, min_severity: str) -> bool:
    """The platform-wide floor applied before any subscription (rules §23/§34).
    A KEV record always passes (exploited in the wild is never filtered out).
    Otherwise the record must clear BOTH the CVSS floor (when it has a score)
    and the severity floor."""
    if record.in_kev:
        return True
    # CVSS floor: a record WITH a score below the floor is rejected outright.
    if min_cvss and min_cvss > 0 and record.cvss_score is not None:
        if record.cvss_score < min_cvss:
            return False
    # Severity floor.
    return _severity_ok(record, min_severity)
