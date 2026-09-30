"""
cve_tracker.ingestion.validator — structural/semantic checks on a record.

A record that fails validation is dropped and counted (rule §46: one malformed
CVE must not stop the batch), never published. Validation is intentionally
strict on identity (a bad CVE id is fatal) and lenient on richness (a CVE with
no CVSS is perfectly valid — 'ไม่พบข้อมูล' is a legitimate state).
"""

from __future__ import annotations

from typing import List, Tuple

from ..constants import CVE_ID_RE, MAX_CVE_ID_LEN, GHSA_ID_RE
from ..models import CVERecord


def validate_record(record: CVERecord) -> Tuple[bool, str]:
    """Return (is_valid, reason). ``reason`` is for logs only."""
    if record is None:
        return False, "null-record"
    cid = (record.cve_id or "").strip()
    if not cid:
        return False, "empty-cve-id"
    if len(cid) > MAX_CVE_ID_LEN and not GHSA_ID_RE.match(cid):
        return False, f"cve-id-too-long({len(cid)})"
    # Accept a real CVE id, or a GHSA sentinel key (non-CVE GitHub advisory).
    if not CVE_ID_RE.match(cid) and not GHSA_ID_RE.match(cid):
        return False, f"invalid-cve-id({cid[:32]})"

    # A record must carry at least one source.
    if not record.sources:
        return False, "no-source-record"

    # Scores, if present, must be in-range — never publish an impossible score.
    for s in record.cvss_scores:
        if s.base_score is not None:
            try:
                sc = float(s.base_score)
            except (TypeError, ValueError):
                return False, "non-numeric-cvss"
            if sc < 0.0 or sc > 10.0:
                return False, f"cvss-out-of-range({sc})"
    if record.cvss_score is not None:
        try:
            top = float(record.cvss_score)
        except (TypeError, ValueError):
            return False, "non-numeric-display-cvss"
        if top < 0.0 or top > 10.0:
            return False, f"display-cvss-out-of-range({top})"

    # Timestamps, if present, must be sane epochs (not negative, not absurd).
    for field_name in ("published_at", "last_modified_at"):
        val = getattr(record, field_name)
        if val is not None and (val < 0 or val > 4102444800):  # > year 2100
            return False, f"{field_name}-implausible"

    return True, "ok"


def is_publishable(record: CVERecord) -> Tuple[bool, str]:
    """A stricter gate for *alerting* (not storage): we happily store a sparse
    record, but we only push a notification when there is something to say —
    a title or description, and a real CVE id."""
    ok, reason = validate_record(record)
    if not ok:
        return False, reason
    if not CVE_ID_RE.match(record.cve_id or ""):
        return False, "not-a-cve-id"
    if not (record.title or record.description):
        return False, "no-title-or-description"
    return True, "ok"


def filter_valid(records: List[CVERecord]) -> Tuple[List[CVERecord], List[Tuple[str, str]]]:
    """Split a batch into (valid, rejected) where rejected is a list of
    (cve_id, reason) for the audit log."""
    valid: List[CVERecord] = []
    rejected: List[Tuple[str, str]] = []
    for rec in records:
        ok, reason = validate_record(rec)
        if ok:
            valid.append(rec)
        else:
            rejected.append((getattr(rec, "cve_id", "?"), reason))
    return valid, rejected
