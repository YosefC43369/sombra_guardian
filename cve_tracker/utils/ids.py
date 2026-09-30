"""
cve_tracker.utils.ids — canonical identifier parsing (CVE / CWE / GHSA).

The whole deduplication story rests on a single stable CVE-id spelling, so the
one function every layer must agree on is :func:`normalize_cve_id`. Get this
wrong and the same vulnerability splits into two records.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..constants import (
    CVE_ID_RE,
    CVE_ID_SCAN_RE,
    CWE_ID_RE,
    CWE_ID_SCAN_RE,
    GHSA_ID_RE,
    GHSA_ID_SCAN_RE,
)


def normalize_cve_id(value: Optional[str]) -> Optional[str]:
    """Return the canonical upper-case ``CVE-YYYY-NNNN`` form, or ``None`` if
    ``value`` is not a syntactically valid CVE id. The sequence part is NOT
    zero-stripped or zero-padded — CVE sequence numbers are not fixed width and
    leading zeros are not significant, but NVD/MITRE never emit them, so we keep
    the digits exactly as given after trimming surrounding noise."""
    if not value:
        return None
    text = str(value).strip().upper()
    # Tolerate a stray "CVE " or "CVE:" separator seen in some feeds.
    text = text.replace("CVE ", "CVE-").replace("CVE:", "CVE-")
    m = CVE_ID_RE.match(text)
    if not m:
        return None
    return f"CVE-{m.group('year')}-{m.group('seq')}"


def is_valid_cve_id(value: Optional[str]) -> bool:
    return normalize_cve_id(value) is not None


def extract_cve_ids(text: Optional[str]) -> List[str]:
    """Every distinct CVE id mentioned in free text, canonicalised and
    de-duplicated, preserving first-seen order."""
    if not text:
        return []
    out: List[str] = []
    seen = set()
    for raw in CVE_ID_SCAN_RE.findall(str(text)):
        norm = normalize_cve_id(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def cve_year(cve_id: Optional[str]) -> Optional[int]:
    norm = normalize_cve_id(cve_id)
    if not norm:
        return None
    try:
        return int(norm.split("-")[1])
    except (IndexError, ValueError):
        return None


def cve_sort_key(cve_id: Optional[str]) -> Tuple[int, int]:
    """Sort key giving newest-year-then-highest-sequence ordering. Invalid ids
    sort to the bottom."""
    norm = normalize_cve_id(cve_id)
    if not norm:
        return (-1, -1)
    parts = norm.split("-")
    try:
        return (int(parts[1]), int(parts[2]))
    except (IndexError, ValueError):
        return (-1, -1)


def normalize_cwe_id(value: Optional[str]) -> Optional[str]:
    """Canonical ``CWE-<n>`` (no leading zeros). Accepts a bare integer,
    'CWE-79', 'cwe79', or 'CWE-0079'."""
    if value is None:
        return None
    text = str(value).strip().upper().replace(" ", "")
    if text.isdigit():
        text = f"CWE-{int(text)}"
    if not text.startswith("CWE-") and text.startswith("CWE"):
        # e.g. "CWE79"
        rest = text[3:]
        if rest.isdigit():
            text = f"CWE-{int(rest)}"
    m = CWE_ID_RE.match(text)
    if not m:
        return None
    return f"CWE-{int(m.group('num'))}"


def extract_cwe_ids(text: Optional[str]) -> List[str]:
    if not text:
        return []
    out: List[str] = []
    seen = set()
    for raw in CWE_ID_SCAN_RE.findall(str(text)):
        norm = normalize_cwe_id(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def normalize_ghsa_id(value: Optional[str]) -> Optional[str]:
    """Canonical upper-case GHSA id, or None. GHSA ids are case-insensitive;
    GitHub renders them upper-case after the prefix."""
    if not value:
        return None
    text = str(value).strip().upper()
    m = GHSA_ID_RE.match(text)
    if not m:
        # scan in case it is embedded
        found = GHSA_ID_SCAN_RE.search(text)
        if not found:
            return None
        text = found.group(0).upper()
    return text
