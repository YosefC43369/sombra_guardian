"""
cve_tracker.utils.versioning — permissive version parsing and range checks.

Affected/fixed version reasoning in CVE data is genuinely messy: semver,
two-part vendor versions, date-versions, alphanumerics ('1.2.3-rc1'),
wildcards. This module gives a *best-effort* comparable key and range test used
by enrichment.cpe and the correlation queries ('is product X at version V
affected?'). It never claims false precision: unparⁿseable operands compare as
'unknown', and range checks return None rather than a misleading boolean.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_VER_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+)")
# Pre-release tokens ordered below the release they qualify.
_PRERELEASE_RANK = {
    "alpha": -4, "a": -4, "beta": -3, "b": -3,
    "rc": -2, "pre": -2, "preview": -2, "m": -2,
    "snapshot": -5, "dev": -5, "nightly": -5,
}


def normalize_version_string(value: Optional[str]) -> str:
    """Trim common noise ('v1.2.3', '1.2.3 (build 4)', '>=1.0') to a bare
    version token. Comparison-oriented, not lossless."""
    if not value:
        return ""
    s = str(value).strip()
    s = re.sub(r"^[vV]\s*", "", s)
    s = re.sub(r"\s*\(.*?\)\s*", "", s)
    s = s.strip(" ='<>~^*")
    return s


def parse_version(value: Optional[str]) -> Optional[Tuple]:
    """Return a comparable tuple key, or None if there is nothing numeric to
    compare. Numbers compare numerically; alphabetic tokens compare by
    pre-release rank (rc < release) then lexically."""
    s = normalize_version_string(value)
    if not s:
        return None
    if s in ("*", "-", "all", "any"):
        return None
    tokens = _VER_TOKEN_RE.findall(s)
    if not tokens or not any(t.isdigit() for t in tokens):
        return None
    key: List[Tuple[int, int, str]] = []
    for tok in tokens:
        if tok.isdigit():
            # (type=1 numeric, value, "") — numeric sorts above alpha at same pos
            key.append((1, int(tok), ""))
        else:
            low = tok.lower()
            rank = _PRERELEASE_RANK.get(low, 0)
            # (type=0 alpha, prerelease_rank, token)
            key.append((0, rank, low))
    return tuple(key)


def compare_versions(a: Optional[str], b: Optional[str]) -> Optional[int]:
    """Return -1/0/1 for a<b / a==b / a>b, or None if either side is not
    comparable. Shorter-but-equal-prefix versions are treated as the lower
    (1.2 < 1.2.1)."""
    ka, kb = parse_version(a), parse_version(b)
    if ka is None or kb is None:
        return None
    # Pad the shorter with numeric-zero so trailing zeros compare equal
    # (2.0 == 2.0.0) while a real extra component still wins (1.2 < 1.2.1) and a
    # pre-release still sorts below its release (1.2 > 1.2-rc1).
    sentinel = (1, 0, "")
    n = max(len(ka), len(kb))
    la = list(ka) + [sentinel] * (n - len(ka))
    lb = list(kb) + [sentinel] * (n - len(kb))
    for x, y in zip(la, lb):
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def version_in_range(
    version: Optional[str],
    *,
    introduced: Optional[str] = None,
    fixed: Optional[str] = None,
    last_affected: Optional[str] = None,
    version_start_including: Optional[str] = None,
    version_start_excluding: Optional[str] = None,
    version_end_including: Optional[str] = None,
    version_end_excluding: Optional[str] = None,
) -> Optional[bool]:
    """Is ``version`` within an affected range? Accepts both the GHSA vocabulary
    (introduced/fixed/last_affected) and the NVD CPE-match vocabulary
    (versionStart*/versionEnd*). Returns None when the comparison can't be made
    reliably — callers must treat None as 'cannot determine', not 'not
    affected'."""
    v = parse_version(version)
    if v is None:
        return None

    lower = version_start_including or introduced
    lower_excl = version_start_excluding
    upper_incl = version_end_including or last_affected
    upper_excl = version_end_excluding or fixed

    checks: List[bool] = []

    if lower is not None:
        c = compare_versions(version, lower)
        if c is None:
            return None
        checks.append(c >= 0)
    if lower_excl is not None:
        c = compare_versions(version, lower_excl)
        if c is None:
            return None
        checks.append(c > 0)
    if upper_incl is not None:
        c = compare_versions(version, upper_incl)
        if c is None:
            return None
        checks.append(c <= 0)
    if upper_excl is not None:
        c = compare_versions(version, upper_excl)
        if c is None:
            return None
        checks.append(c < 0)

    if not checks:
        # No bounds at all → cannot assert membership.
        return None
    return all(checks)
