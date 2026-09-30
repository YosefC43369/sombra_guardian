"""
cve_tracker.ingestion.parser — shared low-level payload helpers.

Source adapters each own their bespoke parsing, but a handful of operations
recur across all of them (walking a nested JSON path safely, picking an
English-language value, coercing a maybe-list, canonicalising a free-text
severity word). Centralising them here keeps every adapter consistent and makes
the tricky cases (a source that returns a scalar where another returns a list)
handled in exactly one place.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..enums import Severity


def get_path(obj: Any, *path, default=None):
    """Safely walk ``obj[path[0]][path[1]]...``; each step tolerates a missing
    key, a None, or a wrong type without raising."""
    cur = obj
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, (list, tuple)) and isinstance(key, int):
            cur = cur[key] if -len(cur) <= key < len(cur) else None
        else:
            return default
        if cur is None:
            return default
    return cur


def coerce_list(value: Any) -> List[Any]:
    """Return a list for scalar/None/list inputs — sources disagree on whether a
    single-valued field is wrapped."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def first_lang_value(entries: List[dict], *, lang: str = "en",
                     value_key: str = "value", lang_key: str = "lang") -> str:
    """Pick the preferred-language value from a list of {lang, value} dicts,
    falling back to the first present value."""
    fallback = ""
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        v = str(e.get(value_key, "") or "")
        if not v:
            continue
        if (e.get(lang_key, "") or "").lower().startswith(lang.lower()):
            return v
        if not fallback:
            fallback = v
    return fallback


def normalize_severity_string(value: Optional[str]) -> str:
    """Map any source's severity word onto our canonical Severity value.
    Unknown/absent → UNKNOWN (never a guess)."""
    sev = Severity.coerce(value, default=None)
    if sev is not None:
        return sev.value
    if value is None:
        return Severity.UNKNOWN.value
    low = str(value).strip().lower()
    aliases = {
        "crit": Severity.CRITICAL, "critical": Severity.CRITICAL,
        "important": Severity.HIGH, "high": Severity.HIGH,
        "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM, "med": Severity.MEDIUM,
        "low": Severity.LOW, "minor": Severity.LOW,
        "none": Severity.NONE, "informational": Severity.NONE, "info": Severity.NONE,
    }
    return aliases.get(low, Severity.UNKNOWN).value


def clamp_score(value: Any) -> Optional[float]:
    """Coerce a score to a float in [0, 10] or None (never an out-of-range or
    fabricated number)."""
    if value is None or value == "":
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f < 0.0 or f > 10.0:
        return None
    return round(f, 1)
