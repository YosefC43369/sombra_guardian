"""
cve_tracker.utils.timeparse — timestamp normalization and Thai date rendering.

Sources speak a zoo of time formats (NVD's ``2026-09-18T14:03:12.123``, CVE.org's
RFC3339 with offsets, CISA's bare ``2026-09-18`` dates, epoch ints). Everything
is normalized to an integer UTC epoch for storage/compare, and rendered to Thai
Buddhist-era dates only at the presentation edge.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional, Union

from ..constants import THAI_MONTHS, THAI_MONTHS_SHORT

_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d %b %Y",
    "%d %B %Y",
    "%b %d, %Y",
    "%B %d, %Y",
)


def now_epoch() -> int:
    return int(time.time())


def parse_timestamp(value: Union[str, int, float, None]) -> Optional[datetime]:
    """Parse an arbitrary source timestamp into a timezone-aware UTC datetime.

    Returns ``None`` when the value is absent or unparseable — callers must
    treat 'unknown time' as a first-class state, never fabricate 'now'.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            # Heuristic: values > 10^12 are milliseconds.
            v = float(value)
            if v > 1e12:
                v /= 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    # Normalise a trailing 'Z' to +00:00 for the %z formats.
    candidate = text.replace("Z", "+0000") if text.endswith("Z") else text
    # Some feeds use +00:00 with a colon; strptime %z accepts it on 3.7+.
    for fmt in _FORMATS:
        for probe in (text, candidate):
            try:
                dt = datetime.strptime(probe, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    # Last resort: fromisoformat (handles many offset spellings on 3.11+).
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def to_epoch(value: Union[str, int, float, datetime, None]) -> Optional[int]:
    """Normalize any timestamp form to an integer UTC epoch, or None."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(dt.astimezone(timezone.utc).timestamp())
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        return int(v)
    dt = parse_timestamp(value)
    return int(dt.timestamp()) if dt else None


def iso_utc(epoch: Optional[int]) -> str:
    """ISO-8601 UTC string for storage/logs, or '' for None."""
    if epoch is None:
        return ""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def thai_date(epoch: Optional[int], *, short: bool = False, buddhist: bool = True) -> str:
    """Render an epoch as a Thai date: '18 กันยายน 2569' (พ.ศ.) by default.

    Uses UTC; for CVE publication dates the day is what matters, not the
    hour, and dragging in a timezone dependency for a ±7h shift on a date-only
    field is not worth the risk.
    """
    if epoch is None:
        return ""
    dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    months = THAI_MONTHS_SHORT if short else THAI_MONTHS
    month = months[dt.month] if 1 <= dt.month <= 12 else str(dt.month)
    year = dt.year + 543 if buddhist else dt.year
    return f"{dt.day} {month} {year}"


def thai_datetime(epoch: Optional[int], *, buddhist: bool = True) -> str:
    if epoch is None:
        return ""
    dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    return f"{thai_date(epoch, buddhist=buddhist)} {dt.strftime('%H:%M')} UTC"


def humanize_ago(epoch: Optional[int], *, now: Optional[int] = None) -> str:
    """Compact Thai relative time: 'เมื่อสักครู่', 'ก่อน 5 นาที', 'ก่อน 3 ชม.',
    'ก่อน 2 วัน'. Used by /cve_status for 'last sync'."""
    if epoch is None:
        return "ไม่ทราบ"
    ref = now if now is not None else now_epoch()
    delta = max(0, ref - int(epoch))
    if delta < 45:
        return "เมื่อสักครู่"
    if delta < 3600:
        return f"ก่อน {delta // 60} นาที"
    if delta < 86400:
        return f"ก่อน {delta // 3600} ชม."
    if delta < 86400 * 30:
        return f"ก่อน {delta // 86400} วัน"
    if delta < 86400 * 365:
        return f"ก่อน {delta // (86400 * 30)} เดือน"
    return f"ก่อน {delta // (86400 * 365)} ปี"
