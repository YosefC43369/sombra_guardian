"""
news_intelligence.parsing.publication_parser — publication date normalization.

Parses the many date formats news feeds and pages use — RFC 822 (RSS pubDate),
ISO 8601 (Atom / schema.org), and a handful of common human formats — into a POSIX
timestamp (float, UTC). Pure and total: an unparseable value yields 0.0, never an
exception, so ingestion never dies on a malformed date.
"""

from __future__ import annotations

import re
import time
from calendar import timegm
from email.utils import parsedate_tz, mktime_tz
from typing import Optional

_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
    "%d %b %Y", "%d %B %Y", "%B %d, %Y", "%b %d, %Y",
    "%m/%d/%Y", "%Y/%m/%d",
)


def parse_date(value: str) -> float:
    if not value:
        return 0.0
    value = value.strip()
    # RFC 822 (RSS)
    try:
        dt = parsedate_tz(value)
        if dt:
            return float(mktime_tz(dt))
    except Exception:
        pass
    # ISO 8601 with a trailing Z normalized to +0000 for %z formats
    normalized = value.replace("Z", "+0000") if value.endswith("Z") else value
    for fmt in _ISO_FORMATS:
        for candidate in ((normalized if "%z" in fmt else value),):
            try:
                st = time.strptime(candidate, fmt)
                # times without tz are treated as UTC (timegm)
                return float(timegm(st))
            except Exception:
                continue
    # last resort: a bare 4-digit year
    m = re.search(r"\b(19|20)\d{2}\b", value)
    if m:
        try:
            return float(timegm(time.strptime(m.group(0), "%Y")))
        except Exception:
            return 0.0
    return 0.0


class PublicationParser:
    def parse(self, value: str) -> float:
        return parse_date(value)

    def best(self, *candidates: str) -> float:
        for c in candidates:
            ts = parse_date(c)
            if ts:
                return ts
        return 0.0


__all__ = ["PublicationParser", "parse_date"]
