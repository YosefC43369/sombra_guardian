"""
group_soc/normalization/context.py — light, dependency-free extraction helpers.

Pulls non-PII structure out of raw text (URLs → domains) so correlation/detection
have something to join on without the SOC ever storing the raw message. Uses stdlib
regex only; no network, no parsing libraries.
"""

from __future__ import annotations

import re
from typing import List, Tuple
from urllib.parse import urlparse

from ..constants import EntityKind

_URL_RE = re.compile(r"\bhttps?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return _URL_RE.findall(text)[:50]


def _host_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc or ""
    except ValueError:
        return ""
    # strip credentials/port
    netloc = netloc.split("@")[-1].split(":")[0]
    return netloc.lower().strip(".")


def extract_entities(text: str) -> List[Tuple[str, str]]:
    """Return (kind, value) entity pairs from text. URLs yield both a URL entity
    and its domain; bare domains yield a domain entity. Bounded and de-duplicated."""
    if not text:
        return []
    out: List[Tuple[str, str]] = []
    seen = set()
    for url in extract_urls(text):
        key = ("url", url)
        if key not in seen:
            out.append((EntityKind.URL.value, url))
            seen.add(key)
        host = _host_of(url)
        if host and ("domain", host) not in seen:
            out.append((EntityKind.DOMAIN.value, host))
            seen.add(("domain", host))
    # bare domains not already captured via a URL
    for m in _BARE_DOMAIN_RE.findall(text):
        host = m.lower().strip(".")
        if host and ("domain", host) not in seen:
            out.append((EntityKind.DOMAIN.value, host))
            seen.add(("domain", host))
        if len(out) >= 100:
            break
    return out
