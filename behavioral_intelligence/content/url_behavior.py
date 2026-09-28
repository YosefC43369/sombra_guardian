"""
behavioral_intelligence.content.url_behavior — public URL behaviour (spec §17).

Normalises URLs (lower-case host, strip tracking params, drop fragments),
categorises them coarsely, and tracks frequency and first/last-seen. Strictly
passive: the engine never fetches, authenticates against, or follows a URL — it
only analyses the strings that already appear in public content.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Sequence
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from ..models.observation import Observation
from ..models.topic import URLStat

# Query params that are pure tracking noise — removed during normalisation.
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "igshid", "ref", "ref_src", "ref_url", "mc_cid",
    "mc_eid", "yclid", "_hsenc", "_hsmi", "spm",
}

_CATEGORY_HINTS = {
    "code": ("github.com", "gitlab.com", "bitbucket.org", "sourceforge.net"),
    "social": ("twitter.com", "x.com", "mastodon", "bsky.app", "reddit.com",
               "facebook.com", "instagram.com", "t.me", "linkedin.com"),
    "video": ("youtube.com", "youtu.be", "vimeo.com", "twitch.tv"),
    "paste": ("pastebin.com", "ghostbin", "hastebin", "gist.github.com"),
    "archive": ("web.archive.org", "archive.org", "archive.ph"),
    "docs": ("medium.com", "substack.com", "wordpress.com", "blogspot.com"),
}

_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
               "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly"}


def normalize_url(url: str) -> str:
    """Canonicalise a URL for comparison: scheme+host lower-cased, tracking
    params stripped, fragment dropped, trailing slash normalised. Returns '' for
    an unparseable input. Never contacts the network."""
    if not url:
        return ""
    raw = url if "://" in url else "http://" + url
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower().lstrip(".")
    if not host:
        return ""
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                       if k.lower() not in _TRACKING_PARAMS])
    path = parts.path.rstrip("/") or "/"
    port = f":{parts.port}" if parts.port and parts.port not in (80, 443) else ""
    return urlunsplit(("https", host + port, path, query, ""))


def categorize(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    for cat, hints in _CATEGORY_HINTS.items():
        if any(h in host for h in hints):
            return cat
    if host in _SHORTENERS:
        return "shortener"
    return "other"


def analyze_urls(observations: Sequence[Observation], *, top_n: int = 50
                 ) -> List[URLStat]:
    freq: Counter = Counter()
    first_seen: Dict[str, float] = {}
    last_seen: Dict[str, float] = {}
    raw_of: Dict[str, str] = {}

    for o in observations:
        for u in o.urls:
            norm = normalize_url(u)
            if not norm:
                continue
            freq[norm] += 1
            raw_of.setdefault(norm, u)
            if o.has_time:
                first_seen[norm] = min(first_seen.get(norm, o.timestamp), o.timestamp)
                last_seen[norm] = max(last_seen.get(norm, o.timestamp), o.timestamp)

    out: List[URLStat] = []
    for norm, f in freq.most_common(top_n):
        out.append(URLStat(
            url=raw_of.get(norm, norm), normalized=norm,
            domain=(urlsplit(norm).hostname or ""), frequency=f,
            category=categorize(norm), first_seen=first_seen.get(norm, 0.0),
            last_seen=last_seen.get(norm, 0.0)))
    return out
