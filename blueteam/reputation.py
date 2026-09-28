"""
blueteam/reputation.py — Link Guard tier 2: per-group allow/deny + public blocklist
feeds (URLhaus / OpenPhish).

Two reputation inputs, both fast (in-memory / indexed SQLite lookups):

  * **Per-group allow/deny lists** — an admin's explicit decisions, checked first.
    Allow short-circuits to SAFE (with an audit trail upstream); deny forces the
    max verdict.
  * **Public blocklist feeds** — URLhaus and OpenPhish are parsed into the
    ``bt_feed`` table and looked up by host, registrable domain and URL key. The
    feed *parsers* are pure functions (tested offline); fetching is opt-in and done
    elsewhere with the shared HTTP client.

Feeds are advisory: a hit is a strong signal, not proof, and is explained like any
other signal.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from .urlkit import ExtractedURL, etld1

logger = logging.getLogger("modbot.blueteam.reputation")


class RepVerdict(str, Enum):
    ALLOW = "allow"        # explicitly allow-listed
    DENY = "deny"          # explicitly deny-listed
    FEED = "feed"          # present on a public blocklist feed
    UNKNOWN = "unknown"


@dataclass(slots=True)
class RepResult:
    verdict: RepVerdict
    detail: str = ""
    source: str = ""


class ReputationChecker:
    def __init__(self, store):
        self._store = store

    def check(self, chat_id: int, eu: ExtractedURL) -> RepResult:
        host = eu.ascii_host or eu.host
        reg = eu.etld1 or etld1(host) if host else ""
        url_key = eu.key

        # 1) explicit allow (domain or exact url) — highest precedence
        if reg and self._store.in_list(chat_id, "allow", "domain", reg):
            return RepResult(RepVerdict.ALLOW, f"allow-listed domain {reg}", "group")
        if self._store.in_list(chat_id, "allow", "url", url_key):
            return RepResult(RepVerdict.ALLOW, "allow-listed url", "group")

        # 2) explicit deny
        if reg and self._store.in_list(chat_id, "deny", "domain", reg):
            return RepResult(RepVerdict.DENY, f"deny-listed domain {reg}", "group")
        if self._store.in_list(chat_id, "deny", "url", url_key):
            return RepResult(RepVerdict.DENY, "deny-listed url", "group")

        # 3) public blocklist feed (host, registrable domain, or full url)
        for value in filter(None, (host, reg, eu.url)):
            src = self._store.feed_contains(value)
            if src:
                return RepResult(RepVerdict.FEED, f"listed on {src} feed", src)
        return RepResult(RepVerdict.UNKNOWN)


# ---------------- feed parsers (pure, offline-testable) ----------------

_COMMENT_RE = re.compile(r"^\s*#")
_URL_HOST_RE = re.compile(r"^[a-z]+://([^/\s:]+)", re.IGNORECASE)


def parse_openphish(text: str, limit: int = 100_000) -> List[str]:
    """OpenPhish 'feed.txt' is one URL per line. Return the URLs (capped)."""
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or _COMMENT_RE.match(line):
            continue
        out.append(line)
        if len(out) >= limit:
            break
    return out


def parse_urlhaus(text: str, limit: int = 100_000) -> List[str]:
    """URLhaus CSV export: comment lines start with '#', columns are quoted and
    comma-separated; the URL is column index 2 (id, dateadded, url, ...). We parse
    defensively without csv to tolerate the header/comment block."""
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or _COMMENT_RE.match(line):
            continue
        # split respecting simple double-quotes
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) >= 3:
            candidate = parts[2]
        else:
            # plain URL-per-line fallback
            candidate = line.strip('"')
        if candidate.lower().startswith(("http://", "https://")):
            out.append(candidate)
        if len(out) >= limit:
            break
    return out


def hosts_from_urls(urls: List[str]) -> List[str]:
    """Extract registrable domains from a list of URLs (for host-level feed rows)."""
    hosts: List[str] = []
    for u in urls:
        m = _URL_HOST_RE.match(u)
        if not m:
            continue
        host = m.group(1).lower()
        hosts.append(host)
        reg = etld1(host)
        if reg and reg != host:
            hosts.append(reg)
    return hosts


async def refresh_feeds(store, client, *, urlhaus_url: str = "",
                        openphish_url: str = "") -> dict:
    """Fetch and store public blocklist feeds (opt-in; needs an HTTP client).

    Returns a summary. Never raises — a feed being down must not affect anything.
    """
    summary = {"urlhaus": 0, "openphish": 0}
    if client is None:
        return summary
    if urlhaus_url:
        try:
            res = await client.get(urlhaus_url)
            if getattr(res, "ok", False):
                urls = parse_urlhaus(res.text)
                store.feed_add_many("urlhaus", "url", urls)
                summary["urlhaus"] = store.feed_add_many("urlhaus", "host",
                                                         hosts_from_urls(urls))
        except Exception as exc:
            logger.info("BLUETEAM FEED | urlhaus refresh failed: %s", exc)
    if openphish_url:
        try:
            res = await client.get(openphish_url)
            if getattr(res, "ok", False):
                urls = parse_openphish(res.text)
                store.feed_add_many("openphish", "url", urls)
                summary["openphish"] = store.feed_add_many("openphish", "host",
                                                           hosts_from_urls(urls))
        except Exception as exc:
            logger.info("BLUETEAM FEED | openphish refresh failed: %s", exc)
    return summary
