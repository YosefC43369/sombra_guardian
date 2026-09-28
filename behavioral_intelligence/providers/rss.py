"""
behavioral_intelligence.providers.rss — public RSS / Atom feed provider
(spec §53 free/public sources).

Reads a PUBLIC feed URL and lifts each entry into an ``Observation``
(``content_type=article``) with its publication time, link, and any categories as
hashtags. Feed parsing uses the stdlib ``xml.etree`` (no ``feedparser``
dependency required); ``feedparser`` is used when present for broader format
tolerance. Fetching uses the repo's shared async HTTP stack when available.

Strictly passive: it fetches one public feed URL over HTTP GET, honours the
configured timeout/rate limit, and does nothing else. ``normalize`` also accepts
a raw XML string, so the parser is testable offline.
"""

from __future__ import annotations

import logging
from typing import Any, List
from xml.etree import ElementTree as ET

from ..models.observation import Observation, ContentType, parse_timestamp
from .base import BehaviorProvider

logger = logging.getLogger("modbot.behavioral.provider.rss")

try:
    import feedparser  # type: ignore
    HAVE_FEEDPARSER = True
except Exception:  # pragma: no cover
    feedparser = None
    HAVE_FEEDPARSER = False

try:
    from osint.utils.async_http import AsyncHTTPClient, HAVE_HTTPX
except Exception:  # pragma: no cover
    AsyncHTTPClient = None  # type: ignore[assignment,misc]
    HAVE_HTTPX = False

_ATOM = "{http://www.w3.org/2005/Atom}"


class RSSProvider(BehaviorProvider):
    name = "rss"
    kind = "feed"

    def __init__(self, config=None, *, platform: str = "rss"):
        super().__init__(config)
        self.platform = platform

    async def health_check(self) -> bool:
        # Healthy if we can either fetch (httpx) or were handed raw content.
        return bool(HAVE_HTTPX or AsyncHTTPClient is not None)

    async def collect(self, target: str) -> Any:
        """Fetch the feed at ``target`` (a public URL). Returns raw XML text.
        Raises if the HTTP stack is unavailable — the orchestrator turns that
        into a provider status, not a crash."""
        if AsyncHTTPClient is None or not HAVE_HTTPX:
            raise RuntimeError("HTTP stack unavailable; supply raw XML to normalize()")
        async with AsyncHTTPClient(rate=self.config.per_host_rate,
                                   burst=self.config.per_host_burst,
                                   timeout=self.config.timeout_seconds,
                                   max_retries=self.config.max_retries,
                                   user_agent=self.config.user_agent) as client:
            res = await client.get(target)
            if not res.ok:
                if res.status == 429:
                    raise RuntimeError("rate limited (429)")
                raise RuntimeError(f"fetch failed: status={res.status}")
            return res.text

    def normalize(self, raw: Any) -> List[Observation]:
        if raw is None:
            return []
        if isinstance(raw, list):          # already records
            return super().normalize(raw)
        text = raw if isinstance(raw, str) else str(raw)
        if HAVE_FEEDPARSER:
            return self._normalize_feedparser(text)
        return self._normalize_etree(text)

    # -- parsers ----------------------------------------------------------- #

    def _normalize_feedparser(self, text: str) -> List[Observation]:
        parsed = feedparser.parse(text)
        feed_title = getattr(parsed.feed, "title", self.platform)
        out: List[Observation] = []
        for e in parsed.entries:
            ts = 0.0
            if getattr(e, "published_parsed", None):
                import calendar
                ts = float(calendar.timegm(e.published_parsed))
            tags = [t.get("term", "") for t in getattr(e, "tags", []) if t.get("term")]
            out.append(Observation(
                platform=self.platform, account_id=str(feed_title),
                timestamp=ts, content_type=ContentType.ARTICLE,
                source_url=getattr(e, "link", ""),
                text=getattr(e, "title", "") + " " + getattr(e, "summary", ""),
                hashtags=tags, source=self.name))
        return out

    def _normalize_etree(self, text: str) -> List[Observation]:
        out: List[Observation] = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            logger.debug("RSS parse error: %s", exc)
            return out
        # RSS 2.0
        channel = root.find("channel")
        if channel is not None:
            feed_title = (channel.findtext("title") or self.platform).strip()
            for item in channel.findall("item"):
                title = (item.findtext("title") or "").strip()
                desc = (item.findtext("description") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub = item.findtext("pubDate") or ""
                cats = [c.text.strip() for c in item.findall("category")
                        if c.text]
                out.append(Observation(
                    platform=self.platform, account_id=feed_title,
                    timestamp=parse_timestamp(pub), content_type=ContentType.ARTICLE,
                    source_url=link, text=f"{title} {desc}".strip(),
                    hashtags=cats, source=self.name))
            return out
        # Atom
        feed_title = (root.findtext(f"{_ATOM}title") or self.platform).strip()
        for entry in root.findall(f"{_ATOM}entry"):
            title = (entry.findtext(f"{_ATOM}title") or "").strip()
            summary = (entry.findtext(f"{_ATOM}summary") or "").strip()
            updated = entry.findtext(f"{_ATOM}updated") or \
                entry.findtext(f"{_ATOM}published") or ""
            link_el = entry.find(f"{_ATOM}link")
            link = (link_el.get("href") or "") if link_el is not None else ""
            out.append(Observation(
                platform=self.platform, account_id=feed_title,
                timestamp=parse_timestamp(updated), content_type=ContentType.ARTICLE,
                source_url=link, text=f"{title} {summary}".strip(),
                source=self.name))
        return out
