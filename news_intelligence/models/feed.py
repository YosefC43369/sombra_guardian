"""
news_intelligence.models.feed — a configured feed endpoint and its ingest state.

A ``Feed`` binds a source to a concrete URL and format (RSS/Atom/JSON Feed/XML/
API) and carries the incremental-ingestion bookkeeping: the ETag/Last-Modified
validators, the last item hash seen, the poll interval, and the failure/retry
counters the scheduler reads. One source may expose several feeds (a blog RSS
plus a GitHub advisories feed, say).

Nothing here fetches; this is pure state. The scheduler and ingestors read and
update it.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class FeedFormat(str, Enum):
    RSS = "rss"
    ATOM = "atom"
    JSON_FEED = "json_feed"
    XML = "xml"
    API = "api"
    STIX = "stix"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "FeedFormat":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class Feed:
    url: str
    source_id: str = ""
    fmt: FeedFormat = FeedFormat.RSS
    provider: str = "rss"                  # ingestor name
    enabled: bool = True
    poll_interval: int = 3600
    # incremental validators
    etag: str = ""
    last_modified: str = ""
    last_item_hash: str = ""
    last_polled: float = 0.0
    last_success: float = 0.0
    # health
    consecutive_failures: int = 0
    total_polls: int = 0
    total_items: int = 0
    last_error: str = ""
    feed_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.fmt = FeedFormat.coerce(self.fmt)
        if not self.feed_id:
            self.feed_id = "feed-" + hashlib.sha256(
                self.url.lower().encode("utf-8")).hexdigest()[:16]

    def due(self, *, now: Optional[float] = None) -> bool:
        """Is this feed due for a poll under its interval + backoff?"""
        now = time.time() if now is None else now
        if not self.enabled:
            return False
        backoff = min(self.consecutive_failures, 6) ** 2 * 60  # up to ~1h
        return (now - self.last_polled) >= (self.poll_interval + backoff)

    def record_success(self, *, items: int, etag: str = "",
                       last_modified: str = "", item_hash: str = "",
                       now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self.last_polled = self.last_success = now
        self.consecutive_failures = 0
        self.total_polls += 1
        self.total_items += max(0, items)
        self.last_error = ""
        if etag:
            self.etag = etag
        if last_modified:
            self.last_modified = last_modified
        if item_hash:
            self.last_item_hash = item_hash

    def record_failure(self, error: str, *, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self.last_polled = now
        self.total_polls += 1
        self.consecutive_failures += 1
        self.last_error = (error or "")[:400]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["fmt"] = self.fmt.value
        d["feed_id"] = self.feed_id
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Feed":
        return cls(
            url=str(d.get("url", "")),
            source_id=str(d.get("source_id", "")),
            fmt=FeedFormat.coerce(d.get("fmt")),
            provider=str(d.get("provider", "rss")),
            enabled=bool(d.get("enabled", True)),
            poll_interval=int(d.get("poll_interval", 3600) or 3600),
            etag=str(d.get("etag", "")),
            last_modified=str(d.get("last_modified", "")),
            last_item_hash=str(d.get("last_item_hash", "")),
            last_polled=float(d.get("last_polled", 0.0) or 0.0),
            last_success=float(d.get("last_success", 0.0) or 0.0),
            consecutive_failures=int(d.get("consecutive_failures", 0) or 0),
            total_polls=int(d.get("total_polls", 0) or 0),
            total_items=int(d.get("total_items", 0) or 0),
            last_error=str(d.get("last_error", "")),
            feed_id=str(d.get("feed_id", "")),
            detail=dict(d.get("detail", {}) or {}),
        )


__all__ = ["FeedFormat", "Feed"]
