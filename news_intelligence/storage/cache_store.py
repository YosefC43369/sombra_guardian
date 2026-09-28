"""
news_intelligence.storage.cache_store — a thin, typed wrapper over the disk cache.

Gives the ingestion and parsing layers named, TTL'd cache namespaces (rss, html,
parsed_article, entity_extraction, translation, topic_cluster) without every caller
re-deriving keys. Backed by ``news_intelligence.cache.DiskCache`` (which reuses the
CTI engine's cache).
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from ..cache import DiskCache, Validators


def _hkey(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


class CacheStore:
    NS_RSS = "rss"
    NS_HTML = "html"
    NS_PARSED = "parsed_article"
    NS_ENTITY = "entity_extraction"
    NS_TRANSLATION = "translation"
    NS_TOPIC = "topic_cluster"

    def __init__(self, cache_dir: str = ".ni_cache", *, ttl: float = 21600):
        self.disk = DiskCache(cache_dir, default_ttl=ttl)
        self.ttl = ttl

    # raw feed bodies
    def get_rss(self, url: str) -> Optional[str]:
        return self.disk.get(self.NS_RSS, url)

    def set_rss(self, url: str, body: str, *, ttl: Optional[float] = None) -> None:
        self.disk.set(self.NS_RSS, url, body, ttl=ttl)

    # fetched html
    def get_html(self, url: str) -> Optional[str]:
        return self.disk.get(self.NS_HTML, url)

    def set_html(self, url: str, body: str, *, ttl: Optional[float] = None) -> None:
        self.disk.set(self.NS_HTML, url, body, ttl=ttl)

    # parsed article dicts
    def get_parsed(self, url: str) -> Optional[dict]:
        return self.disk.get(self.NS_PARSED, url)

    def set_parsed(self, url: str, article: dict) -> None:
        self.disk.set(self.NS_PARSED, url, article)

    # entity extraction results keyed by content hash
    def get_entities(self, content_hash: str) -> Optional[list]:
        return self.disk.get(self.NS_ENTITY, content_hash)

    def set_entities(self, content_hash: str, mentions: list) -> None:
        self.disk.set(self.NS_ENTITY, content_hash, mentions)

    # translation cache
    def get_translation(self, text_hash: str, target_lang: str) -> Optional[str]:
        return self.disk.get(self.NS_TRANSLATION, _hkey(text_hash, target_lang))

    def set_translation(self, text_hash: str, target_lang: str, value: str) -> None:
        self.disk.set(self.NS_TRANSLATION, _hkey(text_hash, target_lang), value)

    # topic clusters
    def get_topics(self, key: str) -> Optional[list]:
        return self.disk.get(self.NS_TOPIC, key)

    def set_topics(self, key: str, topics: list) -> None:
        self.disk.set(self.NS_TOPIC, key, topics)

    # conditional-request validators (shared with disk cache)
    def get_validators(self, url: str) -> Validators:
        return self.disk.get_validators(url)

    def set_validators(self, url: str, v: Validators) -> None:
        self.disk.set_validators(url, v)

    def clear(self) -> int:
        return self.disk.clear()

    def stats(self) -> dict:
        return self.disk.stats()


__all__ = ["CacheStore"]
