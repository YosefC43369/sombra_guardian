"""
news_intelligence.parsing.metadata_parser — OpenGraph / meta-tag extraction.

Reads the ``<meta>`` tags of an HTML document into a normalized dictionary and
pulls the fields the article normalizer needs: canonical URL, og:title,
og:description, article:published_time, article:author, og:site_name, language.
Pure; operates on the tag list produced by ``html_parser.HTMLParser.parse``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .html_parser import HTMLParser


def _meta_index(meta: List[Dict[str, str]]) -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for tag in meta or []:
        name = (tag.get("property") or tag.get("name") or tag.get("itemprop")
                or "").strip().lower()
        content = tag.get("content", "")
        if name and content and name not in idx:
            idx[name] = content
        # http-equiv content-language
        if (tag.get("http-equiv", "").lower() == "content-language"
                and tag.get("content")):
            idx.setdefault("language", tag["content"])
    return idx


class MetadataParser:
    def parse(self, html: str) -> Dict[str, Any]:
        parsed = HTMLParser().parse(html)
        meta = parsed.get("meta", [])  # type: ignore
        idx = _meta_index(meta)  # type: ignore
        links = parsed.get("links", [])  # type: ignore
        canonical = idx.get("og:url", "")
        # <link rel=canonical> comes through as text; re-scan raw for it
        m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)',
                      html or "", re.IGNORECASE)
        if m:
            canonical = m.group(1)
        return {
            "title": idx.get("og:title", "") or parsed.get("title", ""),
            "summary": idx.get("og:description", "") or idx.get("description", ""),
            "canonical_url": canonical,
            "site_name": idx.get("og:site_name", ""),
            "author": idx.get("article:author", "") or idx.get("author", ""),
            "published": (idx.get("article:published_time", "")
                          or idx.get("datepublished", "")
                          or idx.get("date", "")),
            "modified": idx.get("article:modified_time", ""),
            "language": idx.get("og:locale", "") or idx.get("language", ""),
            "section": idx.get("article:section", ""),
            "tags": [t.strip() for t in idx.get("article:tag", "").split(",")
                     if t.strip()] or [t.strip() for t in
                     idx.get("keywords", "").split(",") if t.strip()],
            "image": idx.get("og:image", ""),
            "raw_meta": idx,
        }


__all__ = ["MetadataParser"]
