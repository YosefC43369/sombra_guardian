"""
news_intelligence.ingestion.feedparse — shared RSS/Atom/JSON-Feed item parsing.

Pure feed parsing used by the RSS, Atom and JSON-Feed ingestors so all three speak
one item shape: ``{title, link, summary, published, author, tags, id, content}``.
Uses ``feedparser`` when installed; falls back to a stdlib ``xml.etree`` parser for
XML feeds and ``json`` for JSON Feed. No network.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from xml.etree import ElementTree as ET

try:
    import feedparser  # type: ignore
    HAVE_FEEDPARSER = True
except Exception:  # pragma: no cover
    feedparser = None
    HAVE_FEEDPARSER = False

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

_ATOM_NS = {"atom": "http://www.w3.org/2005/Atom",
            "dc": "http://purl.org/dc/elements/1.1/",
            "content": "http://purl.org/rss/1.0/modules/content/"}


def strip_html(text: str) -> str:
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", text or "")).strip()


def parse_xml_feed(text: str) -> List[Dict[str, Any]]:
    """Parse an RSS 2.0 or Atom feed into normalized item dicts (stdlib)."""
    out: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    # RSS 2.0 / RDF
    for item in root.iter("item"):
        out.append({
            "title": item.findtext("title") or "",
            "link": item.findtext("link") or "",
            "summary": (item.findtext("description") or ""),
            "content": (item.findtext("{%s}encoded" % _ATOM_NS["content"]) or ""),
            "published": (item.findtext("pubDate")
                          or item.findtext("{%s}date" % _ATOM_NS["dc"]) or ""),
            "author": (item.findtext("author")
                       or item.findtext("{%s}creator" % _ATOM_NS["dc"]) or ""),
            "id": item.findtext("guid") or item.findtext("link") or "",
            "tags": [c.text or c.get("term", "")
                     for c in item.findall("category")],
        })
    # Atom
    for entry in root.findall(".//atom:entry", _ATOM_NS):
        link_el = entry.find("atom:link[@rel='alternate']", _ATOM_NS) \
            or entry.find("atom:link", _ATOM_NS)
        link = link_el.get("href") if link_el is not None else ""
        out.append({
            "title": entry.findtext("atom:title", default="", namespaces=_ATOM_NS),
            "link": link,
            "summary": entry.findtext("atom:summary", default="",
                                      namespaces=_ATOM_NS),
            "content": entry.findtext("atom:content", default="",
                                      namespaces=_ATOM_NS),
            "published": (entry.findtext("atom:published", default="",
                                         namespaces=_ATOM_NS)
                          or entry.findtext("atom:updated", default="",
                                            namespaces=_ATOM_NS)),
            "author": entry.findtext("atom:author/atom:name", default="",
                                     namespaces=_ATOM_NS),
            "id": entry.findtext("atom:id", default="", namespaces=_ATOM_NS) or link,
            "tags": [c.get("term", "")
                     for c in entry.findall("atom:category", _ATOM_NS)],
        })
    return out


def parse_feedparser(text: str) -> List[Dict[str, Any]]:  # pragma: no cover
    d = feedparser.parse(text)
    out = []
    for e in d.entries:
        out.append({
            "title": getattr(e, "title", ""),
            "link": getattr(e, "link", ""),
            "summary": getattr(e, "summary", getattr(e, "description", "")),
            "content": (e.content[0].value if getattr(e, "content", None) else ""),
            "published": getattr(e, "published", getattr(e, "updated", "")),
            "author": getattr(e, "author", ""),
            "id": getattr(e, "id", getattr(e, "link", "")),
            "tags": [t.get("term", "") for t in getattr(e, "tags", []) or []],
        })
    return out


def parse_feed(text: str) -> List[Dict[str, Any]]:
    if HAVE_FEEDPARSER:
        try:
            items = parse_feedparser(text)
            if items:
                return items
        except Exception:
            pass
    return parse_xml_feed(text)


def parse_json_feed(text: str) -> List[Dict[str, Any]]:
    """JSON Feed 1.1 (jsonfeed.org)."""
    out: List[Dict[str, Any]] = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for it in data.get("items", []) or []:
        author = ""
        a = it.get("author") or (it.get("authors") or [{}])[0]
        if isinstance(a, dict):
            author = a.get("name", "")
        out.append({
            "title": it.get("title", ""),
            "link": it.get("url", "") or it.get("external_url", ""),
            "summary": it.get("summary", "") or strip_html(
                it.get("content_html", ""))[:500],
            "content": it.get("content_html", "") or it.get("content_text", ""),
            "published": it.get("date_published", "") or it.get("date_modified", ""),
            "author": author,
            "id": it.get("id", "") or it.get("url", ""),
            "tags": it.get("tags", []) or [],
        })
    return out


__all__ = ["parse_feed", "parse_xml_feed", "parse_json_feed", "strip_html",
           "HAVE_FEEDPARSER"]
