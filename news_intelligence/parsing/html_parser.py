"""
news_intelligence.parsing.html_parser — HTML → clean text normalization.

Turns an HTML document into plain, whitespace-normalized text and a shallow tag
map. Uses ``beautifulsoup4`` (a project dependency) when present for robust
parsing; falls back to a stdlib ``html.parser`` implementation so the module
imports and its tests run without it.

Pure: no network. Scripts, styles and boilerplate tags are dropped; the visible
text is what downstream extraction runs over.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser as _StdHTMLParser
from typing import Dict, List, Optional

try:
    from bs4 import BeautifulSoup  # type: ignore
    HAVE_BS4 = True
except Exception:  # pragma: no cover
    BeautifulSoup = None
    HAVE_BS4 = False

_DROP_TAGS = {"script", "style", "noscript", "svg", "head", "nav", "footer",
              "form", "aside"}
_WS_RE = re.compile(r"\s+")


class _TextExtractor(_StdHTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: List[str] = []
        self._skip = 0
        self.meta: List[Dict[str, str]] = []
        self.links: List[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in _DROP_TAGS:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            self.meta.append({k: (v or "") for k, v in attrs})
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)
        if tag in ("p", "br", "div", "li", "h1", "h2", "h3", "section"):
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in _DROP_TAGS and self._skip > 0:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip:
            return
        if self._in_title:
            self.title += data
        text = data.strip()
        if text:
            self._chunks.append(text)

    def text(self) -> str:
        return _WS_RE.sub(" ", " ".join(self._chunks)).strip()


class HTMLParser:
    """Facade over bs4 / stdlib extraction."""

    def __init__(self, *, max_chars: int = 20000):
        self.max_chars = max_chars

    def to_text(self, html: str) -> str:
        if not html:
            return ""
        if HAVE_BS4:
            return self._bs4_text(html)[: self.max_chars]
        p = _TextExtractor()
        try:
            p.feed(html)
        except Exception:
            return _WS_RE.sub(" ", re.sub(r"<[^>]+>", " ", html)).strip()[: self.max_chars]
        return p.text()[: self.max_chars]

    def _bs4_text(self, html: str) -> str:  # pragma: no cover - needs bs4
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(list(_DROP_TAGS)):
            tag.decompose()
        text = soup.get_text(separator=" ")
        return _WS_RE.sub(" ", text).strip()

    def parse(self, html: str) -> Dict[str, object]:
        """Return {title, text, meta, links}."""
        if HAVE_BS4:  # pragma: no cover - needs bs4
            soup = BeautifulSoup(html or "", "html.parser")
            title = (soup.title.string if soup.title else "") or ""
            meta = [{k: (v or "") for k, v in tag.attrs.items()}
                    for tag in soup.find_all("meta")]
            links = [a.get("href") for a in soup.find_all("a") if a.get("href")]
            for tag in soup(list(_DROP_TAGS)):
                tag.decompose()
            text = _WS_RE.sub(" ", soup.get_text(separator=" ")).strip()
            return {"title": title.strip(), "text": text[: self.max_chars],
                    "meta": meta, "links": links}
        p = _TextExtractor()
        try:
            p.feed(html or "")
        except Exception:
            pass
        return {"title": p.title.strip(), "text": p.text()[: self.max_chars],
                "meta": p.meta, "links": p.links}


def strip_html(html: str, *, max_chars: int = 20000) -> str:
    return HTMLParser(max_chars=max_chars).to_text(html)


__all__ = ["HTMLParser", "strip_html", "HAVE_BS4"]
