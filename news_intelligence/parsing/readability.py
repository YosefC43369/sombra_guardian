"""
news_intelligence.parsing.readability — main-content extraction heuristic.

A dependency-free "readability"-style extractor: given raw HTML, it scores block
elements by text density and link-to-text ratio and returns the densest contiguous
region as the article body, discarding navigation, boilerplate and comment chrome.
Uses ``beautifulsoup4`` when present for accurate block boundaries; falls back to a
paragraph-density heuristic over ``html_parser`` output otherwise.

Pure. This never fetches — it operates on HTML already in hand.
"""

from __future__ import annotations

import re
from typing import List, Optional

from .html_parser import HAVE_BS4, HTMLParser

try:  # pragma: no cover
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None

_WS_RE = re.compile(r"\s+")
_SENT_RE = re.compile(r"[.!?]")


def _score_text(text: str) -> float:
    """Density score: length weighted by sentence punctuation and comma count."""
    if not text:
        return 0.0
    length = len(text)
    sentences = len(_SENT_RE.findall(text))
    commas = text.count(",")
    return length + sentences * 25 + commas * 5


class ReadabilityExtractor:
    def __init__(self, *, max_chars: int = 20000, min_block_chars: int = 120):
        self.max_chars = max_chars
        self.min_block_chars = min_block_chars

    def extract(self, html: str) -> str:
        if not html:
            return ""
        if HAVE_BS4:
            body = self._extract_bs4(html)
            if body:
                return body[: self.max_chars]
        return self._extract_fallback(html)[: self.max_chars]

    def _extract_bs4(self, html: str) -> str:  # pragma: no cover - needs bs4
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "aside", "form",
                         "noscript", "header"]):
            tag.decompose()
        candidates = soup.find_all(["article", "main", "div", "section"])
        best_text, best_score = "", 0.0
        for c in candidates:
            paras = c.find_all("p")
            if not paras:
                continue
            text = _WS_RE.sub(" ", " ".join(p.get_text(" ") for p in paras)).strip()
            if len(text) < self.min_block_chars:
                continue
            links = c.find_all("a")
            link_text = sum(len(a.get_text(" ")) for a in links)
            ratio = link_text / max(1, len(text))
            score = _score_text(text) * (1.0 - min(0.9, ratio))
            if score > best_score:
                best_score, best_text = score, text
        if best_text:
            return best_text
        # fall back to all paragraphs
        return _WS_RE.sub(" ", " ".join(
            p.get_text(" ") for p in soup.find_all("p"))).strip()

    def _extract_fallback(self, html: str) -> str:
        # split into paragraph-ish chunks and keep the dense ones in order
        parsed = HTMLParser(max_chars=self.max_chars * 2).parse(html)
        text = str(parsed.get("text", ""))
        chunks = [c.strip() for c in re.split(r"\n|(?<=[.!?])\s{2,}", text)
                  if c.strip()]
        kept = [c for c in chunks if len(c) >= 40]
        joined = " ".join(kept) if kept else text
        return _WS_RE.sub(" ", joined).strip()

    def summary(self, html_or_text: str, *, sentences: int = 3) -> str:
        text = (self.extract(html_or_text) if "<" in (html_or_text or "")
                else html_or_text)
        parts = re.split(r"(?<=[.!?])\s+", text.strip())
        return " ".join(parts[:sentences]).strip()


__all__ = ["ReadabilityExtractor"]
