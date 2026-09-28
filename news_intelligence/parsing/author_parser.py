"""
news_intelligence.parsing.author_parser — byline / author normalization.

Normalizes author strings from feeds and metadata: strips "By ", email addresses,
role suffixes and social handles, and splits multi-author bylines
("Alice Smith and Bob Jones", "Alice Smith, Bob Jones") into a clean list. Pure.
"""

from __future__ import annotations

import re
from typing import List

_BY_RE = re.compile(r"^\s*by[:\s]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\S+@\S+")
_SPLIT_RE = re.compile(r"\s*(?:,|;|\band\b|&|/)\s*", re.IGNORECASE)
_HANDLE_RE = re.compile(r"@\w+")
_ROLE_SUFFIX = re.compile(
    r"\s*[-–—|(].*$")  # drop "- Senior Reporter", "(Contributor)"


def _clean_one(name: str) -> str:
    name = _BY_RE.sub("", name or "")
    name = _EMAIL_RE.sub("", name)
    name = _HANDLE_RE.sub("", name)
    name = _ROLE_SUFFIX.sub("", name)
    name = re.sub(r"\s+", " ", name).strip(" .,-")
    return name


class AuthorParser:
    def parse(self, raw: str) -> List[str]:
        if not raw:
            return []
        raw = _BY_RE.sub("", raw.strip())
        parts = _SPLIT_RE.split(raw)
        out: List[str] = []
        for p in parts:
            c = _clean_one(p)
            # a plausible person/org name: 2..60 chars, has a letter
            if c and 2 <= len(c) <= 60 and re.search(r"[A-Za-z]", c) \
                    and c.lower() not in ("staff", "admin", "editor", "team"):
                if c not in out:
                    out.append(c)
        return out

    def primary(self, raw: str) -> str:
        names = self.parse(raw)
        return names[0] if names else ""


__all__ = ["AuthorParser"]
