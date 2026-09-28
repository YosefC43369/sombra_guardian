"""
news_intelligence.extraction.url_extractor — URL and repository reference mining.

Extracts full URLs and, from them, source-code repository references
(github.com/<org>/<repo>, gitlab.com/<org>/<repo>). Repository references become
``EntityType.REPOSITORY`` mentions so the correlation layer can connect news to
open-source projects, PoCs and advisories. General URLs feed the URL bucket for
Web Footprint cross-referencing (integration layer), never fetched here.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

from ..models.entity import EntityMention, EntityType
from .base import BaseExtractor, _mk

_URL_RE = re.compile(r"\b(?:h[xX]{2}ps?|https?)://[^\s<>\"')\]]+", re.IGNORECASE)
_REPO_RE = re.compile(
    r"(?i)\b(?:https?://)?(github\.com|gitlab\.com|bitbucket\.org)/"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def _defang(v: str) -> str:
    return v.replace("[.]", ".").replace("hxxp", "http")


class URLExtractor(BaseExtractor):
    name = "url"
    entity_types = [EntityType.URL, EntityType.REPOSITORY]

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        out: List[EntityMention] = []
        for m in _URL_RE.finditer(text):
            url = _defang(m.group(0)).rstrip(".,);")
            out.append(_mk(EntityType.URL, url.lower(), surface=m.group(0),
                           extractor=self.name, weight=0.8, text=text,
                           span=m.span()))
        for m in _REPO_RE.finditer(text):
            host, org, repo = m.group(1).lower(), m.group(2), m.group(3)
            repo = repo[:-4] if repo.lower().endswith(".git") else repo
            value = f"{host}/{org}/{repo}"
            out.append(_mk(EntityType.REPOSITORY, value, surface=m.group(0),
                           extractor=self.name, weight=0.85, text=text,
                           span=m.span(), detail={"host": host, "org": org,
                                                  "repo": repo}))
        return out


__all__ = ["URLExtractor"]
