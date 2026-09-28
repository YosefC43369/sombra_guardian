"""
news_intelligence.parsing.schema_parser — schema.org JSON-LD extraction.

Extracts ``application/ld+json`` blocks from an HTML document and normalizes the
``NewsArticle`` / ``Article`` / ``BlogPosting`` / ``TechArticle`` types into the
fields the article normalizer needs (headline, datePublished, author, publisher,
articleBody, inLanguage). Pure and defensive: malformed JSON-LD is skipped, never
raised.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

_LD_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL)

_ARTICLE_TYPES = {"newsarticle", "article", "blogposting", "techarticle",
                  "report", "webpage"}


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _name_of(v: Any) -> str:
    if isinstance(v, dict):
        return str(v.get("name", "") or v.get("@id", ""))
    if isinstance(v, list):
        return ", ".join(_name_of(x) for x in v if _name_of(x))
    return str(v or "")


class SchemaParser:
    def parse(self, html: str) -> Dict[str, Any]:
        best: Dict[str, Any] = {}
        for block in _LD_RE.finditer(html or ""):
            raw = block.group(1).strip()
            for obj in self._iter_objects(raw):
                types = {str(t).lower() for t in _as_list(obj.get("@type"))}
                if not (types & _ARTICLE_TYPES):
                    continue
                cand = self._normalize(obj)
                # prefer the object with the most populated fields
                if sum(1 for v in cand.values() if v) > \
                        sum(1 for v in best.values() if v):
                    best = cand
        return best

    def _iter_objects(self, raw: str):
        try:
            data = json.loads(raw)
        except Exception:
            return
        stack = _as_list(data)
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                yield item
                graph = item.get("@graph")
                if graph:
                    stack.extend(_as_list(graph))
            elif isinstance(item, list):
                stack.extend(item)

    def _normalize(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "title": str(obj.get("headline", "") or obj.get("name", "")),
            "summary": str(obj.get("description", "")),
            "body": str(obj.get("articleBody", ""))[:20000],
            "author": _name_of(obj.get("author")),
            "publisher": _name_of(obj.get("publisher")),
            "published": str(obj.get("datePublished", "")),
            "modified": str(obj.get("dateModified", "")),
            "language": str(obj.get("inLanguage", "")),
            "canonical_url": str(obj.get("url", "") or obj.get("mainEntityOfPage", "")
                                 if not isinstance(obj.get("mainEntityOfPage"), dict)
                                 else obj.get("mainEntityOfPage", {}).get("@id", "")),
            "keywords": [k.strip() for k in
                         (obj.get("keywords", "").split(",")
                          if isinstance(obj.get("keywords"), str)
                          else _as_list(obj.get("keywords"))) if str(k).strip()],
        }


__all__ = ["SchemaParser"]
