"""
news_intelligence.extraction.entity_extractor — the extraction facade.

Composes every specialized extractor (IOC, URL/repo, CVE/CWE/CAPEC, ATT&CK, actor,
malware, organization, location) into one pass over an article's text and returns a
deduplicated ``List[EntityMention]``. This is the single entry point the pipeline
calls; it is pure (no I/O) and deterministic.

Ordering matters only for span-overlap bookkeeping inside individual extractors;
the final ``dedupe_mentions`` collapses duplicates by ``entity_key`` across all
extractors, summing occurrence counts and keeping the highest extractor weight.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..models.entity import EntityMention, dedupe_mentions
from .base import BaseExtractor
from .ioc_extractor import IOCExtractor
from .url_extractor import URLExtractor
from .cve_extractor import CVEExtractor
from .mitre_extractor import MitreExtractor
from .actor_extractor import ActorExtractor
from .malware_extractor import MalwareExtractor
from .organization_extractor import OrganizationExtractor
from .location_extractor import LocationExtractor


class EntityExtractor:
    """The composite extractor. Construct once and reuse — the dictionary indexes
    and the ATT&CK name map are built lazily and cached on the sub-extractors."""

    def __init__(self, *, attack: Optional[Any] = None,
                 extractors: Optional[List[BaseExtractor]] = None):
        self.extractors: List[BaseExtractor] = extractors or [
            IOCExtractor(),
            URLExtractor(),
            CVEExtractor(),
            MitreExtractor(attack=attack),
            ActorExtractor(),
            MalwareExtractor(),
            OrganizationExtractor(),
            LocationExtractor(),
        ]

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        mentions: List[EntityMention] = []
        for ex in self.extractors:
            try:
                mentions.extend(ex.extract(text, article=article))
            except Exception:  # pragma: no cover - one extractor never breaks all
                continue
        return dedupe_mentions(mentions)

    def extract_from_article(self, article: Any) -> List[EntityMention]:
        """Extract over an ``Article``'s title + summary + body and attach the
        mentions back onto the article (rebuilds its typed buckets)."""
        blob = "\n".join(filter(None, [getattr(article, "title", ""),
                                       getattr(article, "summary", ""),
                                       getattr(article, "body", "")]))
        mentions = self.extract(blob, article=article)
        if hasattr(article, "add_mentions"):
            article.add_mentions(mentions)
        return mentions


__all__ = ["EntityExtractor"]
