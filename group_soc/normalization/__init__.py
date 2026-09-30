"""group_soc.normalization — RawEvent → privacy-safe SecurityEvent, plus enrichment."""

from .schema import RawEvent
from .normalizer import Normalizer
from .context import extract_entities, extract_urls
from .enrichment import enrich_with_watchlist

__all__ = ["RawEvent", "Normalizer", "extract_entities", "extract_urls",
           "enrich_with_watchlist"]
