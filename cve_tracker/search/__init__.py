"""
cve_tracker.search — parse, index-dispatch, refine and rank CVE searches.

:class:`SearchService` is the facade the Telegram commands use; it leans on the
repository's indexes (rule §47) and ranks by search relevance only, never a
security score (rule §52).
"""

from .service import SearchService, SearchResult
from .query import SearchQuery, parse
from .nl import deterministic_nl, ai_refine

__all__ = ["SearchService", "SearchResult", "SearchQuery", "parse",
           "deterministic_nl", "ai_refine"]
