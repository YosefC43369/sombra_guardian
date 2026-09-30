"""
cve_tracker.search.service — the CVE search facade used by the commands.

Turns a query string into a ranked, paginated result set by: parsing
(:mod:`query`), dispatching to the best *indexed* repository method for the
dominant intent (never a full scan — rule §47), refining for secondary
constraints (:mod:`filters`), and ranking (:mod:`ranking`). Results are a small
:class:`SearchResult` with pagination metadata the Telegram paginator consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..models import CVERecord
from ..storage.repository import CVERepository
from ..storage.cache import TTLCache
from ..utils import now_epoch
from .query import SearchQuery, parse
from . import filters as search_filters
from . import ranking


@dataclass
class SearchResult:
    query: SearchQuery
    records: List[CVERecord] = field(default_factory=list)
    page: int = 1
    page_size: int = 5
    total_fetched: int = 0

    @property
    def total_pages(self) -> int:
        if self.page_size <= 0:
            return 1
        return max(1, (self.total_fetched + self.page_size - 1) // self.page_size)

    def page_items(self) -> List[CVERecord]:
        start = (self.page - 1) * self.page_size
        return self.records[start:start + self.page_size]

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1


# How many candidates to pull from the index before refine/rank. Bounded so a
# broad query never loads the whole table (rule §47).
_CANDIDATE_LIMIT = 120


class SearchService:
    def __init__(self, repo: CVERepository, *, cache_ttl: float = 60.0):
        self.repo = repo
        self._cache = TTLCache(ttl=cache_ttl, max_size=256)

    def search(self, query_text: str, *, page: int = 1, page_size: int = 5) -> SearchResult:
        q = parse(query_text)
        candidates = self._fetch_candidates(q)
        refined = search_filters.apply(candidates, q)
        ranked = ranking.rank(refined, q)
        return SearchResult(query=q, records=ranked, page=max(1, page),
                            page_size=page_size, total_fetched=len(ranked))

    def get_one(self, cve_id: str) -> Optional[CVERecord]:
        from ..utils import normalize_cve_id
        norm = normalize_cve_id(cve_id)
        if not norm:
            return None
        return self.repo.get_record(norm)

    def _fetch_candidates(self, q: SearchQuery) -> List[CVERecord]:
        kind = q.kind
        key = f"{kind}:{q.raw.lower()}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        if kind == "cve_id" and q.cve_id:
            rec = self.repo.get_record(q.cve_id)
            result = [rec] if rec else []
        elif kind == "kev":
            result = self.repo.kev_records(limit=_CANDIDATE_LIMIT)
        elif kind == "cwe" and q.cwe:
            result = self.repo.by_cwe(q.cwe, limit=_CANDIDATE_LIMIT)
        elif kind == "vendor" and q.vendor:
            result = self.repo.by_vendor(q.vendor, limit=_CANDIDATE_LIMIT)
        elif kind == "product" and q.product:
            result = self.repo.by_product(q.product, limit=_CANDIDATE_LIMIT)
        elif kind == "severity" and q.severity:
            result = self.repo.by_severity(q.severity, limit=_CANDIDATE_LIMIT)
        elif kind == "cvss" and q.min_cvss is not None:
            result = self.repo.by_min_cvss(q.min_cvss, limit=_CANDIDATE_LIMIT)
        elif kind == "recent":
            result = self.repo.recent(limit=_CANDIDATE_LIMIT)
        else:  # text
            result = self.repo.text_search(q.text or q.raw, limit=_CANDIDATE_LIMIT)

        self._cache.set(key, result)
        return result

    async def search_nl(self, text: str, *, adapter=None, page: int = 1,
                        page_size: int = 5) -> SearchResult:
        """Natural-language search (rule §53): derive structured filters
        deterministically, optionally refine with the AI adapter, then run the
        SAME indexed pipeline. The DB stays the source of truth — the AI only
        shapes filters."""
        from .nl import deterministic_nl, ai_refine, to_strict
        q = deterministic_nl(text)
        if adapter is not None:
            q = await ai_refine(text, adapter, base=q)
        q = to_strict(q)
        candidates = self._fetch_candidates(q)
        refined = search_filters.apply(candidates, q)
        ranked = ranking.rank(refined, q)
        return SearchResult(query=q, records=ranked, page=max(1, page),
                            page_size=page_size, total_fetched=len(ranked))

    def recent(self, *, limit: int = 10) -> List[CVERecord]:
        return self.repo.recent(limit=limit)

    def stats(self, *, window_days: int = 7) -> dict:
        since = now_epoch() - window_days * 86400
        return self.repo.stats(since_epoch=since)
