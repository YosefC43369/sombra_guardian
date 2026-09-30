"""
cve_tracker.ai.cache — two-tier cache for AI summaries.

AI calls are the most expensive step, and the same CVE re-ingested with no
meaningful change should not be re-summarised (rule §26). The cache keys on
(cve_id, input_hash) where input_hash is derived from the *facts that drive the
summary* (see prompt_builder.input_signature) — so a summary is reused until the
facts change, and a trivial re-fetch is free.

Tier 1 is an in-process :class:`TTLCache` (avoids a DB hit on hot CVEs); tier 2
is the durable ``cve_ai_summaries`` table via the repository. Only *validated*
(non-fallback) summaries are cached — a deterministic fallback is cheap to
rebuild and must be retried against a recovered AI next time.
"""

from __future__ import annotations

from typing import Optional

from ..enums import AIProcessingState
from ..models import AISummary
from ..storage.cache import TTLCache


class AISummaryCache:
    def __init__(self, repo=None, *, ttl: float = 86400.0, max_size: int = 1024):
        self.repo = repo
        self._mem = TTLCache(ttl=ttl, max_size=max_size)

    def _key(self, cve_id: str, input_hash: str) -> str:
        return f"{cve_id}:{input_hash}"

    def get(self, cve_id: str, input_hash: str) -> Optional[AISummary]:
        key = self._key(cve_id, input_hash)
        hit = self._mem.get(key)
        if hit is not None:
            return hit
        if self.repo is not None:
            stored = self.repo.get_ai_summary(cve_id, input_hash)
            if stored is not None:
                self._mem.set(key, stored)
                return stored
        return None

    def put(self, summary: AISummary) -> None:
        # Never cache a fallback/failed summary — it must be retried later.
        if summary.fallback_used or summary.state in (
                AIProcessingState.FAILED.value, AIProcessingState.FALLBACK.value,
                AIProcessingState.UNAVAILABLE.value):
            return
        key = self._key(summary.cve_id, summary.input_hash)
        self._mem.set(key, summary)
        if self.repo is not None:
            try:
                self.repo.save_ai_summary(summary)
            except Exception:
                pass

    @property
    def stats(self):
        return self._mem.stats
