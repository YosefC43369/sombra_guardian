"""
news_intelligence.pipeline — resolve ingested articles into stored intelligence.

The pipeline is the idempotent bridge between raw ``IngestResult`` batches and the
persisted, correlated corpus. For each incoming article it:

  1. skips it if already stored (by content hash / canonical URL) — incremental;
  2. runs entity extraction (unless the ingestor pre-populated structured mentions);
  3. attaches the article's self-citation evidence and computes its confidence;
  4. detects duplicates against the incoming batch AND recent stored articles, and
     stamps ``duplicate_of`` on syndicated copies (originals kept, copies linked);
  5. seeds timeline events for the salient entities it mentions;
  6. persists the article, its entities, IOCs and evidence.

Everything is deterministic and re-runnable: re-ingesting the same feed changes
nothing. Provenance is preserved on every stored fact.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .configuration import NewsIntelConfig, get_config
from .storage.sqlite_store import SQLiteStore
from .models.article import Article
from .models.entity import EntityType
from .models.evidence import EvidenceBundle, EvidenceRef
from .models.confidence import news_confidence
from .extraction.entity_extractor import EntityExtractor
from .clustering.duplicate_cluster import DuplicateDetector
from .clustering.similarity import simhash


@dataclass
class PipelineResult:
    ingested: int = 0
    duplicates: int = 0
    skipped_existing: int = 0
    entities: int = 0
    errors: List[str] = field(default_factory=list)
    article_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"ingested": self.ingested, "duplicates": self.duplicates,
                "skipped_existing": self.skipped_existing,
                "entities": self.entities, "errors": self.errors,
                "articles": len(self.article_ids)}


# entity types worth a timeline event when first/again seen
_TIMELINE_TYPES = {EntityType.THREAT_ACTOR, EntityType.MALWARE_FAMILY,
                   EntityType.CVE, EntityType.CAMPAIGN}


class Pipeline:
    def __init__(self, *, config: Optional[NewsIntelConfig] = None,
                 store: Optional[SQLiteStore] = None,
                 extractor: Optional[EntityExtractor] = None,
                 attack=None):
        self.config = config or get_config()
        self.store = store or SQLiteStore(self.config.db_path)
        self.extractor = extractor or EntityExtractor(attack=attack)
        self.dedup = DuplicateDetector(
            simhash_hamming=self.config.simhash_hamming_threshold,
            minhash_jaccard=self.config.minhash_jaccard_threshold,
            tfidf_threshold=self.config.tfidf_similarity_threshold)

    # ------------------------------------------------------------------ #
    def process(self, articles: List[Article], *, now: Optional[float] = None
                ) -> PipelineResult:
        now = now or time.time()
        result = PipelineResult()
        fresh: List[Article] = []
        for art in articles:
            try:
                if self._is_existing(art):
                    result.skipped_existing += 1
                    continue
                self._enrich(art, now=now)
                fresh.append(art)
            except Exception as exc:  # pragma: no cover
                result.errors.append(f"{art.url}: {exc}")

        if not fresh:
            return result

        # duplicate detection within the fresh batch + against a recent window
        recent = self._recent_window(now)
        pool = fresh + recent
        clusters = self.dedup.mark_duplicates(pool)
        fresh_ids = {a.article_id for a in fresh}
        result.duplicates = sum(1 for a in fresh if a.duplicate_of)

        for art in fresh:
            self.store.save_article(art)
            result.ingested += 1
            result.entities += len(art.entity_mentions)
            result.article_ids.append(art.article_id)
            if not art.duplicate_of:
                self._seed_timeline(art)
        # persist duplicate stamps that landed on already-stored recent articles
        for art in recent:
            if art.duplicate_of and art.article_id not in fresh_ids:
                self.store.save_article(art)
        return result

    # ------------------------------------------------------------------ #
    def _is_existing(self, art: Article) -> bool:
        return self.store.article_exists(
            content_hash=art.content_hash,
            canonical_url=art.canonical_url or "",
            article_id=art.article_id)

    def _enrich(self, art: Article, *, now: float) -> None:
        if not art.entity_mentions:
            self.extractor.extract_from_article(art)
        else:
            art._rebuild_buckets()
        if not art.simhash:
            art.simhash = simhash(f"{art.title} {art.summary}")
        if not art.evidence:
            art.evidence = [art.as_evidence().to_dict()]
        bundle = EvidenceBundle.from_list(art.evidence)
        art.confidence = news_confidence(bundle, now=now).to_dict()

    def _recent_window(self, now: float, *, hours: int = 96, limit: int = 500
                       ) -> List[Article]:
        since = now - hours * 3600
        return self.store.list_articles(since=since, limit=limit,
                                        include_duplicates=True)

    def _seed_timeline(self, art: Article) -> None:
        ts = art.publication_date or art.ingestion_date
        for m in art.entity_mentions:
            if m.entity_type not in _TIMELINE_TYPES:
                continue
            self.store.add_timeline_event(
                event_id=f"{art.article_id}:{m.entity_key}",
                subject_key=m.entity_key, subject_type=m.entity_type.value,
                ts=ts, article_id=art.article_id,
                label=f"{m.value} reported by {art.source_name or art.source_domain}",
                detail={"value": m.value, "source": art.source_domain,
                        "title": art.title[:140]})

    # ------------------------------------------------------------------ #
    def process_ingest_results(self, results, *, now: Optional[float] = None
                               ) -> PipelineResult:
        """Flatten a list of ``IngestResult`` into one processed batch."""
        articles: List[Article] = []
        for r in results:
            articles.extend(getattr(r, "articles", []))
        return self.process(articles, now=now)


__all__ = ["Pipeline", "PipelineResult"]
