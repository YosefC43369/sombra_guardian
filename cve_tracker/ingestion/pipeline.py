"""
cve_tracker.ingestion.pipeline — the in-memory transform from raw → merged.

Given the per-source :class:`SourceFetchResult`s produced by a polling round,
the pipeline runs the pure, DB-free transform:

    normalize (per source) → validate → dedupe/merge (across sources) → enrich

and returns a :class:`PipelineResult` with the merged, enriched records plus the
counters the source-health tracker and audit log need. Reconciliation against
stored records (new vs. updated, change detection, persistence) belongs to the
engine/coordinator, which owns the repository — the pipeline stays testable with
no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..models import CVERecord
from ..enrichment import enrich
from .normalizer import normalize_record
from .validator import filter_valid
from .deduplicator import dedupe_batch


@dataclass
class PipelineResult:
    records: List[CVERecord] = field(default_factory=list)
    rejected: List[Tuple[str, str]] = field(default_factory=list)
    #: per-source record counts seen before de-duplication
    per_source_seen: Dict[str, int] = field(default_factory=dict)
    total_in: int = 0
    total_out: int = 0

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


class IngestionPipeline:
    """Stateless transformer. One instance can process many rounds."""

    def process(self, source_records: List[CVERecord]) -> PipelineResult:
        """Process a flat list of single-source records (already flattened from
        several :class:`SourceFetchResult`s)."""
        result = PipelineResult(total_in=len(source_records))

        # count per source before anything is dropped
        for rec in source_records:
            src = rec.sources[0].source if rec.sources else "unknown"
            result.per_source_seen[src] = result.per_source_seen.get(src, 0) + 1

        # 1. per-source normalization
        normalized = [normalize_record(r) for r in source_records]

        # 2. structural validation
        valid, rejected = filter_valid(normalized)
        result.rejected = rejected

        # 3. cross-source de-duplication / merge
        merged = dedupe_batch(valid)

        # 4. enrichment over the merged records
        for rec in merged:
            enrich(rec)

        result.records = merged
        result.total_out = len(merged)
        return result

    def process_fetch_results(self, fetch_results) -> PipelineResult:
        """Convenience: flatten a list of SourceFetchResult and process."""
        flat: List[CVERecord] = []
        for fr in fetch_results or []:
            if fr and getattr(fr, "records", None):
                flat.extend(fr.records)
        return self.process(flat)
