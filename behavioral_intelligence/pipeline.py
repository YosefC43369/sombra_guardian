"""
behavioral_intelligence.pipeline — incremental processing pipeline (spec §37, §38).

Ingests new/changed observations without recomputing the entire history:
  * new observations are deduplicated and appended via the ObservationStore;
  * an incremental cursor (max collected_at) tracks what has already been seen;
  * aggregation runs over the affected entity only, streaming from storage in
    batches so a million-row entity never loads wholly into RAM (large-dataset
    mode, spec §38).

``PipelineResult`` reports what was ingested and what changed so a caller can
decide whether re-analysis or re-notification is warranted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .configuration import BehavioralConfig, get_config
from .models.observation import Observation, ObservationBatch
from .storage.observation_store import ObservationStore


@dataclass
class PipelineConfig:
    batch_size: int = 5000
    incremental: bool = True
    max_in_memory: int = 250_000


@dataclass
class PipelineResult:
    entity_id: str = ""
    received: int = 0
    ingested: int = 0
    duplicates: int = 0
    total_after: int = 0
    cursor_before: float = 0.0
    cursor_after: float = 0.0
    streamed: bool = False
    elapsed_ms: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {"entity_id": self.entity_id, "received": self.received,
                "ingested": self.ingested, "duplicates": self.duplicates,
                "total_after": self.total_after, "cursor_before": self.cursor_before,
                "cursor_after": self.cursor_after, "streamed": self.streamed,
                "elapsed_ms": self.elapsed_ms}


class IncrementalPipeline:
    def __init__(self, *, store: Optional[ObservationStore] = None,
                 config: Optional[BehavioralConfig] = None,
                 pipeline_config: Optional[PipelineConfig] = None):
        self.config = config or get_config()
        self.store = store or ObservationStore(db_path=self.config.db_path)
        self.pconfig = pipeline_config or PipelineConfig(
            max_in_memory=self.config.max_observations_in_memory)

    def process(self, entity_id: str, observations: Sequence[Observation]
                ) -> PipelineResult:
        """Ingest a fresh batch of observations for an entity, incrementally."""
        start = time.monotonic()
        for o in observations:
            if not o.entity_id:
                o.entity_id = entity_id
        cursor_before = self.store.cursor(entity_id)
        ingest = self.store.ingest(observations)
        cursor_after = self.store.cursor(entity_id)
        # count without materialising the rows
        with self.store.store._conn() as conn:
            total_after = conn.execute(
                "SELECT COUNT(*) c FROM behavior_observations WHERE entity_id=?",
                (entity_id,)).fetchone()["c"]

        return PipelineResult(
            entity_id=entity_id, received=ingest["received"],
            ingested=ingest["ingested"], duplicates=ingest["duplicates"],
            total_after=total_after, cursor_before=cursor_before,
            cursor_after=cursor_after,
            streamed=total_after > self.pconfig.max_in_memory,
            elapsed_ms=int((time.monotonic() - start) * 1000))

    def load_for_analysis(self, entity_id: str) -> ObservationBatch:
        """Load an entity's observations for analysis, streaming into a batch
        when the row count exceeds the in-memory threshold."""
        with self.store.store._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) c FROM behavior_observations WHERE entity_id=?",
                (entity_id,)).fetchone()["c"]
        if total <= self.pconfig.max_in_memory:
            return self.store.load_batch(entity_id)
        # stream: cap to most recent max_in_memory by streaming and keeping tail
        obs: List[Observation] = []
        for o in self.store.stream(entity_id, batch_size=self.pconfig.batch_size):
            obs.append(o)
            if len(obs) > self.pconfig.max_in_memory:
                obs.pop(0)
        return ObservationBatch(obs, entity_id=entity_id)

    def incremental_slice(self, entity_id: str, last_cursor: float
                          ) -> List[Observation]:
        return self.store.new_since_last(entity_id, last_cursor)
