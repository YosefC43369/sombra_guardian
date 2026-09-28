"""
behavioral_intelligence.storage.observation_store — high-level observation
ingestion with dedup and incremental processing (spec §37).

Wraps ``SQLiteStore`` with the ingestion semantics the pipeline needs:
  * deduplicate on the observation's ``dedupe_key`` (platform+account+time+
    content) so re-collecting the same public post is idempotent;
  * track a per-entity high-water mark (``max collected_at``) so a run can pull
    only *new* observations since the last aggregation — the engine never
    recomputes the entire history when only a handful of rows are new.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence

from ..models.observation import Observation, ObservationBatch
from .sqlite_store import SQLiteStore


class ObservationStore:
    def __init__(self, store: Optional[SQLiteStore] = None,
                 db_path: str = "behavioral_intelligence.db"):
        self.store = store or SQLiteStore(db_path)

    def ingest(self, observations: Sequence[Observation]) -> Dict[str, int]:
        """Persist observations, skipping ones whose dedupe_key already exists.
        Returns {'received','ingested','duplicates'}."""
        received = len(observations)
        if received == 0:
            return {"received": 0, "ingested": 0, "duplicates": 0}
        existing = self._existing_dedupe_keys([o.dedupe_key() for o in observations])
        fresh: List[Observation] = []
        seen_now: set = set()
        for o in observations:
            k = o.dedupe_key()
            if k in existing or k in seen_now:
                continue
            seen_now.add(k)
            fresh.append(o)
        self.store.save_observations(fresh)
        return {"received": received, "ingested": len(fresh),
                "duplicates": received - len(fresh)}

    def _existing_dedupe_keys(self, keys: Sequence[str]) -> set:
        found: set = set()
        # chunk to keep the IN clause bounded
        keys = [k for k in keys if k]
        for i in range(0, len(keys), 400):
            chunk = keys[i:i + 400]
            placeholders = ",".join("?" * len(chunk))
            with self.store._conn() as conn:
                rows = conn.execute(
                    f"SELECT dedupe_key FROM behavior_observations "
                    f"WHERE dedupe_key IN ({placeholders})", chunk).fetchall()
            found |= {r["dedupe_key"] for r in rows}
        return found

    def load_batch(self, entity_id: str, *, since: Optional[float] = None,
                   until: Optional[float] = None) -> ObservationBatch:
        obs = self.store.load_observations(entity_id=entity_id, since=since,
                                           until=until)
        return ObservationBatch(obs, entity_id=entity_id)

    def stream(self, entity_id: str, batch_size: int = 5000) -> Iterable[Observation]:
        return self.store.iter_observations(entity_id=entity_id,
                                            batch_size=batch_size)

    def new_since_last(self, entity_id: str, last_cursor: float
                       ) -> List[Observation]:
        """Observations collected after ``last_cursor`` — the incremental slice."""
        all_new = self.store.load_observations(entity_id=entity_id)
        return [o for o in all_new if o.collected_at > last_cursor]

    def cursor(self, entity_id: str) -> float:
        return self.store.max_collected_at(entity_id)
