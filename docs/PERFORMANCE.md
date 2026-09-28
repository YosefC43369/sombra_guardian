# Performance & Large-Dataset Mode

Modules: `pipeline.py`, `cache.py`, `storage/` (§36–38, §58).

## Design for scale

- **Incremental processing** (§37): observations upsert by `observation_id` and
  deduplicate on a stable `dedupe_key` (platform+account+time+content), so
  re-collection is idempotent. A per-entity high-water mark (`max collected_at`)
  lets a run pull only *new* rows instead of recomputing history.
- **Streaming** (§38): `SQLiteStore.iter_observations` uses keyset pagination on
  `(timestamp, observation_id)` to walk millions of rows without loading them all
  into RAM. `IncrementalPipeline.load_for_analysis` streams and keeps a bounded
  tail once the row count exceeds `BEHAVIORAL_MAX_IN_MEMORY` (default 250k).
- **Indexes**: every `behavior_*` column the engines query on is indexed
  (entity+timestamp, platform+account, content_hash, dedupe_key, collected_at).
- **Calculation cache** (§36): `CalculationCache` memoises expensive aggregates
  keyed by a content fingerprint (hash of the sorted observation-id/hash/time
  triples) plus the calculation name and params. Changing one observation
  invalidates the entry. Backed by a layered memory-over-SQLite cache.

## Measured (this environment, Python 3.11)

Full multi-engine `analyze_entity` (temporal + linguistic + content + social +
anomaly + timeline) over synthetic data:

| observations | wall time | throughput |
|-------------:|----------:|-----------:|
| 1,000 | < 0.2 s | — |
| 10,000 | ~1.5 s | — |
| 100,000 | ~16 s | ~6,300 obs/s |

Ingestion and per-section queries scale with the SQLite indexes above; the
dominant cost at scale is tokenisation for the linguistic/content engines, which
the calculation cache elides on unchanged inputs. For very large entities, prefer
running individual sections (`analyze_languages`, `analyze_topics`, …) or a
bounded observed window rather than the full profile every time.

## Tuning knobs

`BEHAVIORAL_MAX_IN_MEMORY`, `BEHAVIORAL_MAX_CONCURRENCY`, `BEHAVIORAL_RATE`,
`BEHAVIORAL_TIMEOUT`, `BEHAVIORAL_TOP_KEYWORDS` / `BEHAVIORAL_TOP_HASHTAGS` /
`BEHAVIORAL_TOP_DOMAINS`. Optional `DuckDB`/compressed storage can be layered
behind the same store interface.
