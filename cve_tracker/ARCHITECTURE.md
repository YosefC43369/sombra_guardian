# Architecture

`cve_tracker` is a layered package. Each layer depends only on the layers below
it, so any piece is testable in isolation (the tests exercise every layer with
no network, DB or bot).

## Module map

```
cve_tracker/
├── config.py          env-driven config snapshot (read at call time, envutil)
├── enums.py           closed vocabularies (Severity, SourceKind, Priority, …)
├── models.py          the normalized value objects (CVERecord + provenance)
├── errors.py          typed exception hierarchy with retryable hints
├── constants.py       regexes, endpoints, reference allowlists, Thai vocab
├── utils/             pure helpers: ids, timeparse, urls, versioning, text
│
├── ingestion/         the HTTP + transform core
│   ├── fetcher.py     shared httpx client: rate-limit, retry/backoff, ETag, size cap
│   ├── ratelimit.py   per-source async token buckets
│   ├── parser.py      shared JSON navigation + severity/score coercion
│   ├── normalizer.py  per-source record hygiene before merge
│   ├── validator.py   structural/semantic record validation
│   ├── deduplicator.py cross-source merge (provenance-preserving)
│   └── pipeline.py     normalize→validate→dedupe→enrich (pure)
│
├── sources/           source adapters + plugin-style registry
│   ├── base.py        CVESource ABC + FetchContext + SourceFetchResult
│   ├── registry.py    SourceRegistry (add sources without touching the engine)
│   ├── nvd.py cve_org.py cisa_kev.py github_advisories.py vendor_advisories.py
│
├── enrichment/        CVSS engine, CWE catalog, CPE, KEV, references, exploit, timeline
├── intelligence/      priority scoring, change detection, correlation, similarity, risk, exposure
├── ai/                adapter (reuses gemini/ai_router) · prompt_builder · summarizer · validator · analyzer · cache · translator
├── storage/           database (schema) · repository · cache (TTL) · retention · migrations
├── alerts/            filters · routing · formatter · templates · throttler · dispatcher
├── search/            query parser · filters · ranking · service
├── telegram/          commands (pure) · handlers (thin PTB adapter) · permissions · preferences · pagination
├── monitoring/        metrics · health · audit · diagnostics
│
├── coordinator.py     concurrent fault-isolated ingestion round + storage reconcile
├── scheduler.py       periodic loop + graceful shutdown
└── engine.py          CVETracker facade + cve_background_loop(bot) entry
```

## Data flow (one polling round)

1. **`scheduler`** fires `coordinator.run_round()` on `CVE_POLL_INTERVAL`.
2. **`coordinator`** builds the enabled sources from the `registry`, and fetches
   them **concurrently** under a global semaphore, each with a per-source
   timeout. One source failing/timing out/raising never stops the others; its
   failure is recorded against its own `SourceState`/health.
3. Each **source** fetches incrementally (cursor/ETag/Last-Modified) through the
   shared `HttpFetcher` and returns single-source `CVERecord`s.
4. **`pipeline`** runs the pure transform: `normalize` (per source) → `validate`
   → `deduplicate/merge` (across sources) → `enrich`.
5. **`coordinator._reconcile`** loads each record's stored version, **merges**
   (provenance-preserving), runs **change detection**, sets the internal
   **priority**, and persists via the **repository**. New records and
   significant updates are collected.
6. **`dispatcher`** routes each record to subscribed chats (subscription
   filters + platform floor), asks the **`summarizer`** for a validated Thai
   summary (cached; deterministic fallback if AI is down), **formats** it, and
   sends it through the **throttler** (priority queue + flood-control).

## Merge & provenance

The same CVE arrives from several sources. `deduplicator.merge_two` unions the
list facts (references/products/CWEs/CVSS/sources/aliases) and picks the display
scalars (CVSS score, severity) by source **trust weight**, while keeping every
source's value — in the per-source CVSS list and in `CVERecord.provenance` — so
a disagreement is a display decision, never a silent overwrite. KEV presence
from any source wins (it is authoritative for "exploited in the wild").

## Integration seam

* **Commands** → `plugins/builtin/cve_tracker_suite.py` (`ctx.register_command`).
* **Background loop** → `app.py` `post_init` starts `cve_background_loop(app.bot)`
  exactly like `news_background_loop`; `post_shutdown` cancels it.
* **Pagination callback** → one `CallbackQueryHandler(^cvepg:)` in `app.py`.
* **Schema** → `migrations/m0008_cve_tracker.py` (single DDL source in
  `storage/database.py`).
* **AI** → `ai/adapter.py` over `gemini.ask_gemini` / `ai_router.route`.
* **Singleton** → `engine.get_tracker()` so the loop and the commands share state.
