# Database

All data lives on the shared `bot.db` (rule §32). The single DDL definition is
`storage/database.py:CVE_SCHEMA`, used by both the platform migration
(`migrations/m0008_cve_tracker.py`) and the standalone `ensure_schema`, so they
can never drift. Every table is `cve_`-prefixed, created `IF NOT EXISTS`, and
additive — the migration never alters or drops any existing bot table
(rules §44, §45).

## Tables

| Table | Purpose |
|---|---|
| `cve_records` | Merged CVE: indexed columns + full JSON blob (`data`). |
| `cve_source_records` | Per-source raw payloads (provenance / reprocessing). |
| `cve_references` | One row per reference URL (indexed search). |
| `cve_products` | One row per affected vendor/product (indexed search). |
| `cve_cwes` | One row per CWE association (indexed search). |
| `cve_source_state` | Per-source incremental cursor + rolling health. |
| `cve_notifications` | CVE→chat delivery records (idempotency via `dedupe_key`). |
| `cve_subscriptions` | Per-chat notification preferences. |
| `cve_ai_summaries` | Cached AI Thai summaries (`cve_id`+`input_hash`). |
| `cve_events` | Internal domain-event log (change detection, etc.). |
| `cve_ingestion_runs` | One row per polling round (metrics). |
| `cve_failures` | Per-record ingest failures (audit). |
| `cve_audit_log` | Important operations (who/what/result). |
| `cve_meta` | Misc key/value (schema version). |

## Indexes

`cve_records` is indexed on `published_at`, `last_modified_at`, `severity`,
`cvss_score`, `kev`, `priority_score`, `ai_state`, `first_seen_at`. The child
tables are indexed on `ref_type`, `vendor_key`, `product_key`, `cwe_id`. Every
query path in `repository.py` (recent / by-severity / by-min-cvss / by-vendor /
by-product / by-cwe / KEV / text) uses an index — there is no full-table scan,
and statistics use `GROUP BY` aggregates (rules §24, §47, §51).

## Design notes

* **JSON blob + indexed columns.** The full `CVERecord` is stored as JSON in
  `cve_records.data`; the columns that queries filter/sort on are duplicated out
  for indexing. The child tables (`cve_references`/`cve_products`/`cve_cwes`) are
  kept in sync on every save so correlation queries are indexed.
* **`content_hash`** on each record is a stable hash of the notify-worthy fields;
  a save compares it to detect whether anything changed (drives change
  detection without re-diffing the whole record).
* **Idempotent notifications.** `cve_notifications.dedupe_key` is
  `cve_id:chat_id:topic:new|update`; a duplicate insert is rejected, so the same
  CVE is never sent twice to the same chat (rule §22).
* **Concurrency.** Connections are short-lived (the news.py pattern), opened with
  WAL + a 30 s busy timeout; multi-table writes run in one transaction, and a
  transient "database is locked" is retried with backoff.

## Migrations

`migrations/m0008_cve_tracker.py` applies `CVE_SCHEMA` inside the platform's
`MigrationRunner` transaction and stamps `cve_meta.schema_version`. It is
non-destructive and reversible (its `downgrade` drops only `cve_` tables).
`cve_tracker.version.SCHEMA_VERSION` bumps when the schema changes
incompatibly — add a new migration rather than editing the applied one.

## Retention

`storage/retention.py` trims only the history tables (events, failures, audit,
runs, AI summaries, notifications) on their configured horizons, and nulls out
old raw payloads while keeping the provenance row. **CVE core records are never
auto-deleted** (rule §25).
