# Blue Team v0.8 data dictionary (migration 0004)

All tables are `bt_`-prefixed, created `IF NOT EXISTS`, reversible via `downgrade`,
and accessed only through parameterized queries.

## Platform
- **bt_job** — scheduler state. `name` PK, `next_run`, `locked_until` (lease),
  `last_run`, `last_status`.

## Threat Intel
- **bt_ioc** — `ioc_id` PK = `sha256(type|canonical)`, `ioc_type`, `value`
  (canonical), `sources` (csv), `first_seen`, `last_seen`, `expires_at`,
  `confidence`, `severity`, `tlp`, `tags`, `attack`, `family`, `provenance` (JSON),
  `is_local`. Indexed by type and expiry.
- **bt_ioc_sighting** — where an IOC was seen. `ioc_id`, `chat_id`, `user_id`,
  `context`, `seen_at`. Indexed by (ioc_id, seen_at) and (chat_id, seen_at).
- **bt_feed_state** — per feed: `etag`, `last_modified` (conditional GET),
  `last_sync`, `last_status`, `item_count`, `circuit_state`, `failures`, `enabled`.
- **bt_intel_whitelist** — values never treated as malicious. `value` PK.

## Detection-as-Code
- **bt_rule** — `rule_id` PK, `title`, `status`, `level`, `logsource`, `version`,
  `state` (disabled/shadow/canary/enabled), `canary_chats` (JSON), `tags` (JSON),
  `cooldown_s`, `dedupe_field`, `updated_at`, `updated_by`. Indexed by state.
- **bt_rule_version** — hash-chained history. `(rule_id, version)` PK, `body` (JSON),
  `sha256`, `author`, `created_at`, `notes`.
- **bt_rule_hit** — matches. `rule_id`, `chat_id`, `user_id`, `mode`, `matched_at`.
  Indexed by (rule_id, matched_at) and (chat_id, matched_at).
- **bt_rule_cooldown** — dedupe. `(rule_id, chat_id, dedupe_key)` PK, `until`.

## Posture / tenancy
- **bt_tenant** — `tenant_id` PK, `name`, `brand_name`, `brand_color`,
  `brand_footer`, `created_at`.
- **bt_tenant_group** — `(tenant_id, chat_id)` PK; maps groups to a tenant.
- **bt_tenant_role** — `(tenant_id, user_id)` PK, `role`.
- **bt_posture_rollup** — `(chat_id, metric, hour)` PK, `value` (running mean),
  `count`. Trend reads only this.
- **bt_posture_snapshot** — `snapshot_id` PK, `tenant_id`, `chat_id`, `score`,
  `grade`, `coverage`, `breakdown` (JSON), `created_at`.
- **bt_report** — `report_id` PK, `tenant_id`, `chat_id`, `profile`, `fmt`,
  `sha256`, `created_at`.

## Retention
Sightings, rule hits, snapshots and rollups are time-series; prune older than
`BLUETEAM_V08_RETENTION_DAYS` (default 180). IOCs expire via `expires_at`.
