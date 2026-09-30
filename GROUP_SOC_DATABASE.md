# Group SOC — Database

Schema is owned by **`migrations/m0006_group_soc.py`** (version `0006`, non-destructive,
reversible, auto-discovered by the migration runner). All tables are `soc_`-prefixed and
chat-scoped. No table is created outside the migration; stores only read/write.

Privacy: user identities are stored as **salted hashes** (`actor_hash`, `target_hash`);
message content as a **hash + length** (`content_hash`, `content_len`); indicators are
**defanged**. Raw ids/text never touch these tables.

## Tables

| Table | Purpose | Key columns | Indexes |
|---|---|---|---|
| `soc_events` | normalized SecurityEvents (idempotent by `event_id`) | event_id PK, event_type, ts, chat_id, actor_hash, content_hash, correlation_id, severity | (chat_id,ts), (chat_id,event_type,ts), (correlation_id), (chat_id,actor_hash,ts), (chat_id,content_hash,ts) |
| `soc_signals` | correlation/detection output | signal_id PK, producer, dedup_key, correlation_id, dimensions(JSON) | (chat_id,ts), (chat_id,dedup_key,ts), (correlation_id) |
| `soc_alerts` | prioritized, deduped alerts | alert_id PK, dedup_key, status, priority_score, hit_count, group_id | (chat_id,status,updated_at), (chat_id,dedup_key,status), (correlation_id), (group_id), (chat_id,priority_score) |
| `soc_cases` | analyst casework | case_id PK, status, assignee_hash, alert_ids(JSON), incident_id | (chat_id,status,updated_at), (assignee_hash) |
| `soc_case_notes` | case notes | note_id PK, case_id | (case_id,ts) |
| `soc_incidents` | SOC incident aggregates | incident_id PK, classification, status, member_incident_id | (chat_id,status,updated_at), (member_incident_id) |
| `soc_timeline` | durable reconstructed timelines | entry_id PK, kind, ref_id, correlation_id | (chat_id,ts), (correlation_id,ts) |
| `soc_watchlist` | monitoring targets (not verdicts) | id PK, kind, value, active, expires_at; UNIQUE(chat_id,kind,value) | (chat_id,kind,active) |
| `soc_investigations` | investigation state | investigation_id PK, state, hypotheses(JSON) | (chat_id,state), (case_id) |
| `soc_evidence_links` | generic evidence attachment | id PK, owner_kind, owner_id, ref_kind, ref_id | (owner_kind,owner_id) |
| `soc_audit_log` | every state change | id PK, ts, actor_hash, action, target_* | (chat_id,ts), (target_kind,target_id) |
| `soc_group_policy` | per-group activation (default inactive) | chat_id PK, enabled, mode, settings(JSON) | — |

## Access rules
- **All SQL is parameterized.** No value is ever f-string-interpolated into a query.
- **Reads are bounded**: every list path takes a limit clamped by `util.bounded_limit`
  (`DEFAULT_QUERY_LIMIT=20`, `MAX_QUERY_LIMIT=200`). Detector/correlator aggregates are
  single indexed COUNTs, never table scans.
- Connections are short-lived, `sqlite3.Row`, WAL, per-operation (`storage.repository.SocStore`).
- **Retention** (`purge_older_than`) is guarded by a table/column allow-list so it can
  never be pointed at an arbitrary table.

## Rollback
`/migration up` applies it; the migration has a real `downgrade` that drops the tables in
reverse order. Disabling the plugin (or `SOC_ENABLED=false`) stops all use without a
schema change.
