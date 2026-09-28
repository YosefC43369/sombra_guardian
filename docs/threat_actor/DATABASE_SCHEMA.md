# Database Schema

Backend: SQLite (stdlib `sqlite3`, WAL, connection-per-operation), no ORM.
File: `threat_actor_intelligence.db` (override with `TAI_DB_PATH`).
Store: `threat_actor_intelligence/storage/sqlite_store.py` · schema version 1.

Each entity is stored **twice-over**: the full `to_dict()` as a JSON `data` blob
(lossless round-trip) plus the scalar columns needed for indexed querying.
Evidence, aliases, relationships, victimology and timeline events are normalized
into their own tables so they can be counted, joined and deduplicated.

## Tables

### `schema_migrations`
`version INTEGER PK`, `applied_at REAL`. Versioned migration ledger;
`init_db()` is idempotent.

### `actors`
`actor_id PK`, `canonical_name`, `actor_type`, `attack_group_id`,
`confidence REAL`, `first_seen`, `last_seen`, `data`, `updated_at`.
Indexes: `canonical_name`, `actor_type`.

### `campaigns`
`campaign_id PK`, `campaign_name`, `confidence`, `first_observed`,
`last_observed`, `data`, `updated_at`. Index: `campaign_name`.

### `malware_families`
`family_id PK`, `family_name`, `category`, `attack_software_id`, `confidence`,
`first_seen`, `last_seen`, `data`, `updated_at`. Index: `family_name`.

### `infrastructure`
`infra_id PK`, `infra_type`, `value`, `asn`, `country`, `confidence`,
`first_seen`, `last_seen`, `data`, `updated_at`. Indexes: `value`, `infra_type`.

### `ioc`
`ioc_id PK`, `ioc_type`, `value`, `malware`, `campaign`, `actor`, `first_seen`,
`last_seen`, `data`, `updated_at`. Indexes: `value`, `ioc_type`.

### `reports`
`report_id PK`, `title`, `url`, `source`, `vendor`, `published_at`,
`content_hash`, `data`, `updated_at`. Indexes: `url`, `content_hash`, `source`.
`content_hash` drives incremental dedup (`report_exists`).

### `aliases`
`(object_type, object_id, alias) PK`, `display`, `source`, `kind`.
Index: `alias`. `object_type ∈ {actor, campaign, malware}`. Alias is the
normalized form; the exact-alias index powers `find_*_by_name` and collision
detection.

### `techniques`
`technique_id PK`, `name`, `domain`, `is_subtechnique`, `parent_id`, `data`,
`updated_at`. Index: `parent_id`.

### `tactics`
`tactic_id PK`, `short_name`, `name`, `data`, `updated_at`.

### `mitigations`
`mitigation_id PK`, `name`, `data`, `updated_at`.

### `capec`
`capec_id PK`, `name`, `data`, `updated_at`.

### `software`
`software_id PK`, `name`, `software_type`, `data`, `updated_at`. Index: `name`.

### `victimology`
`id PK`, `subject_type`, `subject_id`, `country`, `sector`, `data`, `updated_at`.
Indexes: `(subject_type, subject_id)`, `country`, `sector`.
`subject_type ∈ {actor, campaign}`.

### `relationships`
`rel_id PK`, `src_type`, `src_id`, `rel_type`, `dst_type`, `dst_id`,
`weight REAL`, `confidence REAL`, `data`, `updated_at`.
Indexes: `(src_type, src_id)`, `(dst_type, dst_id)`, `rel_type`.
Each row carries its explaining `signal` + evidence inside `data`.

### `evidence`
`(object_type, object_id, ref_id) PK`, `provider`, `source_url`, `observed_at`,
`data`. Indexes: `(object_type, object_id)`, `provider`. Deduplicated by
`ref_id`; the full `EvidenceRef.to_dict()` is in `data`.

### `timeline`
`event_id PK`, `subject_type`, `subject_id`, `at REAL`, `kind`, `label`, `data`.
Indexes: `(subject_type, subject_id)`, `at`.

### `provider_state` (incremental ingestion)
`(provider, resource) PK`, `etag`, `last_modified`, `content_hash`,
`provider_version`, `fetched_at`. Stores conditional-request validators so only
changed resources are re-processed.

### `kv` (generic)
`(namespace, key) PK`, `value`, `expires_at`. Used for scheduler state and the
persisted merge-candidate list.

## Entity-relationship overview

```
reports ──mentions──▶ actors ──uses──▶ malware ──uses──▶ techniques
   │                    │  ▲              │                   │
   │              attributed_to           │                subtechnique_of
   ▼                    │                 ▼                   ▼
 evidence◀──(all)──── campaigns ──uses──▶ infrastructure   tactics / mitigations / capec
                        │                    │
                     targets              overlaps
                        ▼                    ▼
                country / industry     infrastructure (shared cert/ip/asn/domain)
```

All edges live in `relationships` with their signal + confidence; the
denormalized reference lists on each entity (`actor.malware_families`, etc.) are
kept in sync by the pipeline's denormalization pass for fast dossier assembly.

## Incremental ingestion

`provider_state` + `reports.content_hash` implement the spec's incremental
requirement: conditional GET (ETag / Last-Modified) skips unchanged resources,
and content-hash dedup skips already-stored reports. Batch writes (`save_iocs`,
`save_relationships`) run in a single transaction.
