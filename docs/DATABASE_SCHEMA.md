# Database Schema

`entity_fusion/storage/sqlite_store.py` — durable persistence, standard-library
`sqlite3` only (WAL mode, explicit indexes, `CREATE TABLE IF NOT EXISTS`), matching
`scope_policy` / `security` / `osint_db`. Entities round-trip losslessly: scalar
columns are duplicated out for indexed querying while the full object is kept as
a JSON blob so nothing is lost.

## Tables

### `entities`
| Column | Type | |
| --- | --- | --- |
| `id` | TEXT | PRIMARY KEY (UUID) |
| `type` | TEXT | entity type |
| `value` | TEXT | raw primary value |
| `normalized` | TEXT | canonical value |
| `confidence` | REAL | |
| `first_seen` / `last_seen` | REAL | epoch |
| `data` | TEXT | full `Entity.to_dict()` JSON |
| `updated_at` | REAL | |

Indexes: `(type, normalized)`, `(normalized)`.

### `entity_aliases`
`(entity_id, alias)` PRIMARY KEY. Index on `alias` for reverse lookup.

### `entity_relationships`
`(src_id, dst_id, type)` PRIMARY KEY, plus `weight`, `source`. Indexes on
`src_id` and `dst_id`. `ON CONFLICT` keeps the maximum weight.

### `entity_evidence`
`id` autoincrement, `entity_id`, `kind`, `value`, `weight`, `source_json`,
`observed_at`. Index on `entity_id`.

### `entity_history`
Append-only change log: `id`, `entity_id`, `field`, `old_value`, `new_value`,
`changed_at`. Index on `entity_id`. Rows are written automatically by
`save_entity` when a tracked field (`value`, `normalized`, `confidence`) changes,
feeding the temporal `HistoryEngine`.

### `entity_cache`
Generic `(namespace, key)` PRIMARY KEY → `value` (JSON) with `expires_at` TTL.

## API surface

```python
from entity_fusion.storage import SQLiteStore
store = SQLiteStore("entity_fusion.db")
store.save_entity(entity)                    # + aliases/rels/evidence + history
store.get_entity(id)                         # → Entity | None
store.find_entities(entity_type="username", normalized="johndoe")
store.find_by_alias("john.doe")
store.relationships_for(id)
store.history_for(id)
store.cache_set(ns, key, value, ttl=…)  /  store.cache_get(ns, key)
store.stats()
```

Concurrency: a short-lived connection is opened per operation (WAL enabled), so
the store is safe to use from async code without sharing a connection across the
event loop.
