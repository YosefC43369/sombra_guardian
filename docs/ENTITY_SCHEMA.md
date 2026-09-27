# Entity Schema

The universal entity model (`entity_fusion/entity.py`). Every OSINT record is
lifted into an `Entity`; correlation, graph and storage all speak this one
vocabulary.

## `Entity`

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | `str` (UUID4) | Stable identifier; referenced by the graph, cache, reports. |
| `type` | `EntityType` | The kind of thing (see below). |
| `value` | `str` | Primary identifier, raw form. |
| `normalized` | `str` | Canonical form used for correlation (set by the normalization engine). |
| `aliases` | `set[str]` | Every other spelling/handle seen for the same thing. |
| `sources` | `list[SourceRef]` | Provenance — where each value was observed. |
| `evidence` | `list[Evidence]` | Append-only observed facts (fed to confidence). |
| `relationships` | `list[Relationship]` | Typed, directional links to other entities. |
| `metadata` | `dict` | Type-specific attributes (bio, display_name, favicon hash, country …). |
| `confidence` | `float` | Correlation confidence (set post-fusion). |
| `first_seen` / `last_seen` | `float` | Epoch timestamps, maintained by the mutators. |

### `EntityType`

`person`, `organization`, `domain`, `subdomain`, `ip`, `asn`, `email`, `phone`,
`username`, `website`, `repository`, `certificate`, `wallet`, `document`,
`image`, `location`, `unknown`.

`EntityType.coerce(x)` maps any string to a type, defaulting to `unknown`
(never raises).

## Value objects

### `SourceRef` — provenance
`provider`, `url`, `observed_at`, `confidence` (source self-reported reliability
in [0,1]), `detail`. De-duplicated on `(provider, url)`.

### `Evidence` — one observed fact
`kind` (signal name), `value`, `weight` in [-1, 1] (negative = contradicting),
`source`, `note`, `observed_at`. **Weights are set where the fact is observed —
the confidence engine reads them, it never fabricates them.**

### `Relationship` — typed edge
`target_id`, `type` (`RelationType`), `weight`, `source`, `note`. De-duplicated
on `(type, target_id)`, keeping the strongest weight.

`RelationType`: `owns`, `mentions`, `shares_email`, `shares_avatar`,
`shares_domain`, `shares_wallet`, `shares_org`, `shares_certificate`,
`shares_phone`, `historical_reference`, `appeared_in`, `resolves_to`, `same_as`.

## Behaviour

- **Provenance-preserving mutators** — `add_alias`, `add_source`,
  `add_evidence`, `add_relationship` all de-duplicate and maintain
  `first_seen`/`last_seen`.
- **`merge(other)`** folds another entity in without losing provenance, upgrades
  an `unknown` type, and records the merge itself as `entity_merge` evidence so
  the join is auditable.
- **`to_dict()` / `from_dict()`** round-trip losslessly (SQLite/JSON safe).
- **`from_record(record, provider=…)`** lifts a loose `{"type","value",…}` dict
  (the shape `osint` sources emit) into an `Entity`, carrying extra keys into
  `metadata`.
