# Deployment Guide — Entity Fusion Engine

## Requirements

The correlation core (normalization, similarity, clustering, confidence, graph
export, storage, reports) runs on the **standard library alone** — no install
needed beyond the repo's existing dependencies.

Optional, activated when present:

| Package | Enables | If absent |
| --- | --- | --- |
| `httpx` (already a repo dep) | network enrichers | enrichers no-op; core unaffected |
| `networkx` | richer graph backend + schema-valid GraphML/GEXF | stdlib graph backend used |
| `Pillow` + `imagehash` | (future) avatar image download + perceptual hashing | avatar correlation stays at the hash-metadata level |

```bash
# optional extras
pip install networkx
```

## Configuration (`.env`)

All keys are **optional**; every enricher degrades to a no-op or a lower rate
limit without its key. See `.env.example` → *Entity Fusion Engine* section.

```
ENTITY_FUSION_SIMILARITY_THRESHOLD=0.82
ENTITY_FUSION_PIPELINE_MAX_DEPTH=3
ENTITY_FUSION_PIPELINE_MAX_ENTITIES=500
ENTITY_FUSION_DB_PATH=            # defaults to entity_fusion.db
GITHUB_TOKEN=                     # raises GitHub rate limit
IPINFO_TOKEN=
URLSCAN_API_KEY=
ALIENVAULT_OTX_API_KEY=           # or OTX_API_KEY — IOC enrichment (Blue Team)
```

No key is needed for Gravatar, crt.sh, RDAP/WHOIS, DNS-over-HTTPS, or Wayback.

## Authorization (required for real use)

The gate is fail-closed. To correlate anything you must supply an
`AuthorizationContext` backed by an **active, human-reviewed** `scope_policy`
program:

```python
from entity_fusion import AuthorizationContext
ctx = AuthorizationContext(
    program_id=7,               # a scope_policy program with a reviewed authorization
    allow_person_scope=True,    # ONLY inside an engagement covering these individuals
    actor="analyst@org",
)
```

- Infrastructure entities (domain/ip/url/website) are checked against
  `scope_policy.evaluate_target`.
- Person-level entities require `allow_person_scope=True` **and** the authorized
  program. It is off by default.
- `dev_unsafe_allow_all=True` disables enforcement — **local development / tests
  only**; it logs a loud warning and must never appear in a deployed command
  path.

## Running the tests

```bash
pip install pytest pytest-cov
python -m pytest entity_fusion/tests/ -q --cov=entity_fusion --cov-report=term
```

The suite is pure-stdlib: no network, and networkx/httpx are exercised only when
installed. v1.0 ships 186 tests at ~90% coverage.

## Integration points

- **Ingest** — feed `osint` source records / SOCMINT hits directly:
  `FusionEngine().fuse_records(records, ctx=…)`.
- **Persist** — `entity_fusion.storage.SQLiteStore` (its own DB file, or point
  `ENTITY_FUSION_DB_PATH` at a shared path).
- **Report** — `entity_fusion.reports.render(result, fmt)` or
  `reports.bundle(result, dir)` for a full JSON+MD+CSV+HTML+DOT dossier ready to
  zip.
- **Discover** — `RecursivePipeline` + `enrichers.register_default_expanders`
  for depth-bounded expansion.
