# Entity Fusion Engine (v1.0)

The Entity Fusion Engine (`entity_fusion/`) is Sombra Guardian's
identity-correlation subsystem. It ingests fragmented OSINT/SOCMINT records from
the platform's existing modules, normalises them, correlates them with an
explainable multi-factor similarity model, clusters records that refer to the
same real-world entity, scores the correlation confidence, builds a relationship
graph, and renders an investigation dossier.

It is built for the same authorized use as the rest of this repository:
authorized red-team reconnaissance of infrastructure you may assess, SOCMINT and
threat investigations, IOC enrichment, and incident-response attribution — using
**public information only.**

---

## Scope and posture (read this first)

This engine inherits, and **enforces in code**, the deliberate scope line the
`osint/` package already documents. It is asset/infrastructure-oriented and it is
**not** an unrestricted person-profiling / de-anonymisation tool for arbitrary
private individuals.

| Guardrail | How it is enforced |
| --- | --- |
| **Public data only** | Every enricher reads already-public data (Certificate Transparency, public DNS, RDAP, public profiles, public threat feeds). No credential access, no auth bypass, no private-profile access. |
| **No biometrics** | Avatar correlation is perceptual/cryptographic *hashing* of public images (detecting a reused picture). There is **no facial recognition** and no biometric identification. |
| **Fail-closed authorization** | `authorization.FusionGate` gates every entity. Infrastructure targets are checked against the repo's reviewed `scope_policy`. Person-level correlation additionally requires an explicit `allow_person_scope` flag tied to an authorized program — **off by default**. Nothing correlates outside an authorized program. |
| **SSRF hygiene** | Only globally-routable IPs are ever emitted or enriched; private/reserved space is dropped. |

If you need person-level correlation, you must operate inside a written
engagement that covers the individuals in question and set
`AuthorizationContext(program_id=…, allow_person_scope=True)` against an
active, human-reviewed authorization program.

---

## Architecture

```
records / entities
    │
    ▼  normalization.py         canonical values per entity type (unicode,
    │                           homoglyph skeleton, email/username/phone/url)
    ▼  engines/*                offline correlation engines: derive keys,
    │                           extract embedded identifiers (bio email/wallet)
    ▼  authorization.py         FAIL-CLOSED scope gate (drops out-of-scope)
    │
    ▼  similarity.py            explainable multi-factor pairwise scoring
    ▼  clustering.py            blocking + union-find → clusters
    ▼  confidence.py            0–100 explainable confidence per cluster
    ▼  identity.py              cluster → resolved Identity (label, roll-up)
    ▼  graph.py                 relationship graph + GraphML/GEXF/JSON/DOT
    ▼  reports/*                JSON / Markdown / CSV / HTML / GraphViz dossier
```

Two entry points:

- **`orchestrator.FusionEngine`** — synchronous, pure over its inputs. Correlate
  a static set of records into identities.
- **`pipeline.RecursivePipeline`** — async, depth-bounded, cycle-safe discovery
  of *new* linked public entities via `enrichers/*`, feeding the FusionEngine.

The engine is stdlib- and async-first, layered on the `osint/` framework's HTTP
backbone (shared rate limiting / retry). `networkx` and `httpx` are **optional**:
the pure correlation core runs and is fully tested with zero third-party
dependencies; the network enrichers activate when the HTTP stack is present.

---

## Quick start

```python
from entity_fusion import FusionEngine, AuthorizationContext

records = [
    {"type": "username", "value": "John.Doe", "source": "sherlock",
     "display_name": "John Doe", "bio": "reach me at johndoe@example.com"},
    {"type": "username", "value": "johndoe", "source": "github",
     "display_name": "John Doe"},
    {"type": "domain", "value": "example.com", "source": "crtsh"},
]

engine = FusionEngine()
result = engine.fuse(records, ctx=AuthorizationContext(program_id=7,
                                                       allow_person_scope=True))

print(result.stats())
for identity in result.top(5):
    print(identity.summary())

from entity_fusion import reports
print(reports.render(result, "markdown"))
```

### Recursive discovery (async, network enrichers)

```python
import asyncio
from entity_fusion import RecursivePipeline, AuthorizationContext, EntityType
from entity_fusion.entity import Entity
from entity_fusion.enrichers import register_default_expanders

pipe = RecursivePipeline()
register_default_expanders(pipe)          # gravatar, github, crtsh, dns, whois, …
ctx = AuthorizationContext(program_id=7, allow_person_scope=True)
seed = Entity(type=EntityType.USERNAME, value="johndoe")

pres, fres = asyncio.run(pipe.discover_and_fuse([seed], ctx))
print(pres.stats(), fres.stats())
```

---

## Module map

| Module | Responsibility |
| --- | --- |
| `entity.py` | Universal `Entity` model, `SourceRef`, `Evidence`, `Relationship`, merge. |
| `normalization.py` | Multilingual canonicalization + homoglyph skeletons. |
| `similarity.py` | String metrics + explainable multi-factor entity scorer. |
| `clustering.py` | Blocking + union-find clustering. |
| `confidence.py` | Explainable 0–100 confidence with positive/negative/conflict evidence. |
| `identity.py` | Cluster → resolved `Identity`. |
| `graph.py` | Relationship graph (networkx-optional) + exports. |
| `authorization.py` | Fail-closed scope gate integrating `scope_policy`. |
| `orchestrator.py` | `FusionEngine` — the top-level fuse façade. |
| `pipeline.py` | `RecursivePipeline` — async, depth-bounded discovery. |
| `history.py` | Temporal change tracking / timeline. |
| `cache.py`, `scheduler.py` | Tiered cache facade; async bounded-concurrency scheduler. |
| `engines/*` | Offline correlation engines (username, email, phone, crypto, domain, ip, asn, certificate, website, organization). |
| `enrichers/*` | Public network enrichers (gravatar, github, crtsh, dns, whois, wayback, ipinfo, urlscan, alienvault). |
| `storage/*` | SQLite store + memory/disk caches. |
| `reports/*` | JSON / Markdown / CSV / HTML / GraphViz renderers. |

See the companion docs: [ENTITY_SCHEMA](ENTITY_SCHEMA.md),
[SIMILARITY_MODEL](SIMILARITY_MODEL.md), [CONFIDENCE_ENGINE](CONFIDENCE_ENGINE.md),
[GRAPH_ENGINE](GRAPH_ENGINE.md), [DATABASE_SCHEMA](DATABASE_SCHEMA.md),
[DEPLOYMENT_GUIDE](DEPLOYMENT_GUIDE.md).

---

## v1.0 scope notes (honest boundaries)

- **Avatar correlation** is implemented at the *hash* level: if an upstream
  module supplies `avatar_sha256` / `avatar_phash` in a record's metadata, the
  similarity engine treats a match as a hard identifier. The image *download +
  perceptual-hash* enricher (needs Pillow/imagehash) is a documented extension
  point and is deliberately not shipped in v1.
- **Breach/exposure lookups** for arbitrary individuals are intentionally not
  implemented; any such check must be organisation-asset-scoped behind the gate.
- The engines/enrichers are additive and pluggable — new signals register
  without touching the correlation core.
