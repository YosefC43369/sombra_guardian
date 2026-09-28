# Threat Actor Intelligence Engine

A production-grade Cyber Threat Intelligence (CTI) subsystem for Sombra Guardian
that collects, normalizes, correlates, scores, stores and visualizes **publicly
available** intelligence about threat actors, malware families, campaigns,
indicators of compromise (IOCs), infrastructure, aliases, ATT&CK/CAPEC TTPs,
reports and historical activity.

Package: `threat_actor_intelligence/` · Version: 1.0.0 · Python 3.11+ ·
stdlib-first (every third-party dependency is optional).

---

## Core objective

Answer, with traceable evidence on every conclusion:

| Question | Where it is answered |
|---|---|
| Which public reports mention this actor? | `engine.actor_report(...)["public_reports"]` |
| Which aliases refer to the same actor? | `models.Alias` + `correlation.AliasResolver` (suggests, never merges) |
| Which malware families are associated? | actor dossier `malware_relationships` |
| Which public IOCs belong to campaigns? | campaign dossier `iocs` |
| Which infrastructure overlaps across campaigns? | `engine.infrastructure_overlaps()` |
| Which ATT&CK techniques are documented? | `engine.attack_coverage(...)`, `/attack` |
| Which countries/industries are targeted? | `victimology` (public reporting only) |
| What timeline of activity is supported? | `engine.timeline(...)` |
| Which sources corroborate the same campaign? | `engine.corroborations()` |

### Non-negotiable principles (enforced in code)

- **Public data only.** Passive, read-only collectors; conditional requests,
  rate limits and (where configured) robots are respected.
- **Never fabricate attribution.** No attribution of criminal responsibility is
  asserted beyond what the cited public sources state.
- **Aliases are not identity.** Two actors sharing an alias are *merge
  candidates* surfaced for human review — never merged automatically.
- **Everything is traceable.** Every stored fact anchors to an `EvidenceRef`;
  every correlation is an explainable `Relationship`; every score is a
  `ConfidenceModel` with its factor breakdown; every report renders the standing
  limitations.

### Security boundary

This is an intelligence *analysis* system. It implements **no** malware
execution, payload/exploit/phishing generation, credential theft, persistence,
C2, scanning or exploit automation. Malware families are catalog metadata only;
known hashes are *references to* public samples, never sample bytes.

---

## Architecture

```
threat_actor_intelligence/
  models/        typed CTI domain + epistemics (evidence, confidence, entities)
  storage/       SQLite persistence (normalized tables, incremental state) + cache
  ingestion/     passive public collectors (RSS, STIX, TAXII, CISA, NVD, OTX,
                 URLhaus, MalwareBazaar, GitHub, vendor) — pure parse + I/O
  mitre/         ATT&CK + CAPEC knowledge bases and mappers
  correlation/   explainable, evidence-gated correlation + careful alias handling
  timeline/      evidence-dated chronologies
  graph/         relationship graphs (GraphML / GEXF / JSON / DOT)
  reports/       actor / campaign / malware dossiers + markdown/html/json/csv
  telegram/      the /actor /campaign /malware /ioc /attack ... command surface
  configuration.py  resolved, typed settings (all keys from the environment)
  cache.py       disk cache + conditional-request validators
  pipeline.py    resolve ingest results into stored entities (idempotent)
  orchestrator.py ingestion + correlation conductor
  engine.py      the public query API
  scheduler.py   incremental scheduled ingestion
```

### Data flow

```
public sources ──▶ ingestion (parse)  ──▶ IngestResult
                                            │
                          pipeline (resolve, dedup, denormalize, MITRE map)
                                            │
                                        SQLite store
                                            │
                          correlation (evidence-gated Relationships)
                                            │
              engine / reports / graph / timeline / telegram
```

Each ingestor separates a **pure** `parse(raw, …) -> IngestResult` (unit-tested
against fixtures, fully offline) from an **I/O** `run(…)` that performs polite
conditional HTTP. The `ResolutionPipeline` folds an `IngestResult` into the store
idempotently; the `Orchestrator` chains ingestion + correlation; the `engine`
exposes the query API used by Telegram and `app.py`.

---

## Confidence model (evidence quality, not certainty of guilt)

`models.confidence.ConfidenceModel.compute()` folds four evidence dimensions into
a 0..1 score with a full factor breakdown:

- **corroboration** — noisy-OR across the trust weights of the *distinct*
  supporting providers (independent confirmation raises confidence);
- **source_trust** — the best single supporting source's class weight
  (government/standards > vendor > research > community > aggregator);
- **recency** — exponential decay from the freshest citation's age;
- **sample** — saturating function of the number of distinct citations.

Contradicting sources subtract a fixed penalty each. Scores map to ATT&CK-style
bands (very low → very high). Every model carries the standing CTI limitations
(aliases ≠ identity; absence of a source ≠ absence of activity; no attribution
beyond cited sources).

See `ATTACK_MAPPING.md`, `IOC_ENGINE.md`, `CAMPAIGN_ENGINE.md`,
`DATABASE_SCHEMA.md`, `TELEGRAM_COMMANDS.md`.

---

## Integration with Sombra Guardian

- **Entity Fusion** — shares the `blueteam.urlkit` URL canonicalizer when
  present; the evidence/confidence model mirrors `entity_fusion` and
  `behavioral_intelligence` so citations move between engines.
- **Geo-OSINT** — infrastructure nodes carry `country`/`cloud_region` fields
  populated from Geo-OSINT enrichment where available (`use_geo_osint`).
- **Evidence system** — `EvidenceRef` is compatible with the repository's
  provenance/ledger discipline (`use_evidence_ledger`).
- **Telegram bot** — `telegram.register_all(app)` is wired into `app.py`
  alongside the behavioral engine, collision-safe and fully guarded.
- **Graph engine** — exports GraphML/GEXF for Maltego/Gephi, matching
  `entity_fusion.graph`.

## Configuration

All settings resolve from the environment at runtime (never at import); every
value has a safe default. A provider without its API key is skipped, not an
error. See the `TAI_*` block in `.env.example`.

## Running

```python
from threat_actor_intelligence import Orchestrator, ThreatActorIntelligenceEngine

orch = Orchestrator()                 # seeded ATT&CK + CAPEC, SQLite store
orch.run_all()                        # fetch every available provider, correlate
eng = ThreatActorIntelligenceEngine()
print(eng.actor_report("APT29", fmt="markdown"))
```

Tests: `python -m pytest threat_actor_intelligence/tests/ -q` (84 tests, offline).
