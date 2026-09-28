# Changelog — Threat Actor Intelligence Engine

## v1.0.0

Initial release of the **Threat Actor Intelligence Engine**
(`threat_actor_intelligence/`), a production-grade, async-friendly, public-source
CTI subsystem for Sombra Guardian.

### Added

**Domain model & epistemics (`models/`)**
- `EvidenceRef` / `EvidenceBundle` with TLP marking, source-class trust weights
  and content-hash dedup.
- `ConfidenceModel` (explainable 0..1 score: corroboration, source trust,
  recency, sample) with `AssertionKind` (OBSERVED/CORRELATED/INFERRED/UNKNOWN)
  and standing CTI limitations.
- Entities: `ThreatActor`, `Campaign`, `MalwareFamily`, `Infrastructure`, `IOC`,
  `Report`, `Technique`/`Tactic`/`Mitigation`/`CAPECPattern`, `Software`,
  `Victimology`, `Relationship`. All lossless `to_dict`/`from_dict`.
- Deterministic IOC canonicalization (re-fangs defanged input) across 18 types;
  YARA/Sigma stored as references only.

**Storage (`storage/`)**
- SQLite store with 18 normalized tables, explicit indexes, a versioned
  migration ledger, batch writes and `provider_state` for incremental ingestion.
- Disk cache + conditional-request validator store.

**Ingestion (`ingestion/`)** — pure `parse` + polite conditional `run`:
- RSS/Atom, STIX 2.0/2.1, TAXII 2.1, CISA (KEV + advisories), NIST NVD,
  AlienVault OTX, URLhaus, MalwareBazaar (hash refs only), GitHub
  (text + GHSA + YARA/Sigma refs), generic vendor HTML.
- Shared IOC/CVE/technique/name extractor.

**MITRE (`mitre/`)**
- ATT&CK STIX loader (techniques, tactics, mitigations, software, groups,
  relationship resolution) + offline seed; CAPEC engine; technique/tactic/
  software mappers.

**Correlation (`correlation/`)** — explainable, evidence-gated:
- Actor / campaign / malware / infrastructure / IOC / report correlators.
- Careful alias resolution: exact-collision + fuzzy matching with a numeric
  designator guard (APT29 ≠ APT28); **suggests merges, never auto-merges**.

**Timeline / Graph / Reports**
- Evidence-dated timelines (activity, campaign, infrastructure, report).
- Relationship graphs with GraphML/GEXF/JSON/DOT export (optional networkx).
- Actor/campaign/malware dossiers rendered to markdown/html/json/csv.

**Engine / orchestration**
- `ThreatActorIntelligenceEngine` public query API; `ResolutionPipeline`
  (idempotent resolution + denormalization + MITRE mapping); `Orchestrator`
  (ingestion + correlation); `IngestionScheduler` (incremental).

**Telegram** — `/actor /campaign /malware /ioc /attack /capec /report /timeline
/actor_graph /campaign_graph /ioc_report`, wired into `app.py` (collision-safe).

**Tests** — 84 offline pytest tests across models, storage, ingestion,
attack-mapping, correlation, timeline/graph, pipeline, reports and engine.

**Docs** — `THREAT_ACTOR_ENGINE`, `ATTACK_MAPPING`, `IOC_ENGINE`,
`CAMPAIGN_ENGINE`, `DATABASE_SCHEMA`, `TELEGRAM_COMMANDS`, this changelog.

### Security posture
Analysis-only. No malware execution, payload/exploit/phishing generation,
credential theft, persistence, C2, scanning or exploit automation. Public data
only; no fabricated attribution; every conclusion traceable to cited evidence.

### Dependencies
stdlib-first. Optional accelerators (all degrade gracefully): `httpx`,
`feedparser`, `beautifulsoup4`, `networkx`. All provider API keys resolve from
the environment; a provider without its key is skipped.
