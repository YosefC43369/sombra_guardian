# Changelog — Behavioral Intelligence Engine v1.0

## v1.0.0

First release of the `behavioral_intelligence/` subsystem: a passive, public-data
behavioural-analysis engine for authorized OSINT/SOCMINT/threat investigation.

### Added

- **Core models** (`models/`) — universal `Observation` (UTC-internal,
  provenance-preserving, content-hashed, timestamp-precision aware) and typed
  results for activity, language, topic, timeline, anomaly and the composed
  `BehaviorProfile`.
- **Epistemics layer** (`models/confidence.py`) — `Assertion` /
  `AssertionKind` (OBSERVED/CORRELATED/INFERRED/UNKNOWN), `ConfidenceModel`,
  `EvidenceRef`, `SourceReliability`, standing limitations. Every analytical
  output is a labelled, evidence-backed assertion.
- **Fail-closed authorization** (`authorization.py`) — `BehaviorGate` delegating
  to the shared `entity_fusion` scope gate; person-scope off by default.
- **Temporal engine** — rate/coverage/intervals, hour/weekday/month histograms
  and 2-D heatmaps, peak windows, bursts, inactivity gaps, change points
  (CUSUM/rolling-z/EWMA), seasonality, cross-platform correlation.
- **Linguistic engine** — Unicode script detection; heuristic language detection
  for 15 languages; language switching timeline/matrix; TF-IDF keywords, n-gram
  phrases, hashtags, terminology; character-level transliteration.
- **Content engine** — topic discovery & evolution, URL/domain behaviour, media
  summary, repost/thread structure, content-reuse (SHA-256/SimHash/MinHash/cosine).
- **Social engine** — mention/reply networks, interaction patterns, community
  detection (Louvain/label-propagation/connected-components), platform migration.
- **Infrastructure engine** — domain/certificate/repository/IOC reference
  behaviour with optional threat-intel cross-reference.
- **Anomaly & scoring** — self-baseline construction (7/30/90d), explainable
  0–100 deviation score (never a threat score), outliers, drift; activity /
  consistency / anomaly / confidence scores.
- **Storage & pipeline** — `behavior_*` SQLite schema with indexes, dedup,
  incremental cursors, streaming for large datasets, layered cache and a
  content-fingerprint calculation cache.
- **Engine / orchestrator / scheduler** — `BehavioralEngine` service API,
  passive-provider orchestration with per-provider failure isolation, periodic
  snapshots and a snapshot diff engine.
- **Providers** — passive RSS/Atom and public ActivityPub outbox collectors.
- **Visualization** — inline-SVG heatmap/timeline/bar/network charts (+ optional
  matplotlib PNG / GraphViz DOT), all data also exposed as JSON.
- **Reports** — markdown, JSON, CSV, self-contained HTML, executive summary and
  evidence table, all preserving epistemic labels and limitations.
- **Telegram** — 13 commands, inline keyboards, callback handling, `register_all`
  hook; fail-closed on person scope.
- **Docs** — engine overview + temporal/language/topic/anomaly/baseline/
  interaction/evidence/privacy/performance/telegram guides.

### Quality

- 69 unit/integration/statistical/storage/report tests (Unicode, Thai, timezone,
  timestamp-precision, provider-failure isolation, epistemic-labelling coverage).
- `ruff` clean; `mypy --ignore-missing-imports` clean for the subsystem.
- No circular imports; optional deps (`httpx`/`networkx`/`matplotlib`) degrade
  gracefully; async HTTP uses context-managed sessions (no leaks).

### Notes

- ~11.9k lines across 111 modules.
- Backward compatible: additive only; no existing module was modified except an
  optional guarded command registration in `app.py`.
