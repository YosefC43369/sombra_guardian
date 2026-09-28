# Behavioral Intelligence Engine v1.0

A subsystem of Sombra Guardian that analyses patterns in **publicly available**
OSINT/SOCMINT activity and renders an investigation dossier with evidence,
confidence and explicit limitations attached to every conclusion.

It answers, for an authorized target:

- **When** is the account publicly active? (temporal)
- **How** does it write — languages, scripts, recurring terms? (linguistic)
- **What** does it post about and link to? (content)
- **Who** does it publicly interact with? (social)
- **What infrastructure** does it reference? (infrastructure)
- **How does recent behaviour deviate** from its own baseline? (anomaly)

---

## Core principle (enforced in code)

> The engine describes **observable behaviour in public information**. It does
> **not** determine mental state, psychological diagnosis, personality, criminal
> intent, guilt, ideology-as-identity, or other sensitive attributes.

This is not a disclaimer bolted on at the end — it is mechanical. Every
analytical output is an `Assertion` (`models/confidence.py`) carrying:

| field | meaning |
|-------|---------|
| `kind` | `OBSERVED` · `CORRELATED` · `INFERRED` · `UNKNOWN` |
| `confidence` | 0–1 score with sample size, observation period, source count, supporting & contradicting signals |
| `evidence` | `EvidenceRef`s back to the public observations/sources |
| `observation_period` | the window the claim covers |
| `limitations` | explicit statements of what it cannot establish |

Reports render `kind` verbatim, so a reader can never mistake a correlation for
a conclusion. Concretely:

- ✅ *"Public activity was concentrated 19:00–23:00 UTC during the observed period."*
- ❌ *"The person is nocturnal."*
- ✅ *"The account frequently switched between Thai and English."*
- ❌ *"The person is Thai-American."*

Cross-platform synchrony is `CORRELATED` and carries *"does not prove the
accounts belong to the same person."* Cross-account behavioural consistency is
supporting evidence, never an identity proof — identity resolution is deferred to
the Entity Fusion engine under authorization.

---

## Scope & posture

- **Public data only.** Providers are passive, read-only clients: no
  authentication bypass, no paywalls, no stolen sessions/cookies, no brute force.
  `robots.txt`, provider terms and per-host rate limits are respected.
- **No biometrics.** Media analysis counts publicly-declared attachments; it
  performs no facial recognition or biometric identification.
- **Fail-closed authorization.** `behavioral_intelligence.authorization` gates
  every run and **delegates to the shared `entity_fusion` scope gate**, so there
  is exactly one scope decision in the codebase. Account/person-level analysis
  requires an explicit `allow_person_scope` tied to a reviewed `scope_policy`
  program — **off by default**. Telegram admin is never sufficient.

---

## Architecture

```
behavioral_intelligence/
  engine.py            BehavioralEngine — the public service API (§43)
  orchestrator.py      collect → ingest → analyze → persist
  pipeline.py          incremental processing (dedup + cursors, large-dataset)
  scheduler.py         periodic snapshots + diff engine
  cache.py             content-hash-keyed calculation cache
  configuration.py     env-driven config (stdlib, read at call time)
  authorization.py     fail-closed BehaviorGate (delegates to entity_fusion)
  util.py              dependency-free numeric/text helpers

  models/              Observation + all typed results + the epistemics layer
  temporal/            rate, heatmaps, bursts, gaps, change points, seasonality
  linguistic/          script/language detection, switching, keywords, phrases,
                       hashtags, terminology, transliteration
  content/             topics + evolution, URL/domain behaviour, media, reposts,
                       threads, content-reuse (SHA-256/SimHash/MinHash/cosine)
  social/              mention/reply networks, interactions, communities,
                       platform migration
  infrastructure/      domain/certificate/repository/IOC reference behaviour
  anomaly/             baseline, outliers, drift, change detection, scoring
  scoring/             activity / consistency / anomaly / confidence scores
  visualization/       inline-SVG heatmap/timeline/charts/network (+optional PNG)
  reports/             markdown / json / csv / html / executive / evidence
  providers/           passive RSS & ActivityPub collectors
  telegram/            commands, callbacks, keyboards, register hook
  tests/               unit / integration / statistical / storage / report tests
```

### Dependency posture

Async- and stdlib-first, layered on the `osint` framework's HTTP backbone.
`httpx`, `networkx` and `matplotlib` are **optional**: the pure analytical core
(temporal, linguistic, content, social, anomaly, scoring, storage, reports) runs
and is fully tested with zero third-party dependencies. Network providers and PNG
renderers activate when those libraries are present, degrading to inline-SVG /
"no fetch" cleanly otherwise.

---

## Quick start

```python
from behavioral_intelligence import BehavioralEngine, ObservationBatch
from behavioral_intelligence.authorization import AuthorizationContext
from behavioral_intelligence.models import Observation

engine = BehavioralEngine()
batch = ObservationBatch([Observation(...), ...], entity_id="actor-7", label="@alice")

# person-level analysis requires an authorized scope_policy program:
ctx = AuthorizationContext(program_id=7, allow_person_scope=True)

profile = engine.analyze_entity(batch, ctx)
print(engine.generate_report(batch, ctx, fmt="markdown"))
```

### Service API (`BehavioralEngine`, §43)

All methods authorize first (fail-closed) and return typed models:

`analyze_entity` · `build_baseline` · `detect_anomalies` · `build_timeline` ·
`analyze_languages` · `analyze_topics` · `analyze_interactions` ·
`compare_periods` · `compare_accounts` · `generate_report`

---

## Collection (orchestrator + providers)

```python
from behavioral_intelligence.orchestrator import BehavioralOrchestrator
from behavioral_intelligence.providers import RSSProvider, ActivityPubProvider

orch = BehavioralOrchestrator(providers=[RSSProvider(), ActivityPubProvider()])
profile = await orch.run("https://example.org/feed.xml", ctx, entity_id="actor-7")
```

One provider failing never aborts a run — it becomes a `provider_status` entry on
the profile (spec §56). See `PERFORMANCE.md` for large-dataset behaviour.

---

## Integration with the rest of Sombra Guardian

- **Entity Fusion** — consumes `entity_id`/aliases and reuses the same scope gate.
  Behaviour is aggregated across an actor's correlated accounts *within an
  authorized program*; the engine never performs identity resolution itself.
- **SOCMINT / OSINT** — public posts/profiles/threads are lifted into
  `Observation` via `Observation.from_record`.
- **Threat Intelligence / IOC** — `infrastructure/public_ioc_activity.py`
  cross-references public IOC mentions against the repo's `findings` store when
  available.
- **SQLite storage** — `behavior_*` tables, standard-library `sqlite3`, matching
  `entity_fusion`/`scope_policy` conventions.
- **Telegram** — `behavioral_intelligence.telegram.register_all(application)`.

See the companion docs: `TEMPORAL_ANALYSIS.md`, `LANGUAGE_ANALYSIS.md`,
`TOPIC_ENGINE.md`, `ANOMALY_ENGINE.md`, `BASELINE_ENGINE.md`,
`INTERACTION_ANALYSIS.md`, `EVIDENCE_MODEL.md`, `PRIVACY_MODEL.md`,
`PERFORMANCE.md`, `TELEGRAM_COMMANDS.md`.
