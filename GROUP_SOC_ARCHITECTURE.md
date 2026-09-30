# Group Security Operations Center (`group_soc`) — Architecture

> A modular, production-oriented Security Operations Center subsystem for Telegram
> communities, layered on top of Sombra Guardian's existing event bus, plugin
> system and migration framework. Defensive (Blue Team) only.

Version: see `group_soc/version.py` · Status: initial build

---

## 1. Purpose

Sombra Guardian already has strong *primary* detectors (Link Guard, Scam/Impersonation,
Join Guard, IOC intel, CTI, behavioral intelligence). What it lacks is a **second-order
layer** that treats a group's security activity as **one continuous story** rather than a
stream of isolated moderation events.

`group_soc` is that layer. It implements the SOC loop:

```
OBSERVE → COLLECT → NORMALIZE → CORRELATE → DETECT → PRIORITIZE
        → INVESTIGATE → RESPOND → DOCUMENT → LEARN
```

It turns raw Telegram + detector events into a small set of durable, reviewable
objects: **Event → Signal → Alert → Case / Incident → Timeline → Story → Report.**

Non-goals (kept out by design, exposed as clean extension points instead):
Security DNA, Digital Twin, Temporal Graph, Threat Hunting, AI Security Analyst,
Autonomous Control Plane. The SOC emits and stores enough structured data for those
to attach later; it does not implement them.

## 2. Architecture

`group_soc` is a **plugin-hosted subsystem**. It never imports `app.py`. It attaches
through the three seams the platform already exposes:

1. **Migration** `migrations/m0006_group_soc.py` — creates all `soc_*` tables
   (auto-discovered, non-destructive, reversible).
2. **Plugin** `plugins/builtin/group_soc_suite.py` — a `BasePlugin` that builds the
   SOC runtime, subscribes it to the event bus, and registers the `/soc` commands.
3. **Services / adapters** `group_soc/integrations/*` — thin adapters over the
   existing incident/intel/integrity systems (reuse, never re-implement).

```
                         TELEGRAM  (python-telegram-bot, app.py)
                            │  additive emits (unchanged behaviour)
                            ▼
                  workflows.EventBus  ── existing async pub/sub
                            │  message.received / member.joined / member.left
                            │  rule.matched / intel.ioc_matched / detection.triggered
                            │  incident.created / evidence.created ...
                            ▼
   ┌───────────────────────────────────── group_soc.SocRuntime ────────────────────────────┐
   │                                                                                          │
   │   collector.EventRouter                                                                  │
   │        │  raw bus Event → routed to a collector                                          │
   │        ▼                                                                                 │
   │   normalization.Normalizer  ── redact/hash PII → SecurityEvent (immutable record)        │
   │        │                                                                                 │
   │        ▼                                                                                 │
   │   pipeline.Pipeline  (bounded queue + ordered stages, backpressure)                      │
   │        │                                                                                 │
   │   ┌────┼───────────────┬──────────────────┐                                             │
   │   ▼    ▼               ▼                  ▼                                             │
   │ store  correlation   detection         enrichment                                       │
   │ (event) (temporal/    (rule/threshold/  (watchlist/intel adapter)                        │
   │         entity/seq)    sequence/anomaly)                                                 │
   │   └────┼───────────────┴──────────────────┘                                             │
   │        ▼                                                                                 │
   │   SecuritySignal  ── "something correlated/detected", with confidence                    │
   │        │                                                                                 │
   │        ▼                                                                                 │
   │   prioritization.PriorityEngine  (severity × confidence × impact × urgency ...)          │
   │        │                                                                                 │
   │        ▼                                                                                 │
   │   alerts.AlertManager  (dedup → suppress → group → escalate → lifecycle)                 │
   │        │                                                                                 │
   │   ┌────┼───────────────┬──────────────────┐                                             │
   │   ▼    ▼               ▼                  ▼                                             │
   │ SOC   investigation   incidents         (emit soc.alert.created onto bus)                │
   │ case   (hypothesis/    (adapter →                                                        │
   │         evidence/pivot)  member_incident)                                                │
   │   └────┼───────────────┴──────────────────┘                                             │
   │        ▼                                                                                 │
   │   timeline.TimelineBuilder → stories.StoryGenerator → reporting.ReportBuilder            │
   │                                                                                          │
   └──────────────────────────────────────────────────────────────────────────────────────┘
                            │  /soc commands (admin-gated, plain text)
                            ▼
                         TELEGRAM
```

## 3. Components

| Package | Responsibility |
|---|---|
| `models/` | Immutable value objects: `SecurityEvent`, `Severity/Priority` dims, `SecuritySignal`, `Alert`, `Case`, `Incident`, `TimelineEntry`, `Story`, `Entity`. Pure dataclasses, telegram-free, JSON round-trippable. |
| `collector/` | Adapt raw bus `Event`s into the SOC. `event_router` maps bus event types → collectors; per-source collectors extract the relevant fields. |
| `normalization/` | `Normalizer` builds a `SecurityEvent` from routed input, applying **redaction/hashing** (privacy by default) and light enrichment/context. |
| `pipeline/` | `PipelineStage` protocol, ordered `Pipeline`, bounded async `Queue`, `dispatcher`, `backpressure`. Keeps heavy work off the Telegram handler path. |
| `correlation/` | Temporal, entity, behavioral, sequence and clustering correlators + `CorrelationEngine`. Emits correlation records, never a verdict. |
| `detection/` | `rule_engine`, `threshold`, `sequence`, `anomaly` detectors behind a `DetectorManager`. Second-order: consumes SOC events + upstream signals. |
| `prioritization/` | Multi-dimensional scoring (severity, confidence, impact, urgency, exposure, persistence) → normalized `Priority`. |
| `alerts/` | `AlertManager` + `deduplication`, `suppression`, `grouping`, `escalation`, `lifecycle` (NEW→…→CLOSED). |
| `cases/` | SOC `CaseManager`: assignment, notes, evidence links, lifecycle. |
| `incidents/` | SOC `IncidentManager`: classification, containment hooks, resolution, lifecycle; bridges to `member_incident` via adapter. |
| `timeline/` | Reconstruct an ordered timeline from scattered events/alerts; render to text. |
| `stories/` | Turn a timeline into a readable **security story** with facts / analysis / hypothesis / recommendation kept separate. |
| `investigation/` | Investigator state: hypotheses, evidence graph, event/entity/timeline pivots, case linking. |
| `watchlist/` | Monitoring targets (users/bots/domains/urls/phrases/event-types) + matcher. Monitoring ≠ malicious. |
| `reporting/` | Daily/weekly/incident/executive/technical report builders + exporters. |
| `metrics/` | SOC/detection/performance counters (MTTA/MTTR, throughput, queue depth). |
| `integrations/` | Adapters: `event_bus`, `incident` (→member_incident), `threat_intel`, `entity_fusion`, `behavioral`, `evidence`, `workflow`. |
| `commands/` | `/soc …` command tree. Telegram imported only at call time. |
| `storage/` | sqlite repositories (`event_store`, `alert_store`, `case_store`, incident/timeline/watchlist/investigation) + `repository` base. |
| `runtime.py` | `SocRuntime` orchestrator; `get_runtime(db_path, emit)` cached per DB (mirrors `blueteam.runtime`). |

## 4. Data Flow

1. `app.py` emits existing events onto the bus (unchanged).
2. The plugin subscribed `SocRuntime.on_event` to the relevant types.
3. `on_event` → `EventRouter` → `Normalizer` → `SecurityEvent` (persisted to `soc_events`).
4. The event is offered to the `Pipeline`; stages run async (correlation, detection, enrichment).
5. A detection/correlation produces a `SecuritySignal` (persisted `soc_signals`).
6. `PriorityEngine` scores it.
7. `AlertManager` dedups/suppresses/groups → may create an `Alert` (`soc_alerts`) and emit `soc.alert.created`.
8. Analysts triage via `/soc`; alerts feed `Case`/`Incident`; timeline & story are built on demand.

## 5. Event Flow (bus contracts)

**Consumed** (existing): `message.received`, `member.joined`, `member.left`,
`detection.triggered`, `rule.matched`, `intel.ioc_matched`, `incident.created`,
`evidence.created`.

**Produced** (new, `group_soc/integrations/event_bus.py`, frozen contracts):
`soc.event.recorded`, `soc.signal.created`, `soc.alert.created`,
`soc.alert.escalated`, `soc.case.created`, `soc.incident.created`,
`soc.incident.resolved`. All PII-safe payloads (ids/hashes only; never raw content).

## 6. Database Design

All tables `soc_`-prefixed, chat-scoped, created by migration `0006` (non-destructive,
reversible). See `GROUP_SOC_DATABASE.md`. Core tables:
`soc_events`, `soc_signals`, `soc_alerts`, `soc_cases`, `soc_case_notes`,
`soc_incidents`, `soc_timeline`, `soc_watchlist`, `soc_investigations`,
`soc_evidence_links`, `soc_audit_log`. Indexed on
`chat_id, ts, event_type, actor_hash, correlation_id, severity, status`.

## 7. Detection Pipeline

`PipelineStage` protocol: `async def process(ctx) -> ctx`. Stages are ordered and
composable; new detectors register without touching the pipeline. Stages:
`PersistStage → CorrelateStage → DetectStage → EnrichStage → ScoreStage → AlertStage`.
Heavy correlation runs in the pipeline worker, never inline in the update handler.

## 8. Alert Lifecycle

`NEW → TRIAGED → ACKNOWLEDGED → INVESTIGATING → ESCALATED → RESOLVED → CLOSED`
(+ `SUPPRESSED`). Transitions validated; dedup by `dedup_key`, cooldown-based
suppression, correlation-id grouping, threshold escalation. Every transition audited.

## 9. Incident Lifecycle

`OPEN → CONTAINED → ERADICATED → RECOVERED → RESOLVED → CLOSED`. A SOC incident
aggregates alerts/cases; when it concerns a specific member it bridges to
`member_incident` through the adapter (single source of truth for member custody).

## 10. Command Architecture

One `/soc` root with subcommands (see `GROUP_SOC_COMMANDS.md`). Each command is a pure
service returning text; the telegram adapter (registered by the plugin) wraps it.
Admin-gated via `PermissionLevel.ADMIN` → platform `is_admin`.

## 11. Worker Architecture

Reuses the platform's async loop. The `Pipeline` owns one bounded `asyncio.Queue`
and a drain task started at plugin setup; a periodic `cleanup` applies retention.
No new OS processes. Bounded queue = backpressure; overflow is counted & dropped-oldest.

## 12. Integration Points

Event bus (in), `soc.*` events (out), `member_incident` (incidents), `integrity_ledger`
(anchoring), `blueteam.intel` (IOC lookups — optional adapter), workflow engine
(SOC events can trigger playbooks). All adapters degrade to no-ops if the target is
absent — the SOC never crashes because a dependency changed.

## 13. Security Boundaries

Defensive only. No shell exec, no untrusted file exec, no auto network scans, no
Telegram-permission bypass. External calls are opt-in and off by default. User content
is stored redacted/hashed; alerts/reports render defanged, plain text.

## 14. Performance Model

Bounded queries (pagination, `LIMIT`), indexed lookups, per-chat ring buffers for
correlation windows, batch inserts, WAL. No `SELECT *` on unbounded tables. Correlation
windows are time-bounded and count-capped.

## 15. Failure Handling

Idempotent event ingest (`event_id` unique), retry-free fire-and-forget from producers,
per-stage try/except with structured logging, dead-letter counter, health checks. A SOC
failure can never break moderation (every handler is isolated).

## 16. Testing Strategy

Real pytest suite in `group_soc/tests/` — models, storage/migration, normalization
(redaction), pipeline, correlation, detection, prioritization, alerts (lifecycle/dedup),
cases, incidents, timeline, story, watchlist, commands (service-level), integration
(plugin wiring, event round-trip). No `assert True` filler. Runs offline (telegram-free core).

## 17. Migration Strategy

Additive only. `m0006` creates tables; nothing existing is altered. The plugin is
**dormant by default** (`SOC_ENABLED=false`), so deploying the code changes nothing until
an admin turns it on. Rollback = disable plugin and/or `downgrade` the migration.
