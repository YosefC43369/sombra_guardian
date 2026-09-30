# Group SOC — Integration

The SOC attaches to Sombra Guardian only through the platform's existing extension seams.
**It never imports `app.py`** and modifies no existing module.

## The three attachment points
1. **Migration** — `migrations/m0006_group_soc.py` (auto-discovered; creates `soc_*`).
2. **Plugin** — `plugins/builtin/group_soc_suite.py` (`GroupSocPlugin`, auto-discovered by
   `plugins.loader`). On `setup(ctx)` it:
   - builds `group_soc.get_runtime(db_path, emit=bind_emit(ctx.event_bus))`,
   - subscribes `runtime.on_event` to every type in `CONSUMED_BUS_EVENTS`,
   - registers the admin `/soc` command.
   It is **dormant** unless `SOC_ENABLED=true` (safe default).
3. **Runtime** (`group_soc/runtime.py`) — one `SocRuntime` per DB (cached, mirroring
   `blueteam.runtime.get_runtime`).

## Events consumed (already emitted by the platform)
`message.received`, `member.joined`, `member.left` (app.py) · `detection.triggered`
(app.py) · `rule.matched`, `intel.ioc_matched` (blueteam) · `incident.created`,
`evidence.created`. The collector/router only wires types the platform actually emits;
the broader taxonomy is an extension point, not a fabricated capability.

## Events produced (clean interfaces for future subsystems)
`soc.event.recorded`, `soc.signal.created`, `soc.alert.created`, `soc.alert.escalated`,
`soc.case.created`, `soc.incident.created`, `soc.incident.resolved` — all PII-safe
payloads. These are how Threat Hunting / AI Analyst / Autonomous Control-Plane etc. attach
later without touching SOC internals. The SOC does not re-ingest its own `soc.*` events.

## Adapters (reuse, never duplicate — all degrade to no-ops)
| Adapter | Reuses | Behavior |
|---|---|---|
| `integrations/incident.py` | `member_incident.py` | bridge a SOC incident to a member incident (single source of truth for member custody) |
| `integrations/integrity.py` | `integrity_ledger.py` | anchor a compact, non-PII incident fingerprint into the tamper-evident ledger |
| `integrations/threat_intel.py` | `blueteam.intel` | optional, gated, **local** IOC lookup |
| `integrations/event_bus.py` | `workflows.EventBus` | emit binding + typed SOC event contracts |

## What this module does NOT re-implement
Primary detection (`detection.py`, `blueteam` guards, `blueteam.intel`) stays authoritative;
the SOC is a **second-order** layer that correlates across their outputs. `bb_case.py`
(bug-bounty findings) is a different domain and is untouched.

## Files added / modified
- **Added**: `group_soc/**` (subsystem), `migrations/m0006_group_soc.py`,
  `plugins/builtin/group_soc_suite.py`, `GROUP_SOC_*.md`.
- **Modified**: `.env.example` (append-only SOC config block). No existing code changed.
