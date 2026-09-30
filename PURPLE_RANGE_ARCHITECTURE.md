# Purple Range (`purple_range`) — Architecture

> A purple-team **content, telemetry and analytics** layer on top of Sombra Guardian's
> existing `purpleteam.py` engine. It turns curated ATT&CK emulation plans into real
> purple-team exercises, generates **synthetic** telemetry for detection tuning, and
> reports program-wide detection coverage. Defensive / adversary-emulation only —
> **no agents, no command execution, no shell, no scope/RoE bypass.**

Version: see `purple_range/version.py` · Status: initial build

---

## 1. Purpose & non-duplication

The repo already owns the purple-team **engine**:
- `purpleteam.py` — exercises, per-technique emulations, detection outcomes (with MTTD
  latency + DeTT&CT coverage states), tuning lifecycle, timeline, RoE binding.
- `redteam.py` / `scope_policy.py` — engagements, Rules of Engagement (`check_roe`),
  kill switch, authorization/scope.
- `threat_actor_intelligence/mitre/ATTACKEngine` — the ATT&CK catalog.

`purple_range` does **not** re-implement any of these. It adds the missing *content and
analytics* on top:

1. **Emulation plan library** — curated, versioned ATT&CK technique chains (fixtures).
2. **Plan instantiation** — one call creates a real `purpleteam` exercise and adds each
   step as an emulation (delegates to `create_exercise` / `add_emulation`).
3. **Synthetic telemetry generator** — deterministic fixture events per technique, for
   detection tuning. Pure data; touches no host.
4. **Detection-expectation catalog** — technique → expected telemetry + expected rule ids.
5. **Coverage analytics** — a program-wide ATT&CK coverage matrix across exercises.
6. **SOC bridge (opt-in)** — replay a plan's synthetic telemetry through `group_soc` to
   exercise the detection pipeline end-to-end.

## 2. Security posture (what this is NOT)

- **No agents / no C2 / no remote control.** Nothing connects to a host or endpoint.
- **No command execution.** No `subprocess`, `os.system`, `eval`, `exec`; no `/shell`,
  `/exec`, `/cmd`. "Emulation" means *records and synthetic data*, never execution.
- **No authorization bypass.** There is no `force` / `ignore_scope` / `bypass_roe` /
  `admin_override`. Instantiation goes through `purpleteam`, which enforces engagement
  ownership and re-checks RoE at `start_exercise`. `purple_range` never imports or
  weakens `scope_policy.py`.
- **Fail-closed, admin-gated, dormant by default** (`PURPLE_RANGE_ENABLED=false`).

## 3. Architecture

```
            Telegram  (/range …, admin-gated)
                 │
                 ▼
        purple_range.commands
                 │
                 ▼
        PurpleRangeService  ── the facade
     ┌───────────┼─────────────┬───────────────┬─────────────┐
     ▼           ▼             ▼               ▼             ▼
 plans/      telemetry/     expectations/    coverage/    integrations/
 (library +  (synthetic     (technique →     (ATT&CK      (purpleteam_bridge,
  loader +    fixtures)      expected         coverage      soc_bridge)
  registry)                  telem/rules)     matrix)
     │           │             │               │             │
     │           │             │               │             ├── purpleteam.create_exercise / add_emulation / record_detection
     │           │             │               │             └── group_soc pipeline (opt-in, synthetic events)
     ▼           ▼             ▼               ▼
        purple_range.storage  (pr_* tables, migration 0007)
                 │
                 ▼
        ATTACKEngine (reused)   redteam/scope_policy (RoE — reused, never bypassed)
```

## 4. Plan → exercise flow (the acceptance path)

```
Red Team Lead creates + authorizes engagement (existing redteam.py)
        │
        ▼
/range plans                      → browse the curated library
        │
        ▼
/range instantiate <plan> <eng>   → purple_range builds a purpleteam EXERCISE:
        │                             create_exercise(chat, engagement, name)
        │                             for step in plan.steps: add_emulation(...)
        ▼
purpleteam.start_exercise(...)    → RoE re-checked here (existing governance)
        │
        ▼
/range telemetry <technique>      → synthetic telemetry fixtures for tuning
        │
        ▼
(opt-in) /range simulate <ex>     → replay synthetic telemetry into group_soc
        │
        ▼
purpleteam.record_detection(...)  → analyst records observed outcome (existing)
        │
        ▼
/range coverage                   → program-wide ATT&CK coverage matrix
```

## 5. Components
| Package | Responsibility |
|---|---|
| `models.py` | `Plan`, `PlanStep`, `Expectation`, `TelemetryEvent`, `CoverageCell` dataclasses (pure) |
| `attack.py` | `AttackCatalog` adapter over `ATTACKEngine` (degrades to id-only if unavailable) |
| `plans/` | fixture schema, loader, registry, and the curated `library/*.json` |
| `telemetry/` | per-technique synthetic telemetry templates + deterministic generator |
| `expectations/` | technique → expected telemetry types + expected detection rule ids |
| `coverage/` | program-wide coverage matrix built from `purpleteam` data + `ATTACKEngine` |
| `storage/` | `pr_*` repositories (plans catalog, instantiations, coverage snapshots) |
| `integrations/` | `purpleteam_bridge` (instantiate), `soc_bridge` (replay to group_soc) |
| `service.py` | `PurpleRangeService` — the facade the commands call |
| `runtime.py` | `get_runtime(db_path)` cached per DB |
| `commands/` | `/range` dispatcher (pure text; Telegram-free core) |

## 6. Database (migration 0007, additive, reversible)
`pr_plans`, `pr_plan_steps` (custom/registered plans), `pr_instantiations`
(plan → exercise link + operator + ts), `pr_coverage_snapshots` (point-in-time program
coverage). Audit reuses `security.write_audit_log` (repo pattern); no new audit table.
All parameterized, indexed, `CREATE TABLE IF NOT EXISTS`.

## 7. Integration points
- `purpleteam.create_exercise / add_emulation / record_detection / get_technique_coverage
  / get_exercise_metrics / list_exercises / normalize_technique` (reuse)
- `threat_actor_intelligence.mitre.ATTACKEngine` (reuse, via adapter)
- `redteam` / `scope_policy` governance (respected through purpleteam, never bypassed)
- `group_soc` pipeline (opt-in synthetic telemetry replay)
- `security.write_audit_log` (audit), `envutil` (config), plugin + migration + event-bus idioms

## 8. Testing
Real pytest suite: plan schema/loader, attack adapter, telemetry determinism, expectations,
coverage math, purpleteam bridge (against a temp DB with a real engagement), soc bridge,
service, commands. Offline; no Telegram, no network. Existing suites must stay green.
