# Blue Team v0.8 architecture

Three defensive modules — **Threat Intel/IOC** (`blueteam/intel`),
**Detection-as-Code** (`blueteam/dac`), **Security Posture** (`blueteam/posture`) —
on a shared platform (`blueteam/platform`), wired into the bot by one auto-discovered
plugin (`plugins/builtin/blueteam_v08.py`). Everything is **passive and defensive**.

## Layering (enforced by `tests/test_blueteam_arch.py`)

```
handlers / commands      (telegram only at call time)
      │  depends on
services                 (orchestration; depends only on ports/Protocols)
      │
adapters                 (SQLite; parameterized; bt_ tables)
      │
domain / pure core       (no telegram, no sqlite, no I/O)
```

Rules the fitness test enforces statically (via `ast`):
1. No `blueteam.*` module imports `app.py` or `sg_platform.py`.
2. No import cycles among `blueteam.*` modules.
3. `blueteam.platform.*` is the base — it never imports intel/dac/posture.
4. `*/domain.py` imports no adapters/services/handlers, no `telegram`, no `sqlite3`.
5. Event contracts stay frozen dataclasses with a `schema_version`.

## Shared platform (`blueteam/platform`)
- `events.py` — versioned frozen event contracts (see `events.md`).
- `metrics.py` — in-process counter/gauge/histogram registry (no dependency).
- `clock.py` — injectable clock + `FakeClock` for deterministic tests.
- `batcher.py` — write-behind batcher (flush by size/interval/shutdown, off-loop,
  bounded with drop-oldest backpressure).
- `scheduler.py` — persistent job scheduler port (`JobStore`), lease (compare-and-set),
  jitter, catch-up-once missed-run policy.
- `circuit_breaker.py` — closed/open/half-open breaker.
- `tenancy.py` — Tenant/group/Role; `TenantScope.guard` for repository-level isolation
  (a single group is its own tenant `chat:<id>`).
- `config.py` — typed config via `envutil`, safe/off defaults, clamping, kill switch.
- `container.py` — the DI container assembled by the wiring plugin.

## Module shape (same for all three)
`domain` (pure) → `service` (ports) → `adapters` (SQLite) + `commands` (text). The
service depends only on `typing.Protocol` ports; the wiring plugin injects the
concrete SQLite adapters, the metrics registry, the event `emit`, and the integrity-
ledger `sealer`.

## Data flow on a message (fail-open)
`message.received` → plugin `_analyze`:
1. build a normalized **record** (`dac/records.py`) from the payload;
2. DaC `evaluate` (Aho-Corasick prefilter → compiled predicates → aggregation);
3. Intel URL lookup (double-buffered index);
4. emit **defanged** `rule.matched` / `intel.ioc_matched` events;
5. opportunistic, throttled feed-sync / posture-snapshot in an executor.

Any exception in analysis is swallowed — detection is fail-open so it can never
break message handling. Permission checks are fail-closed.

## Persistence
All new schema is in `migrations/m0004_blueteam_intel_gov.py`, `bt_`-prefixed,
`IF NOT EXISTS`, reversible (`downgrade`), indexed per access pattern, WAL.
