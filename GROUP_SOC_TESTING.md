# Group SOC — Testing

Real test suite in `group_soc/tests/` — **88 tests, all passing**, fully offline (no
Telegram, no network). Async pipeline tests use `asyncio.run` (no `pytest-asyncio` needed).

## Run
```bash
python3 -m pytest group_soc/tests/ -q
```

## Fixtures (`conftest.py`)
A fresh temp sqlite DB migrated by the **real** migration runner, a config with the master
switch forced on, and a runtime with the group activated. Nothing is mocked away that the
production path uses — the DB, migrations and stores are the real ones.

## Coverage by area
| File | What it proves |
|---|---|
| `test_models.py` | validation, clamping, row round-trips, transition tables, risk math |
| `test_migration.py` | 0006 creates every table + indexes, runner reaches 0006, verify clean, idempotent |
| `test_storage.py` | idempotent ingest, content-hash aggregates, policy, audit, retention allow-list, dedup lookups |
| `test_normalization.py` | **privacy**: actor ids hashed, raw text/username never stored, domains defanged |
| `test_correlation.py` | each correlator fires on its pattern and stays quiet otherwise; engine dedups |
| `test_detection.py` | threshold/rule/anomaly/sequence detectors; manager dedups + isolates |
| `test_prioritization.py` | dimension→score, band assignment, noisy-OR confidence, repeat urgency |
| `test_alerts.py` | create/fold, auto-escalation, cooldown suppression, valid+illegal lifecycle, grouping |
| `test_cases.py` | create/note/assign/link/close, invalid transitions, not-found |
| `test_incidents.py` | classification, noisy-OR aggregation, linking, lifecycle, member bridge |
| `test_timeline.py` | ordered reconstruction across events/signals/alerts, incident marker, rendering |
| `test_story.py` | four registers separated, confidence caveat present, confidence from incident |
| `test_pipeline.py` | gate stops inactive group, full join-burst flow, duplicate short-circuit, backpressure drop-oldest |
| `test_commands.py` | activation toggle, overview/status, alert/case/incident/watchlist/report commands, never-raises |
| `test_integration.py` | bus→on_event→ingest→alert, `soc.*` not re-ingested, inactive group ignored, plugin metadata |

## Principles
- **No `assert True` filler.** Every test asserts real behavior or a real invariant.
- **Negative cases included** (below-threshold quiet, illegal transitions, suppressed
  re-open, inactive-group ignore, malformed command args).
- **Regression**: the existing platform suites still pass with the new migration + plugin
  present (`tests/test_migrations.py` 29/29, `tests/test_plugins.py` 28/28,
  `tests/test_workflows.py` 29/29). Full-platform boot (`sg_platform.init_platform`) loads
  the plugin dormant with 0 failures.
