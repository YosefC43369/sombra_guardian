# Purple Range — Testing

Real pytest suite in `purple_range/tests/` — **41 tests, all passing**, fully offline.

## Run
```bash
python3 -m pytest purple_range/tests/ -q
```

## Fixtures (`conftest.py`)
One temp sqlite DB shared by the legacy engine modules (`security`, `scope_policy`,
`redteam`, `purpleteam` — whose DB path is a module global) and by purple_range, with all
their tables initialised and migrations applied, plus a real `redteam` engagement. Nothing
mocked away that the production path uses.

## Coverage by file
| File | Proves |
|---|---|
| `test_models_plans.py` | plan/step validation, normalization, library load, registry, round-trip |
| `test_telemetry.py` | determinism per seed, max-event cap, synthetic provenance, lab-safe values |
| `test_expectations_attack.py` | expectation catalog (+ parent-technique fallback), ATT&CK adapter |
| `test_bridge_service.py` | instantiate → real purpleteam exercise; **wrong-chat / missing engagement denied** |
| `test_coverage.py` | cross-exercise aggregation, summary math, snapshot persistence |
| `test_commands.py` | `/range` dispatch for every subcommand; never raises on bad input |
| `test_migration.py` | 0007 creates pr_* tables, runner verifies, idempotent |
| `test_security_posture.py` | **no exec/bypass primitives, no scope_policy import, no shell commands** |
| `test_integration.py` | plugin metadata + full plan→exercise→coverage→snapshot flow |

## Regression
The existing platform suites still pass with the new migration + plugin present
(`tests/test_migrations.py` 29/29, `tests/test_plugins.py` 28/28), the `group_soc` suite
still passes (88/88), and `sg_platform.init_platform` boots with `purple-range` loaded and
dormant, 0 failures.

## Principles
No `assert True` filler. Negative/denial cases are explicit (wrong-chat engagement, missing
engagement, unknown plan, bad command args). The security posture is a *test-enforced
invariant*, not a convention.
