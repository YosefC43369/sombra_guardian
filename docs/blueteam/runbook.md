# Blue Team v0.8 runbook

## Kill switches
- Everything: `BLUETEAM_V08_ENABLED=false` → all v0.8 modules dormant (plugin idle).
- Per module: `BLUETEAM_INTEL_ENABLED` / `BLUETEAM_DAC_ENABLED` /
  `BLUETEAM_POSTURE_ENABLED` = `false`.
- Emergency, no restart: disable rules (`/rule disable <id>`) or feeds; add
  false-positive domains to `/intel whitelist`.

## Health
`/plugins health` shows `blueteam-v08` with intel index size, active rule count,
posture status. Metrics registry counters: `bt_intel_*`, `bt_dac_*`, `bt_posture_*`.

## Common situations

### A feed keeps failing
`/intel feeds` shows `failures`/`last_status`. Causes:
- `license_blocked` — the feed's license is uncertain; it's disabled by design.
- `error:SSRF guard: …` — the feed host resolved to a private/blocked address.
- `error:http 401/403` — abuse.ch now needs an Auth-Key: set
  `BLUETEAM_INTEL_ABUSECH_AUTHKEY`.
- `quarantined_growth` — the feed returned far more items than last time; inspect the
  source before re-enabling. Growth threshold: `BLUETEAM_INTEL_GROWTH_RATIO`.

### A rule is too noisy / wrong
- Move it to `shadow` (`/rule shadow <id>`) to keep evaluating without acting, or
  `disable`. Check `/rule backtest <id>`. Fix and re-`import` (bumps a version);
  `/rule rollback` if a change regressed.

### A rule was auto-disabled (circuit breaker)
`/rule stats` lists `breakers_open`. A rule that repeatedly blew its time budget is
skipped for a cooldown. Simplify its regex/condition and re-import.

### Posture score dropped
`posture.score_dropped` fired. `/posture explain` names the controls that regressed
and how to fix them; `/posture whatif` previews a fix; `/posture trend` shows history.

### Verify a client report
`/posture verify <report_id>` re-hashes the supplied report and compares to the
sealed SHA-256. Mismatch ⇒ the file was altered after generation.

## Backup / restore
All state is in the SQLite DB (`bt_*` tables). Back up the DB file. The migration is
reversible (`migrate_down 0003`) but that **drops** v0.8 tables — export first
(`/intel export`, `/posture report json`).

## Performance envelope (indicative, single-core)
- Intel lookup: ~9–16 µs/op over a 100k-IOC index (60k–110k ops/s).
- DaC evaluate: ~54 µs/msg for 37 enabled rules (~18k msgs/s) with the AC prefilter.
- Posture score: ~120 µs for 20 controls.
Well within a Telegram bot's message rate; analysis is fail-open regardless.
