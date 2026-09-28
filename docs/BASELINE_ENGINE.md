# Baseline Engine

Module: `behavioral_intelligence/anomaly/baseline.py` (§8).

A **baseline** is the entity's *own prior behaviour* — the reference the anomaly
engine deviates against. Anomalies are therefore always relative to self, never
to a population norm the engine has not observed.

## Features captured (`Baseline`)

- posts/day, posts/hour
- inter-post interval mean & stdev
- hour-of-day histogram (24 buckets)
- distributions: language, platform, topic, hashtag, domain (each summing to ~1)
- sample size and the exact `period_start`/`period_end` it was built from

## Configurable windows

`build_baselines` builds one baseline per configured window (default **7 / 30 /
90 days**, set via `BEHAVIORAL_BASELINE_WINDOWS`). A custom window is a single
`build_baseline(observations, window_days=N)` call.

```python
from behavioral_intelligence.anomaly import build_baseline, build_baselines
b30 = build_baseline(observations, window_days=30, entity_id="actor-7")
weekly, monthly, quarterly = build_baselines(observations, windows=(7, 30, 90))
```

The baseline is built from data **before** the observed window when used for
anomaly detection, so the comparison is prior-behaviour vs. recent-behaviour —
not a window against itself. Baselines can be persisted (`SQLiteStore.save_baseline`)
and retrieved (`latest_baseline`) for incremental runs.
