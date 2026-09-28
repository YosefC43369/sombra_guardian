# Temporal Analysis

Module: `behavioral_intelligence/temporal/` — analyses *when* public activity was
observed. All timestamps are UTC internally; any timezone shift is a **display**
choice recorded on the result and never asserted as identity evidence.

## What it produces

- **Activity statistics** (`ActivityStats`): posts/day, posts/active-day,
  active/inactive days, coverage, and inter-post interval statistics
  (min/median/mean/max/stdev).
- **Distributions & heatmaps**: hour-of-day (24), weekday (7), month, and 2-D
  heatmaps — `hour_weekday`, `hour_date`, `day_month`, `platform_hour`,
  `platform_day`.
- **Peak windows** (`ActivityWindow`): contiguous UTC hour ranges holding a
  disproportionate share of activity, grown greedily from the busiest hour. The
  engine states *"activity concentrated in HH:00–HH:00 UTC"* — never a chronotype.
- **Bursts** (`Burst`, §5): windows where the rate exceeds a threshold multiple
  of the baseline hourly rate, with absolute/relative change.
- **Inactivity gaps** (`InactivityGap`, §6): prolonged silence, framed as *lack
  of observation*, never physical absence, with prior/following rates.
- **Change points** (`ChangePoint`, §7): abrupt/gradual rate changes via three
  detectors — rolling **z-score**, **CUSUM** (two-sided cumulative sum), and
  **EWMA** control chart. Co-located detections are merged and list every method
  that fired.
- **Seasonality**: autocorrelation of the daily series to surface recurring
  cycles (e.g. weekly rhythm).
- **Cross-platform correlation** (`TemporalCorrelation`, §4): hour-of-day
  histogram intersection + Pearson r between two platforms. Emitted as
  `CORRELATED` with the explicit limitation that synchrony does **not** prove
  the accounts are the same person.

## Timestamp precision

`Observation.timestamp_precision` gates which analyses an event contributes to. A
day-precise crawl hit populates the daily histogram but is **excluded** from the
hour-of-day heatmap — the engine will not pin an event to an hour it does not
actually have.

## Usage

```python
from behavioral_intelligence.temporal import TemporalEngine
result = TemporalEngine(tz_offset_hours=0).analyze(batch)
result.heatmap.hottest()          # (weekday, hour, count)
for a in result.assertions: print(a.render())
```
