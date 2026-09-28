# Anomaly Engine

Module: `behavioral_intelligence/anomaly/` (§27, §30).

Detects change **relative to the entity's own observed baseline**. Wording is
strict throughout: an anomaly is *"anomalous relative to the observed baseline"* —
never "malicious", and the score is a **deviation measure, NOT a threat,
criminality or intent score**.

## Anomaly score (0–100)

`AnomalyEngine.analyze` compares a recent observed window against a prior
`Baseline` and produces an explainable score whose contributing features are
always exposed:

| feature | max points | measure |
|---------|-----------:|---------|
| posting_rate | 30 | observed vs baseline daily rate |
| language_mix | 20 | Jensen–Shannon distance from baseline |
| domain_mix | 15 | Jensen–Shannon distance |
| hour_profile | 15 | 1 − hour-of-day histogram intersection |
| hashtag_mix | 10 | Jensen–Shannon distance |
| new_domains | 10 | fraction of newly-appearing domains |

Bands (spec §30): 0–20 normal · 21–40 minor · 41–60 moderate · 61–80 significant ·
81–100 high deviation. Every `Deviation` row carries `observed`, `baseline`,
`z_score`, `relative_change` and its point `contribution`.

## Supporting detectors

- `outlier.py` — z-score, IQR (Tukey), MAD (robust) univariate outlier detection.
- `drift.py` — Jensen–Shannon distance between two windows for a categorical
  feature (language/hashtag/domain/platform), with top terms on each side.
- `change_detection.py` — coordinates statistical frequency change points
  (CUSUM/z-score/EWMA) with categorical shifts (dominant language, profile
  username/avatar/bio changes) into one list.

## Blue-team framing

Discrete `Anomaly` records (rate spike, language shift, hour-profile shift, new
domains) are produced for analyst attention. They are **not** auto-labelled
malicious; each description ends *"anomalous relative to observed baseline."* The
score's `to_dict()` repeats that it is not a measure of malice or intent.

```python
from behavioral_intelligence.anomaly import AnomalyEngine
score, anomalies, assertions = AnomalyEngine(observed_window_days=7).analyze(obs, entity_id="a")
print(score.score, score.band)
for d in score.top_features(5): print(d.feature, d.contribution)
```
