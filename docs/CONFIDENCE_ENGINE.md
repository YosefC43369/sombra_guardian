# Confidence Engine

`entity_fusion/confidence.py` turns a cluster of correlated entities into an
explainable confidence verdict. It never emits a bare number.

## Output — `ConfidenceReport`

| Field | Meaning |
| --- | --- |
| `score` | 0–100. |
| `band` | `conclusive` (≥90), `strong` (≥75), `moderate` (≥55), `weak` (≥35), `insufficient` (<35). |
| `positives` | Facts supporting one-entity (strongest link, each firing signal, corroboration, hard identifier). |
| `negatives` | Facts against it (contradicting singular attributes, negative-weight evidence). |
| `conflicts` | Human-readable list of contradictions. |
| `human_explanation` | A narrative paragraph. |
| `machine` | A machine-readable dict for pipelines. |

## Scoring model (deterministic and auditable)

```
base          = strongest pairwise link score in the cluster        (0..100)
+ corroboration = per-independent-provider and per-distinct-signal bonus
+ hard bonus    = +12 if a hard identifier matched
- conflict      = -18 per contradicting singular attribute
score           = clamp(base + corroboration + hard - conflict, 0, 100)
```

Constants live at the top of the module (`CORROBORATION_PER_PROVIDER=3.0`,
`CORROBORATION_PER_SIGNAL=2.5`, `CORROBORATION_CAP=20.0`, `HARD_MATCH_BONUS=12.0`,
`CONFLICT_PENALTY=18.0`) so the model is inspectable and tunable, and two runs
over the same evidence produce the same verdict (determinism feeds the
investigation report and the integrity ledger).

### Corroboration
Bonus for breadth: `(providers − 1) × 3.0 + (distinct signal types − 1) × 2.5`,
capped at 20. Two records from the *same* provider corroborate less than two
from independent providers.

### Conflicts
Cluster members are checked for disagreement on singular attributes
(`country`, `country_code`, `verified_email`, `birth_year`, `legal_name`,
`national_id`) and for any negative-weight `Evidence`. Each conflict costs
`CONFLICT_PENALTY` and is listed explicitly.

### Singleton clusters
A one-member cluster is always `insufficient` (0): there is no corroborating
record to correlate against.

## Discipline

Every verdict ends with: *"machine-generated correlation for authorized
investigation; treat it as a lead requiring analyst review, not a proven
identity."* The engine surfaces evidence and math — a human decides.
