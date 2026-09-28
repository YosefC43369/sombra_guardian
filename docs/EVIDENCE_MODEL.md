# Evidence & Confidence Model

Module: `behavioral_intelligence/models/confidence.py` (§31–33, §51). This is the
mechanism that keeps observation and inference separate — in code and in every
report.

## Assertion — the atom of every report

Nothing in the package emits a bare claim. Every analytical output is an
`Assertion`:

```python
Assertion(
    statement="Public activity was concentrated 19:00–23:00 UTC …",
    kind=AssertionKind.OBSERVED,     # OBSERVED | CORRELATED | INFERRED | UNKNOWN
    confidence=ConfidenceModel(...), # score + reasons
    evidence=[EvidenceRef(...)],     # provenance
    observation_period=(start, end),
    tags=[...], detail={...})
```

### AssertionKind (§51)

| kind | meaning |
|------|---------|
| `OBSERVED` | directly present in the collected public data |
| `CORRELATED` | two observed facts co-occur; **no cause asserted** |
| `INFERRED` | an interpretation drawn from observed facts |
| `UNKNOWN` | the available public data cannot establish it |

Reports render the kind as a prefix, so a reader can never mistake a correlation
for a conclusion.

## ConfidenceModel (§33)

A 0–1 score computed deterministically from four bounded factors — **sample
size**, **observation period**, **independent source count**, and **supporting
signals** — minus a penalty per **contradicting signal**. The result always
carries the factor breakdown, the supporting/contradicting signal lists, and
`Limitation` lines. Two standing limitations are appended to *every* model:

1. *"Reflects only publicly observed data; absence of a signal is not evidence of
   its absence in reality."*
2. *"Describes observable activity patterns, not the person behind the account;
   no psychological, medical or intent conclusion is implied."*

A sample below the pattern minimum adds an "indicative only" caution.

## EvidenceRef (§31)

Links a claim back to the public data it rests on: `provider`, `source_url`,
`observation_id`, `content_hash`, event `timestamp`, `collected_at`, and the
source's self-reported `confidence`. Provenance is never discarded.

## SourceReliability (§32)

Sources are **not** silently treated as equally reliable. An explainable weight in
[0,1] blends the source type (direct/feed/archive/aggregator/derived), freshness
decay, corroboration count and historical consistency — and returns the factor
breakdown, never a bare number.
