# Security Posture score formula

The score is transparent and defensible — the same formula appears in the client
report footer.

## Formula

```
score = Σ(wᵢ · sᵢ · cᵢ) / Σ(wᵢ · cᵢ)          (∈ [0,1], shown ×100)
```

For each control *i*:
- `wᵢ` — weight (relative importance, from the catalog).
- `sᵢ` — sub-score in [0,1] from its status: pass/strong=1.0, partial=0.5,
  weak=0.25, fail=0.0.
- `cᵢ` — coverage: 1 if we have a signal, **0 if UNKNOWN**.

**UNKNOWN controls are excluded from BOTH numerator and denominator** — an
unmeasured control neither helps nor hurts the score; it's reported separately as a
coverage gap (`coverage = covered / applicable`).

## Properties (all tested)
- **Deterministic** — controls are processed in sorted id order; no wall-clock, no
  dict-order dependence.
- **Monotonic** — improving any control's status never lowers the score (weights are
  non-negative; `s` is monotonic in status). Property-tested over random catalogs.
- **Gated** — a **critical** control that is `fail` caps the letter grade (default
  cap: C), applied transparently and listed in `gates`. Gating changes the *grade*,
  not the numeric score.

## Grades
`A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F` — then any gate cap is applied.

## Explain & what-if
- `/posture explain` ranks the biggest **drags**: for each control, the points it
  would gain if lifted to `pass`, normalized by the covered weight, plus its
  remediation text. Unknown controls surface as coverage gaps.
- `/posture whatif <control>=<status> …` recomputes before/after and shows the
  delta and grade change — a deterministic preview, no side effects.

## Worked example
Controls: A(w=2, pass), B(w=1, partial), U(w=3, unknown).
`num = 2·1 + 1·0.5 = 2.5`; `den = 2 + 1 = 3`; `score = 2.5/3 × 100 = 83.3`.
Adding another UNKNOWN control (any weight) leaves the score unchanged.
