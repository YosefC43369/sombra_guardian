"""
behavioral_intelligence.scoring.anomaly_score — reusable anomaly-score assembly
(spec §30).

A thin, dependency-light layer over ``models.anomaly``: combine a list of
``Deviation`` features into a banded 0–100 ``AnomalyScore``. Kept separate from
``anomaly.anomaly_engine`` so a caller with its own deviations (e.g. from a
custom feature set) can produce the same explainable, banded score without
re-running the full engine.

The score is a deviation-from-baseline measure. It is explicitly NOT a
criminality, threat or intent score — every rendering repeats that.
"""

from __future__ import annotations

from typing import Sequence

from ..models.anomaly import Deviation, AnomalyScore, anomaly_band


def score_from_deviations(deviations: Sequence[Deviation], *, entity_id: str = "",
                          baseline_window_days: int = 30,
                          observed_window_days: float = 7.0,
                          sample_size: int = 0) -> AnomalyScore:
    total = min(100.0, sum(max(0.0, d.contribution) for d in deviations))
    return AnomalyScore(
        entity_id=entity_id, score=total, band=anomaly_band(total),
        deviations=list(deviations), baseline_window_days=baseline_window_days,
        observed_window_days=observed_window_days, sample_size=sample_size)
