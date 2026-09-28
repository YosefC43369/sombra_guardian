"""
behavioral_intelligence.anomaly.change_detection — coordinated change detection.

Combines the statistical frequency change-point detectors (temporal.change_point)
with categorical-shift detection (dominant language / dominant domain / profile
fields) to produce a single list of change signals. Purely descriptive: each
signal says what changed and when, framed relative to the observed baseline —
never labelled malicious or intentional (spec §27 wording discipline).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Sequence

from ..models.observation import Observation
from ..models.timeline import ChangePoint, ChangeKind
from ..temporal import daily_analysis, change_point
from ..linguistic.language_switching import switches as language_switches
from ..social.account_activity import _profile_changes


def detect_changes(observations: Sequence[Observation], *,
                   zscore_threshold: float = 3.0) -> List[ChangePoint]:
    changes: List[ChangePoint] = []

    # 1. frequency change points on the dense daily series
    labels, series = daily_analysis.dense_daily_series(observations)
    if len(series) >= 4:
        ts = [datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
              for d in labels]
        changes += change_point.detect_change_points(
            [float(v) for v in series], ts, zscore_threshold=zscore_threshold)

    # 2. dominant-language shifts (each observed switch of dominant language)
    for sw in language_switches(observations):
        changes.append(ChangePoint(
            at=sw.at, kind=ChangeKind.LANGUAGE.value, method="dominant_language",
            magnitude=1.0, direction="change",
            detail=f"dominant language {sw.from_language} -> {sw.to_language}"))

    # 3. profile changes (username / avatar / bio) from metadata snapshots
    for ev in _profile_changes(sorted(observations,
                                      key=lambda o: o.timestamp if o.has_time else 0)):
        kind = ev.kind
        changes.append(ChangePoint(
            at=ev.at, kind=kind, method="profile_snapshot", magnitude=1.0,
            direction="change", detail=ev.label))

    changes.sort(key=lambda c: c.at)
    return changes
