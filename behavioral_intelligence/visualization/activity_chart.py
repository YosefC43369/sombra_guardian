"""
behavioral_intelligence.visualization.activity_chart — activity-over-time and
hour-of-day charts (spec §42).

Renders the daily activity series and the hour-of-day histogram as inline SVG bar
charts, with an optional matplotlib PNG. Data-only access returns the underlying
series so external tools can plot it themselves.
"""

from __future__ import annotations

from typing import Any, Dict, Sequence

from ..models.observation import Observation
from ..temporal import daily_analysis, hourly_analysis
from ._svg import bar_chart_svg

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_MATPLOTLIB = True
except Exception:  # pragma: no cover
    plt = None
    HAVE_MATPLOTLIB = False


def hour_histogram_svg(observations: Sequence[Observation]) -> str:
    hist = hourly_analysis.hour_histogram(observations)
    pairs = [(f"{h:02d}", hist.counts[h]) for h in range(24)]
    return bar_chart_svg(pairs, label="hour-of-day activity")


def daily_series_svg(observations: Sequence[Observation], *, last_n: int = 60) -> str:
    labels, series = daily_analysis.dense_daily_series(observations)
    pairs = list(zip(labels, series))[-last_n:]
    return bar_chart_svg(pairs, label="daily activity", width=560)


def to_png(observations: Sequence[Observation], path: str) -> str:  # pragma: no cover
    if not HAVE_MATPLOTLIB:
        return ""
    labels, series = daily_analysis.dense_daily_series(observations)
    fig, ax = plt.subplots(figsize=(9, 3))
    ax.plot(range(len(series)), series, color="#0969da")
    ax.set_title("Daily public activity")
    ax.set_xlabel("day index")
    ax.set_ylabel("observations")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def to_dict(observations: Sequence[Observation]) -> Dict[str, Any]:
    labels, series = daily_analysis.dense_daily_series(observations)
    hist = hourly_analysis.hour_histogram(observations)
    return {"daily": {"labels": labels, "values": series},
            "hour_of_day": hist.to_dict()}
