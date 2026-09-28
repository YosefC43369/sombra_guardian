"""
behavioral_intelligence.visualization.timeline — event-timeline rendering
(spec §42).

Renders a ``Timeline`` (change points, bursts, gaps, migrations, profile changes)
as an inline SVG: events placed on a horizontal time axis, colour-coded by kind,
each with a hover title. Also emits the events as a JSON-able list.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from ..models.timeline import Timeline
from ._svg import open_svg, close_svg, esc, MUTED

_KIND_COLOR = {
    "activity_burst": "#cf222e", "inactivity_gap": "#6e7781",
    "platform_migration": "#8250df", "language_change": "#9a6700",
    "username_change": "#0969da", "avatar_change": "#0969da",
    "bio_change": "#0969da", "posting_frequency_change": "#1a7f37",
}


def _date(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d") \
        if epoch else "?"


def to_svg(timeline: Timeline, *, width: int = 640) -> str:
    events = timeline.sorted_events()
    if not events:
        return "<svg width='1' height='1'></svg>"
    lo = timeline.period_start or events[0].at
    hi = timeline.period_end or events[-1].at
    span = max(hi - lo, 1.0)
    height = 120
    axis_y = 70
    left, right = 20, width - 20
    parts = [open_svg(width, height, "event timeline")]
    parts.append(f"<line x1='{left}' y1='{axis_y}' x2='{right}' y2='{axis_y}' "
                 f"stroke='{MUTED}' stroke-width='1'/>")
    parts.append(f"<text x='{left}' y='{axis_y+18}' font-size='9' fill='{MUTED}'>"
                 f"{esc(_date(lo))}</text>")
    parts.append(f"<text x='{right}' y='{axis_y+18}' font-size='9' fill='{MUTED}' "
                 f"text-anchor='end'>{esc(_date(hi))}</text>")
    for i, ev in enumerate(events):
        x = left + (right - left) * (ev.at - lo) / span
        color = _KIND_COLOR.get(ev.kind, "#0969da")
        up = i % 2 == 0
        ly = axis_y - 30 if up else axis_y + 30
        parts.append(f"<line x1='{x:.1f}' y1='{axis_y}' x2='{x:.1f}' y2='{ly}' "
                     f"stroke='{color}' stroke-width='1'/>")
        parts.append(f"<circle cx='{x:.1f}' cy='{axis_y}' r='4' fill='{color}'>"
                     f"<title>{esc(_date(ev.at))}: {esc(ev.label or ev.kind)}</title>"
                     f"</circle>")
    parts.append(close_svg())
    return "".join(parts)


def to_dict(timeline: Timeline) -> Dict[str, Any]:
    return timeline.to_dict()
