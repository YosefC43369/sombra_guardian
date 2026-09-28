"""
behavioral_intelligence.visualization.language_chart — language distribution and
language-over-time charts (spec §42).

A 100%-stacked bar for the overall language mix and a small multiples view of the
per-period language timeline. Descriptive of language *use* only.
"""

from __future__ import annotations

from typing import Any, Dict, Sequence

from ..models.language import LanguageDistribution, LanguageTimelinePoint
from ._svg import stacked_bar_svg, open_svg, close_svg, esc, MUTED


def distribution_svg(dist: LanguageDistribution) -> str:
    shares = sorted(dist.shares.items(), key=lambda kv: kv[1], reverse=True)
    return stacked_bar_svg(shares, label="language distribution")


def timeline_svg(points: Sequence[LanguageTimelinePoint], *, width: int = 560) -> str:
    if not points:
        return "<svg width='1' height='1'></svg>"
    row_h = 26
    height = len(points) * row_h + 10
    palette = ["#0969da", "#1a7f37", "#9a6700", "#8250df", "#cf222e", "#6e7781"]
    langs = sorted({lang for p in points for lang in p.distribution})
    color = {lang: palette[i % len(palette)] for i, lang in enumerate(langs)}
    parts = [open_svg(width, height, "language over time")]
    label_w = 70
    bar_w = width - label_w - 6
    for i, p in enumerate(points):
        y = i * row_h + 6
        parts.append(f"<text x='0' y='{y+13}' font-size='10' fill='{MUTED}'>"
                     f"{esc(p.period_label)}</text>")
        x = float(label_w)
        total = sum(p.distribution.values()) or 1.0
        for lang, share in sorted(p.distribution.items(), key=lambda kv: -kv[1]):
            w = bar_w * share / total
            parts.append(f"<rect x='{x:.1f}' y='{y}' width='{w:.1f}' height='16' "
                         f"fill='{color.get(lang,'#6e7781')}'>"
                         f"<title>{esc(lang)} {share*100:.0f}%</title></rect>")
            x += w
    parts.append(close_svg())
    return "".join(parts)


def to_dict(dist: LanguageDistribution,
            timeline: Sequence[LanguageTimelinePoint]) -> Dict[str, Any]:
    return {"distribution": dist.to_dict(),
            "timeline": [p.to_dict() for p in timeline]}
