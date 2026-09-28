"""
behavioral_intelligence.visualization._svg — tiny inline-SVG helpers.

Shared primitives for the visualization modules so every chart renders as a
self-contained, theme-aware SVG string with no external dependency. Colours are
CSS variables with sensible fallbacks, so a chart embedded in the HTML report
inherits the report's palette and adapts to dark mode.
"""

from __future__ import annotations

import html
from typing import List, Optional, Sequence, Tuple

ACCENT = "var(--accent,#0969da)"
MUTED = "var(--muted,#6e7781)"
FG = "var(--fg,#1f2328)"
SURFACE = "var(--surface,#f6f8fa)"


def esc(s) -> str:
    return html.escape(str(s))


def open_svg(width: int, height: int, label: str = "") -> str:
    return (f"<svg viewBox='0 0 {width} {height}' width='100%' "
            f"style='max-width:{width}px' role='img' "
            f"aria-label='{esc(label)}' xmlns='http://www.w3.org/2000/svg'>")


def close_svg() -> str:
    return "</svg>"


def bar_chart_svg(pairs: Sequence[Tuple[str, float]], *, width: int = 480,
                  bar_h: int = 18, gap: int = 6, label: str = "chart",
                  unit: str = "") -> str:
    if not pairs:
        return "<svg width='1' height='1'></svg>"
    mx = max(v for _, v in pairs) or 1
    label_w = 130
    val_w = 52
    track_w = width - label_w - val_w - 8
    height = len(pairs) * (bar_h + gap) + gap
    parts = [open_svg(width, height, label)]
    y = gap
    for name, v in pairs:
        w = max(1, int(track_w * v / mx))
        parts.append(f"<text x='0' y='{y+bar_h*0.72}' font-size='11' fill='{MUTED}'>"
                     f"{esc(str(name)[:20])}</text>")
        parts.append(f"<rect x='{label_w}' y='{y}' width='{track_w}' height='{bar_h}' "
                     f"rx='3' fill='{SURFACE}'/>")
        parts.append(f"<rect x='{label_w}' y='{y}' width='{w}' height='{bar_h}' "
                     f"rx='3' fill='{ACCENT}'/>")
        parts.append(f"<text x='{label_w+track_w+6}' y='{y+bar_h*0.72}' "
                     f"font-size='11' fill='{MUTED}'>{esc(v)}{esc(unit)}</text>")
        y += bar_h + gap
    parts.append(close_svg())
    return "".join(parts)


def stacked_bar_svg(shares: List[Tuple[str, float]], *, width: int = 480,
                    height: int = 34, palette: Optional[Sequence[str]] = None,
                    label: str = "distribution") -> str:
    """A single horizontal 100% stacked bar (for a distribution)."""
    palette = palette or ["#0969da", "#1a7f37", "#9a6700", "#8250df", "#cf222e",
                          "#6e7781"]
    total = sum(v for _, v in shares) or 1.0
    parts = [open_svg(width, height, label)]
    x = 0.0
    legend = []
    for i, (name, v) in enumerate(shares):
        w = width * v / total
        color = palette[i % len(palette)]
        parts.append(f"<rect x='{x:.1f}' y='0' width='{w:.1f}' height='18' "
                     f"fill='{color}'><title>{esc(name)}: {v*100:.0f}%</title></rect>")
        legend.append((name, color, v))
        x += w
    lx = 0
    for name, color, v in legend[:6]:
        parts.append(f"<rect x='{lx}' y='24' width='9' height='9' fill='{color}'/>")
        parts.append(f"<text x='{lx+12}' y='32' font-size='10' fill='{MUTED}'>"
                     f"{esc(name)} {v*100:.0f}%</text>")
        lx += 78
    parts.append(close_svg())
    return "".join(parts)
