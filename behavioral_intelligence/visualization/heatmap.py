"""
behavioral_intelligence.visualization.heatmap — activity heatmap rendering
(spec §42).

Renders a ``Heatmap`` model as an inline SVG (always, stdlib) and, when
``matplotlib`` is present, as a PNG. Also exposes the raw grid as a JSON-able dict
for external renderers. All values are UTC unless a display timezone offset was
applied when the heatmap was built (recorded on the model).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..models.activity import Heatmap
from ._svg import open_svg, close_svg, esc, ACCENT, MUTED

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_MATPLOTLIB = True
except Exception:  # pragma: no cover
    plt = None
    HAVE_MATPLOTLIB = False


def to_svg(hm: Heatmap, *, cell: int = 18) -> str:
    if not hm or not hm.grid:
        return "<svg width='1' height='1'></svg>"
    rows, cols = len(hm.grid), len(hm.grid[0])
    pad_left, pad_top = 46, 22
    width = pad_left + cols * cell + 12
    height = pad_top + rows * cell + 12
    mx = max((max(r) for r in hm.grid), default=1) or 1
    parts = [open_svg(width, height, f"{hm.row_dimension} × {hm.col_dimension}")]
    for c in range(cols):
        if c % max(1, cols // 12) == 0:
            parts.append(f"<text x='{pad_left+c*cell+cell/2}' y='{pad_top-6}' "
                         f"font-size='9' text-anchor='middle' fill='{MUTED}'>"
                         f"{esc(hm.col_labels[c])}</text>")
    for r in range(rows):
        parts.append(f"<text x='{pad_left-6}' y='{pad_top+r*cell+cell*0.7}' "
                     f"font-size='9' text-anchor='end' fill='{MUTED}'>"
                     f"{esc(hm.row_labels[r])}</text>")
        for c in range(cols):
            v = hm.grid[r][c]
            parts.append(
                f"<rect x='{pad_left+c*cell}' y='{pad_top+r*cell}' "
                f"width='{cell-1}' height='{cell-1}' rx='2' fill='{ACCENT}' "
                f"fill-opacity='{v/mx:.3f}'><title>{esc(hm.row_labels[r])} "
                f"{esc(hm.col_labels[c])}: {v}</title></rect>")
    parts.append(close_svg())
    return "".join(parts)


def to_png(hm: Heatmap, path: str) -> Optional[str]:  # pragma: no cover - needs mpl
    if not HAVE_MATPLOTLIB or not hm.grid:
        return None
    fig, ax = plt.subplots(figsize=(max(6, len(hm.col_labels) * 0.35),
                                    max(3, len(hm.row_labels) * 0.35)))
    ax.imshow(hm.grid, aspect="auto", cmap="viridis")
    ax.set_xticks(range(len(hm.col_labels)))
    ax.set_xticklabels(hm.col_labels, rotation=90, fontsize=6)
    ax.set_yticks(range(len(hm.row_labels)))
    ax.set_yticklabels(hm.row_labels, fontsize=7)
    ax.set_title(f"{hm.row_dimension} × {hm.col_dimension} (UTC)")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def to_dict(hm: Heatmap) -> Dict[str, Any]:
    return hm.to_dict()
