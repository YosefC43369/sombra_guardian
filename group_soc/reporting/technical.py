"""
group_soc/reporting/technical.py — the technical report renderer.

Adds the detection breakdown (which producers fired, analytic-state distribution) and
the current top alerts to the executive rollup. Plain text.
"""

from __future__ import annotations

from typing import Any, Dict

from .executive import format_executive


def format_technical(report: Dict[str, Any]) -> str:
    out = [format_executive(report), ""]
    det = report.get("detection", {})
    by_producer = det.get("by_producer", {})
    if by_producer:
        out.append("Detection (by producer):")
        for producer, n in list(by_producer.items())[:15]:
            out.append(f"  {n:>4}  {producer}")
    by_state = det.get("by_state", {})
    if by_state:
        out.append("")
        out.append("Signals by analytic state: "
                   + ", ".join(f"{k}={v}" for k, v in sorted(by_state.items())))
    top = report.get("top_alerts") or []
    if top:
        out.append("")
        out.append("Top open alerts:")
        for a in top[:10]:
            out.append(f"  [{a.get('priority_band')}] {a.get('title')} "
                       f"(score {a.get('priority_score')}, hits {a.get('hit_count')})")
    return "\n".join(out)
