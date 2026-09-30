"""
group_soc/reporting/executive.py — the executive-summary renderer.

A short, non-technical rollup: volumes, open work, and the headline KPIs. Plain text,
safe to post into a chat.
"""

from __future__ import annotations

from typing import Any, Dict


def _fmt_secs(v) -> str:
    if v is None:
        return "—"
    v = float(v)
    if v < 90:
        return f"{v:.0f}s"
    if v < 5400:
        return f"{v / 60:.1f}m"
    return f"{v / 3600:.1f}h"


def format_executive(report: Dict[str, Any]) -> str:
    ov = report.get("overview", {})
    by_status = ov.get("alerts_by_status", {})
    inc = ov.get("incidents_by_status", {})
    lines = [
        f"SOMBRA SOC REPORT — {report.get('label', '')} (Executive)",
        "",
        f"Events:       {ov.get('events', 0)}",
        f"Signals:      {ov.get('signals', 0)}",
        f"Alerts open:  {ov.get('alerts_open', 0)}",
        f"Incidents:    open={sum(v for k, v in inc.items() if k not in ('resolved','closed'))} "
        f"resolved={inc.get('resolved', 0) + inc.get('closed', 0)}",
        "",
        f"Alert status: " + (", ".join(f"{k}={v}" for k, v in sorted(by_status.items())) or "none"),
        f"MTTA:         {_fmt_secs(ov.get('mtta_s'))}",
        f"MTTR:         {_fmt_secs(ov.get('mttr_s'))}",
    ]
    open_inc = report.get("open_incidents") or []
    if open_inc:
        lines.append("")
        lines.append("Open incidents:")
        for i in open_inc[:5]:
            lines.append(f"  • [{i.get('severity')}] {i.get('title')} ({i.get('classification')})")
    return "\n".join(lines)
