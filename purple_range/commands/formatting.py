"""purple_range/commands/formatting.py — plain-text rendering for /range output (mobile-friendly)."""

from __future__ import annotations

from typing import List

from ..models import Plan, TelemetryEvent, Expectation, CoverageCell
from ..constants import TACTICS_ORDERED

_COV_ICON = {"DETECTION": "🟢", "PARTIAL": "🟡", "TELEMETRY": "🔵", "NONE": "⚪"}


def plan_line(p: Plan) -> str:
    return f"{p.code}  —  {p.name}  ({len(p.steps)} steps, {p.risk_level}, {p.source})"


def plan_detail(p: Plan) -> str:
    lines = [f"📋 PLAN {p.code}", p.name, ""]
    if p.description:
        lines += [p.description, ""]
    lines.append(f"risk: {p.risk_level}   framework: {p.framework}   tactics: "
                 + (", ".join(p.tactics) or "—"))
    lines.append("steps:")
    for s in p.steps:
        exp = s.expectation
        lines.append(f"  {s.order}. {s.technique_id} [{s.tactic or '—'}] {s.name}")
        if exp.expected_telemetry:
            lines.append(f"       telemetry: {', '.join(exp.expected_telemetry)}")
        if exp.expected_rules:
            lines.append(f"       rules: {', '.join(exp.expected_rules)}")
    lines.append("")
    lines.append("→ /range instantiate " + p.code + " <engagement_id>")
    return "\n".join(lines)


def expectation_detail(technique_id: str, exp: Expectation, name: str = "") -> str:
    return "\n".join([
        f"🎯 EXPECTATION {technique_id}" + (f" — {name}" if name else ""),
        f"expected telemetry: {', '.join(exp.expected_telemetry) or '—'}",
        f"expected rules:     {', '.join(exp.expected_rules) or '—'}",
        f"data sources:       {', '.join(exp.data_sources) or '—'}",
    ])


def telemetry_sample(events: List[TelemetryEvent], limit: int = 10) -> str:
    if not events:
        return "(no telemetry generated)"
    lines = [f"🧪 SYNTHETIC TELEMETRY ({len(events)} events; source=purple_range_sim)"]
    for e in events[:limit]:
        host = e.fields.get("host", "")
        lines.append(f"  #{e.seq} {e.event_type} [{e.technique_id}] {host}")
    if len(events) > limit:
        lines.append(f"  … (+{len(events) - limit} more)")
    lines.append("Note: all values are synthetic/lab-safe. Nothing was executed.")
    return "\n".join(lines)


def coverage_report(cells: List[CoverageCell], summary: dict, limit: int = 40) -> str:
    lines = [
        "🗺 ATT&CK COVERAGE (program)",
        f"techniques: {summary['total_techniques']}   exercised: {summary['exercised']} "
        f"({summary['exercised_pct']}%)   detection: {summary['detection']} ({summary['detection_pct']}%)",
        "",
    ]
    # group by tactic in kill-chain order
    by_tactic = {}
    for c in cells:
        by_tactic.setdefault(c.tactic or "unknown", []).append(c)
    ordered = [t for t in TACTICS_ORDERED if t in by_tactic] + \
              [t for t in by_tactic if t not in TACTICS_ORDERED]
    shown = 0
    for tactic in ordered:
        lines.append(f"[{tactic}]")
        for c in by_tactic[tactic]:
            if shown >= limit:
                lines.append("  …")
                return "\n".join(lines)
            icon = _COV_ICON.get(c.best_coverage, "⚪")
            lines.append(f"  {icon} {c.technique_id} {c.technique_name}"
                         f" (x{c.exercise_count})")
            shown += 1
    return "\n".join(lines)
