"""
news_intelligence.reports.markdown_report — render a NewsReport to Markdown.

Deterministic Markdown rendering of the report tree (sections, lines, tables,
subsections) plus a standing limitations block. Every table is a GitHub-flavoured
Markdown table; evidence links render as footnote-style source lines.
"""

from __future__ import annotations

import time
from typing import List

from ..models.report import NewsReport, ReportSection


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))
    except Exception:
        return "—"


def _table(section: ReportSection) -> List[str]:
    if not section.rows:
        return []
    cols = section.columns or list(section.rows[0].keys())
    out = ["| " + " | ".join(cols) + " |",
           "| " + " | ".join("---" for _ in cols) + " |"]
    for row in section.rows:
        out.append("| " + " | ".join(str(row.get(c, "")) for c in cols) + " |")
    return out


def _render_section(section: ReportSection, level: int) -> List[str]:
    out: List[str] = [f"{'#' * min(level, 6)} {section.title}"]
    if section.body:
        out.append("")
        out.append(section.body)
    if section.lines:
        out.append("")
        out.extend(f"- {ln}" for ln in section.lines)
    if section.rows:
        out.append("")
        out.extend(_table(section))
    if section.evidence:
        out.append("")
        out.append("*Sources:*")
        for ev in section.evidence[:20]:
            title = ev.get("title", "") or ev.get("provider", "source")
            url = ev.get("source_url", "")
            out.append(f"- [{title}]({url})" if url else f"- {title}")
    for sub in section.subsections:
        out.append("")
        out.extend(_render_section(sub, level + 1))
    return out


def render_markdown(report: NewsReport) -> str:
    out: List[str] = [f"# {report.title}", ""]
    meta = []
    if report.subject:
        meta.append(f"**Subject:** {report.subject}")
    meta.append(f"**Generated:** {_fmt_ts(report.generated_at)}")
    if report.window_start or report.window_end:
        meta.append(f"**Window:** {_fmt_ts(report.window_start)} → "
                    f"{_fmt_ts(report.window_end)}")
    out.append("  \n".join(meta))
    if report.summary:
        out += ["", report.summary]
    for section in report.sections:
        out.append("")
        out.extend(_render_section(section, 2))
    if report.limitations:
        out += ["", "## Limitations & Confidence Notes", ""]
        for lim in report.limitations:
            sev = lim.get("severity", "info")
            out.append(f"- _{sev}_: {lim.get('text', '')}")
    return "\n".join(out).strip() + "\n"


__all__ = ["render_markdown"]
