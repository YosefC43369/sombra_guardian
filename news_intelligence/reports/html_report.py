"""
news_intelligence.reports.html_report — render a NewsReport to a standalone HTML page.

A self-contained, dependency-free HTML dashboard (inline CSS, no external assets) for
the daily/weekly briefs and profiles. Escapes all content, renders tables and a
limitations footer. Suitable for the HTML Dashboard deliverable.
"""

from __future__ import annotations

import time
from html import escape
from typing import List

from ..models.report import NewsReport, ReportSection

_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
max-width:1000px;margin:0 auto;padding:24px;color:#1b1f24;background:#fff;line-height:1.5}
h1{border-bottom:3px solid #b31b1b;padding-bottom:8px}
h2{margin-top:32px;color:#0b3d91}h3{color:#333}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #d0d7de;padding:6px 10px;text-align:left;font-size:14px}
th{background:#f6f8fa}
.meta{color:#57606a;font-size:14px}
.lim{background:#fff8e1;border-left:4px solid #f0ad4e;padding:8px 12px;margin:6px 0}
.lim.critical{background:#fde8e8;border-left-color:#b31b1b}
.src{font-size:13px;color:#57606a}
.badge{display:inline-block;background:#eef;border-radius:10px;padding:1px 8px;font-size:12px;margin-left:6px}
"""


def _fmt(ts: float) -> str:
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))
    except Exception:
        return "—"


def _table(section: ReportSection) -> str:
    if not section.rows:
        return ""
    cols = section.columns or list(section.rows[0].keys())
    head = "".join(f"<th>{escape(str(c))}</th>" for c in cols)
    body = ""
    for row in section.rows:
        body += "<tr>" + "".join(
            f"<td>{escape(str(row.get(c, '')))}</td>" for c in cols) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section(section: ReportSection, level: int) -> str:
    tag = f"h{min(level, 6)}"
    parts = [f"<{tag}>{escape(section.title)}</{tag}>"]
    if section.body:
        parts.append(f"<p>{escape(section.body)}</p>")
    if section.lines:
        parts.append("<ul>" + "".join(
            f"<li>{escape(ln)}</li>" for ln in section.lines) + "</ul>")
    if section.rows:
        parts.append(_table(section))
    if section.evidence:
        parts.append('<div class="src"><strong>Sources:</strong><ul>')
        for ev in section.evidence[:20]:
            title = escape(ev.get("title", "") or ev.get("provider", "source"))
            url = escape(ev.get("source_url", ""))
            parts.append(f'<li><a href="{url}">{title}</a></li>' if url
                         else f"<li>{title}</li>")
        parts.append("</ul></div>")
    for sub in section.subsections:
        parts.append(_section(sub, level + 1))
    return "\n".join(parts)


def render_html(report: NewsReport) -> str:
    body = [f"<h1>{escape(report.title)}</h1>"]
    meta = [f"Generated: {_fmt(report.generated_at)}"]
    if report.subject:
        meta.insert(0, f"Subject: {escape(report.subject)}")
    if report.window_start or report.window_end:
        meta.append(f"Window: {_fmt(report.window_start)} → "
                    f"{_fmt(report.window_end)}")
    body.append(f'<p class="meta">{" · ".join(meta)}</p>')
    if report.summary:
        body.append(f"<p>{escape(report.summary)}</p>")
    for section in report.sections:
        body.append(_section(section, 2))
    if report.limitations:
        body.append("<h2>Limitations &amp; Confidence Notes</h2>")
        for lim in report.limitations:
            sev = escape(lim.get("severity", "info"))
            cls = "lim critical" if sev == "critical" else "lim"
            body.append(f'<div class="{cls}">{escape(lim.get("text", ""))}</div>')
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{escape(report.title)}</title><style>{_CSS}</style></head>"
            f"<body>{''.join(body)}</body></html>")


__all__ = ["render_html"]
