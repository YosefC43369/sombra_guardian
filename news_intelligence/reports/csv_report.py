"""
news_intelligence.reports.csv_report — render a NewsReport's tables to CSV.

Flattens every tabular section of a report into CSV. When a report has one dominant
table (e.g. a top-CVEs brief) the CSV is that table; when it has several, each is
emitted under a ``# section`` banner. Uses stdlib ``csv`` for correct quoting.
"""
from __future__ import annotations
import csv
import io
from typing import List
from ..models.report import NewsReport, ReportSection


def _iter_tables(section: ReportSection, prefix: str = ""):
    title = (prefix + " / " + section.title).strip(" /")
    if section.rows:
        yield title, section.columns or list(section.rows[0].keys()), section.rows
    for sub in section.subsections:
        yield from _iter_tables(sub, title)


def render_csv(report: NewsReport) -> str:
    buf = io.StringIO()
    tables = []
    for section in report.sections:
        tables.extend(_iter_tables(section))
    if not tables:
        buf.write("no tabular data in report\n")
        return buf.getvalue()
    writer = csv.writer(buf)
    for i, (title, cols, rows) in enumerate(tables):
        if len(tables) > 1:
            if i:
                writer.writerow([])
            writer.writerow([f"# {title}"])
        writer.writerow(cols)
        for row in rows:
            writer.writerow([row.get(c, "") for c in cols])
    return buf.getvalue()


__all__ = ["render_csv"]
