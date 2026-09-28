"""
news_intelligence.models.report — the intelligence report/brief output object.

A ``NewsReport`` is a rendered-agnostic intelligence product (daily brief, weekly
brief, actor/campaign/CVE/malware profile, executive summary). It is a tree of
``ReportSection`` objects, each carrying ``Assertion``-style lines, tables and the
evidence backing them. The ``reports`` package renders it to Markdown/HTML/JSON/CSV
without re-computing anything — a report is a *view* over stored, evidenced facts,
so every number in it traces back to a citation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ReportSection:
    title: str
    body: str = ""
    lines: List[str] = field(default_factory=list)
    rows: List[Dict[str, Any]] = field(default_factory=list)   # tabular data
    columns: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    subsections: List["ReportSection"] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    def add_line(self, text: str) -> "ReportSection":
        if text:
            self.lines.append(text)
        return self

    def add_row(self, row: Dict[str, Any]) -> "ReportSection":
        self.rows.append(row)
        for k in row:
            if k not in self.columns:
                self.columns.append(k)
        return self

    def add_subsection(self, section: "ReportSection") -> "ReportSection":
        self.subsections.append(section)
        return section

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title, "body": self.body, "lines": list(self.lines),
            "rows": list(self.rows), "columns": list(self.columns),
            "evidence": list(self.evidence),
            "subsections": [s.to_dict() for s in self.subsections],
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReportSection":
        return cls(
            title=str(d.get("title", "")), body=str(d.get("body", "")),
            lines=list(d.get("lines", []) or []),
            rows=list(d.get("rows", []) or []),
            columns=list(d.get("columns", []) or []),
            evidence=list(d.get("evidence", []) or []),
            subsections=[cls.from_dict(s) for s in d.get("subsections", []) or []],
            detail=dict(d.get("detail", {}) or {}),
        )


@dataclass
class NewsReport:
    title: str
    report_type: str = "brief"          # daily|weekly|actor|campaign|cve|malware|executive
    subject: str = ""                   # actor/campaign/cve name for profiles
    generated_at: float = field(default_factory=time.time)
    window_start: float = 0.0
    window_end: float = 0.0
    sections: List[ReportSection] = field(default_factory=list)
    limitations: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    report_id: str = ""

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = f"nr-{self.report_type}-{int(self.generated_at)}"

    def add_section(self, section: ReportSection) -> ReportSection:
        self.sections.append(section)
        return section

    def section(self, title: str) -> ReportSection:
        for s in self.sections:
            if s.title == title:
                return s
        s = ReportSection(title=title)
        self.sections.append(s)
        return s

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id, "title": self.title,
            "report_type": self.report_type, "subject": self.subject,
            "generated_at": self.generated_at, "window_start": self.window_start,
            "window_end": self.window_end, "summary": self.summary,
            "sections": [s.to_dict() for s in self.sections],
            "limitations": list(self.limitations), "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NewsReport":
        r = cls(
            title=str(d.get("title", "")),
            report_type=str(d.get("report_type", "brief")),
            subject=str(d.get("subject", "")),
            generated_at=float(d.get("generated_at", time.time()) or time.time()),
            window_start=float(d.get("window_start", 0.0) or 0.0),
            window_end=float(d.get("window_end", 0.0) or 0.0),
            summary=str(d.get("summary", "")),
            limitations=list(d.get("limitations", []) or []),
            detail=dict(d.get("detail", {}) or {}),
            report_id=str(d.get("report_id", "")),
        )
        r.sections = [ReportSection.from_dict(s) for s in d.get("sections", []) or []]
        return r


__all__ = ["ReportSection", "NewsReport"]
