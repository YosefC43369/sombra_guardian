"""
cybersecurity_intelligence.reports.assessment_report — assessment renderers.

Markdown / JSON / Telegram renderers for an :class:`Assessment` plus the
:class:`Contradiction` objects that pertain to it. The Markdown layout follows the
CTI product template (BLUF → key assessments by register → contradictions →
knowledge gaps → sources), and analytic language is preserved verbatim from the
statements so the report never over-claims.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from ..models.assessment import Assessment, AssessmentStatement
from ..models.contradiction import Contradiction


def _ts(epoch: float) -> str:
    if not epoch:
        return "unknown"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _cite(stmt: AssessmentStatement) -> str:
    srcs = sorted({r.provider for r in stmt.evidence if r.provider})
    urls = [r.source_url for r in stmt.evidence if r.source_url]
    tail = ""
    if srcs:
        tail = f" — sources: {', '.join(srcs)}"
    if urls:
        tail += f" [{urls[0]}]"
    return tail


def render_markdown(assessment: Assessment,
                    contradictions: Optional[Sequence[Contradiction]] = None
                    ) -> str:
    a = assessment
    contradictions = list(contradictions or [])
    conf = a.overall_confidence
    lines: List[str] = []
    lines.append(f"# {a.title}")
    lines.append("")
    lines.append(f"**Subject:** `{a.subject_key}`  |  "
                 f"**Priority:** {a.priority.value.upper()}  |  "
                 f"**Products:** {', '.join(p.value for p in a.product_types) or 'n/a'}")
    if conf:
        lines.append(f"**Overall confidence:** {conf.band} ({conf.score:.2f})")
    lines.append(f"**Collection window:** {_ts(a.collection_start)} → "
                 f"{_ts(a.collection_end)}  |  **Generated:** {_ts(a.created_at)}")
    lines.append("")
    lines.append("## Bottom Line Up Front")
    lines.append(a.summary or "_No summary available._")
    lines.append("")

    def section(heading: str, items: List[AssessmentStatement]) -> None:
        lines.append(f"## {heading}")
        if not items:
            lines.append("_None._")
        else:
            for s in items:
                band = f" _(confidence: {s.confidence.band})_" if s.confidence else ""
                lines.append(f"- {s.text}{band}{_cite(s)}")
        lines.append("")

    section("Facts", a.facts)
    section("Source Claims", a.source_claims)
    section("Analytic Inferences", a.inferences)

    lines.append("## Contradictions")
    subj_contras = [c for c in contradictions if c.subject_key == a.subject_key] \
        or contradictions
    if not subj_contras:
        lines.append("_No contradictions detected among the collected sources._")
    else:
        for c in subj_contras:
            lines.append(f"- **{c.contradiction_type.value}**: {c.summary}")
            for p in c.positions:
                srcs = ", ".join(p.sources) or "unattributed"
                lines.append(f"    - `{p.value}` — {srcs}")
    lines.append("")

    lines.append("## Known Unknowns / Intelligence Gaps")
    if not a.knowledge_gaps and not a.uncertainties:
        lines.append("_No explicit gaps recorded._")
    else:
        for u in a.uncertainties:
            lines.append(f"- {u.text}")
        for g in a.knowledge_gaps:
            lines.append(f"- {g}")
    lines.append("")

    if conf and conf.limitations:
        lines.append("## Limitations")
        for lim in conf.limitations:
            lines.append(f"- _({lim.severity})_ {lim.text}")
        lines.append("")

    lines.append("## Sources")
    seen = set()
    n = 0
    for s in a.statements:
        for r in s.evidence:
            key = r.provider + "|" + r.source_url
            if key in seen:
                continue
            seen.add(key)
            n += 1
            loc = r.source_url or r.external_id or "(no locator)"
            lines.append(f"{n}. **{r.provider}** ({r.source_class.value}) — "
                         f"{r.title or 'untitled'} — {loc} — observed {_ts(r.observed_at)}")
    if n == 0:
        lines.append("_No sources recorded._")
    lines.append("")
    lines.append("---")
    lines.append("_This assessment is derived only from public reporting. "
                 "Source claims are relayed, not endorsed; contradictions are "
                 "shown unresolved; confidence reflects evidence quality, not "
                 "certainty of guilt._")
    return "\n".join(lines)


def render_json(assessment: Assessment,
                contradictions: Optional[Sequence[Contradiction]] = None,
                *, indent: int = 2) -> str:
    payload = {
        "assessment": assessment.to_dict(),
        "contradictions": [c.to_dict() for c in (contradictions or [])],
    }
    return json.dumps(payload, ensure_ascii=False, indent=indent)


def render_telegram(assessment: Assessment,
                    contradictions: Optional[Sequence[Contradiction]] = None,
                    *, max_items: int = 5) -> str:
    """Compact, Telegram-safe (plain-text) summary. Pagination/inline UI is the
    Telegram layer's job; this is the message body."""
    a = assessment
    conf = a.overall_confidence
    out: List[str] = []
    out.append(f"🛡 {a.title}")
    out.append(f"Priority: {a.priority.value.upper()}"
               + (f" | Confidence: {conf.band} ({conf.score:.2f})" if conf else ""))
    out.append("")
    out.append(a.summary or "")
    if a.facts:
        out.append("")
        out.append("Facts:")
        for s in a.facts[:max_items]:
            out.append(f"• {s.text}")
    if a.source_claims:
        out.append("")
        out.append("Source claims:")
        for s in a.source_claims[:max_items]:
            out.append(f"• {s.text}")
    subj_contras = [c for c in (contradictions or []) if c.subject_key == a.subject_key]
    if subj_contras:
        out.append("")
        out.append("⚠ Contradictions:")
        for c in subj_contras[:max_items]:
            out.append(f"• {c.summary}")
    if a.knowledge_gaps:
        out.append("")
        out.append("Gaps:")
        for g in a.knowledge_gaps[:max_items]:
            out.append(f"• {g}")
    return "\n".join(out).strip()


__all__ = ["render_markdown", "render_json", "render_telegram"]
