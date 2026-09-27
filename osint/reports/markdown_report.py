"""osint.reports.markdown_report — render an Intelligence object to Markdown.

A human-readable assessment summary: header + stats, a per-source status table,
and the merged findings grouped by record type with their corroboration count.
Pure string building, no dependencies.
"""

from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from ..orchestrator import Intelligence, MergedRecord


def render(intel: "Intelligence") -> str:
    stats = intel.stats()
    lines: List[str] = []
    lines.append(f"# OSINT report — `{intel.target}` ({intel.kind})")
    lines.append("")
    lines.append(f"- Sources run: {stats['sources_run']} "
                 f"(ok: {stats['sources_ok']})")
    lines.append(f"- Records: {stats['records_total']} raw, "
                 f"{stats['records_merged']} merged")
    lines.append(f"- Elapsed: {stats['elapsed_ms']} ms")
    lines.append("")

    # Per-source status table.
    lines.append("## Sources")
    lines.append("")
    lines.append("| Source | Status | Records | Time (ms) | Note |")
    lines.append("|---|---|---:|---:|---|")
    for r in sorted(intel.results, key=lambda x: x.source):
        note = (r.reason or "").replace("|", "\\|")[:80]
        lines.append(f"| {r.source} | {r.status.value} | {r.count} "
                     f"| {r.elapsed_ms} | {note} |")
    lines.append("")

    # Merged findings grouped by type.
    lines.append("## Findings")
    lines.append("")
    if not intel.merged:
        lines.append("_No records found._")
        return "\n".join(lines)

    by_type: Dict[str, List["MergedRecord"]] = {}
    for m in intel.merged:
        by_type.setdefault(m.type or "other", []).append(m)

    for rtype in sorted(by_type):
        items = by_type[rtype]
        lines.append(f"### {rtype} ({len(items)})")
        lines.append("")
        for m in items:
            corrob = f" _(x{m.confidence}: {', '.join(sorted(set(m.sources)))})_" \
                if m.confidence > 1 else f" _({', '.join(sorted(set(m.sources)))})_"
            lines.append(f"- `{m.value}`{corrob}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
