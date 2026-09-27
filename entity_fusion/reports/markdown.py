"""entity_fusion.reports.markdown — render a FusionResult as an analyst-readable
dossier in Markdown.

Sections follow the report spec: Identity Summary, Confidence Matrix, Aliases,
values by type (Accounts/Domains/Emails/…), Timeline hooks, and an Evidence
Appendix. Deterministic ordering so the same run yields the same document."""

from __future__ import annotations

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..orchestrator import FusionResult
    from ..identity import Identity


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _identity_section(idx: int, ident: "Identity") -> List[str]:
    out = [f"### {idx}. {_md_escape(ident.label)}  ",
           f"- **Type:** {ident.primary_type.value}  ",
           f"- **Confidence:** {ident.band} ({ident.score:.0f}/100)  ",
           f"- **Records fused:** {len(ident.member_ids)}  ",
           f"- **Providers:** {', '.join(ident.providers) or '—'}  "]
    if ident.aliases:
        out.append(f"- **Aliases:** {', '.join(_md_escape(a) for a in ident.aliases)}  ")

    if ident.values_by_type:
        out.append("\n**Values by type**\n")
        out.append("| Type | Values |")
        out.append("| --- | --- |")
        for t in sorted(ident.values_by_type):
            vals = ", ".join(_md_escape(v) for v in ident.values_by_type[t])
            out.append(f"| {t} | {vals} |")

    if ident.confidence:
        c = ident.confidence
        out.append("\n**Confidence breakdown**\n")
        out.append("| Factor | Kind | Detail | Weight |")
        out.append("| --- | --- | --- | ---: |")
        for f in c.positives + c.negatives:
            out.append(f"| {_md_escape(f.label)} | {f.kind} | "
                       f"{_md_escape(f.value)} | {f.weight:+.1f} |")
        if c.conflicts:
            out.append("\n> **Conflicts:** " + "; ".join(_md_escape(x) for x in c.conflicts))
        out.append(f"\n_{_md_escape(c.human_explanation)}_")
    return out


def render(result: "FusionResult", *, title: str = "Entity Fusion Dossier") -> str:
    stats = result.stats()
    lines = [f"# {title}", "",
             "> Machine-generated correlation for **authorized investigation**. "
             "Each identity is a lead requiring analyst review, not a proven fact.",
             "", "## Identity Summary", "",
             f"- Input records: **{stats['input_records']}**",
             f"- Authorized & correlated: **{stats['authorized']}**",
             f"- Excluded by scope gate: **{stats['denied']}**",
             f"- Identities resolved: **{stats['identities']}** "
             f"({stats['multi_record_identities']} multi-record)",
             f"- Elapsed: {stats['elapsed_ms']} ms", ""]

    lines += ["## Confidence Matrix", "",
              "| # | Identity | Type | Band | Score | Records |",
              "| ---: | --- | --- | --- | ---: | ---: |"]
    for i, ident in enumerate(result.identities, 1):
        lines.append(f"| {i} | {_md_escape(ident.label)} | {ident.primary_type.value} "
                     f"| {ident.band} | {ident.score:.0f} | {len(ident.member_ids)} |")
    lines.append("")

    lines += ["## Identities", ""]
    for i, ident in enumerate(result.identities, 1):
        lines += _identity_section(i, ident)
        lines.append("")

    if result.denied:
        lines += ["## Excluded by Scope Gate", "",
                  "| Type | Value | Reason |", "| --- | --- | --- |"]
        for d in result.denied:
            lines.append(f"| {d.entity_type} | {_md_escape(d.value)} "
                         f"| {d.reason} |")
        lines.append("")

    if result.graph:
        gs = result.graph.stats()
        lines += ["## Relationship Graph", "",
                  f"- Backend: `{gs['backend']}`",
                  f"- Nodes: {gs['nodes']}, Edges: {gs['edges']}",
                  "- Export via `result.graph.to_dot()` / `to_graphml()` / "
                  "`to_gexf()` / `to_json()`.", ""]
    return "\n".join(lines)
