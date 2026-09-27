"""entity_fusion.reports.html — a self-contained, dependency-free HTML dossier.

Builds the Markdown report and wraps it in a minimal styled HTML shell with an
embedded node-link JSON of the relationship graph, so an analyst can open a
single file. No templating engine and no external assets — the markup is
assembled with ``html.escape`` so any entity value is safe to embed."""

from __future__ import annotations

import html as _html
import json as _json
from typing import TYPE_CHECKING

from . import markdown as _md

if TYPE_CHECKING:
    from ..orchestrator import FusionResult

_STYLE = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1b1f23}
h1,h2,h3{line-height:1.2} table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;font-size:.9rem}
th{background:#f6f8fa} code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}
blockquote{border-left:4px solid #d0a215;background:#fff8e5;margin:1rem 0;
padding:.5rem 1rem;color:#57430b} .band-conclusive{color:#1a7f37;font-weight:600}
.band-strong{color:#2da44e} .band-moderate{color:#bf8700}
.band-weak,.band-insufficient{color:#cf222e}
"""


def _minimal_md_to_html(md_text: str) -> str:
    """A deliberately tiny Markdown→HTML pass covering exactly the constructs
    the markdown report emits (headings, tables, blockquotes, bold, lists).
    Not a general Markdown engine — just enough to render our own output."""
    lines = md_text.split("\n")
    out, in_table, in_list = [], False, False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>"); in_list = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("|") and i + 1 < len(lines) and set(lines[i+1].strip()) <= set("|-: "):
            close_list()
            headers = [c.strip() for c in stripped.strip("|").split("|")]
            out.append("<table><thead><tr>" +
                       "".join(f"<th>{_inline(h)}</th>" for h in headers) +
                       "</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue
        if stripped.startswith("### "):
            close_list(); out.append(f"<h3>{_inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            close_list(); out.append(f"<h2>{_inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            close_list(); out.append(f"<h1>{_inline(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            close_list(); out.append(f"<blockquote>{_inline(stripped[2:])}</blockquote>")
        elif stripped.startswith("- "):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{_inline(stripped[2:])}</li>")
        elif not stripped:
            close_list()
        else:
            close_list(); out.append(f"<p>{_inline(stripped)}</p>")
        i += 1
    close_list()
    return "\n".join(out)


def _inline(text: str) -> str:
    import re
    escaped = _html.escape(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"`(.+?)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"_(.+?)_", r"<em>\1</em>", escaped)
    return escaped


def render(result: "FusionResult", *, title: str = "Entity Fusion Dossier") -> str:
    body = _minimal_md_to_html(_md.render(result, title=title))
    graph_json = (_json.dumps(result.graph.to_node_link()) if result.graph else "{}")
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body>{body}"
        f"<h2>Graph data</h2><details><summary>Relationship graph (node-link JSON)</summary>"
        f"<pre><code>{_html.escape(_json.dumps(_json.loads(graph_json), indent=2))}</code></pre>"
        "</details></body></html>"
    )
