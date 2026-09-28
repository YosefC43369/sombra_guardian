"""
blueteam/posture/report.py — client-facing report renderers (pure; stdlib only).

Produces a **self-contained** HTML report: inline CSS, **self-drawn SVG** charts (no
JS, no external assets), a strict CSP meta, ``@page`` rules so a browser prints
clean PDF, and a Thai-first font stack. Also Markdown / JSON / CSV.

Security:
  * every dynamic string is HTML-escaped (XSS-safe even though there's no JS);
  * CSV fields starting with ``= + - @`` are prefixed with ``'`` (formula-injection
    guard);
  * the **client** profile pseudonymizes group ids and drops internal notes; the
    **internal** profile keeps everything.

PDF is optional: :func:`maybe_pdf` returns bytes only if a pure-python/available
engine is importable, else ``None`` (the caller degrades to HTML).
"""

from __future__ import annotations

import hashlib
import html
import io
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_GRADE_COLOR = {"A": "#1b7f4b", "B": "#4b9f2f", "C": "#c9a227", "D": "#d97706", "F": "#b91c1c"}
# only hex or a plain css color name (letters) — blocks CSS/expr injection via branding
_SAFE_COLOR = re.compile(r"^#[0-9a-fA-F]{3,8}$|^[a-zA-Z]{1,20}$")


@dataclass
class Branding:
    brand_name: str = "Sombra Guardian"
    brand_color: str = "#0b3d5c"
    footer: str = ""
    logo_text: str = "🛡️"


@dataclass
class ReportModel:
    title: str
    subject_label: str                       # group name or pseudonym
    generated_at: str                        # preformatted string (deterministic input)
    score: float
    grade: str
    coverage: float
    contributions: List[Dict[str, Any]]
    gates: List[str] = field(default_factory=list)
    top_actions: List[Dict[str, Any]] = field(default_factory=list)
    trend: List[float] = field(default_factory=list)   # recent scores oldest->newest
    categories: Dict[str, float] = field(default_factory=dict)  # category -> avg%
    profile: str = "internal"


def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def escape_csv_field(s: Any) -> str:
    text = "" if s is None else str(s)
    if text[:1] in ("=", "+", "-", "@"):
        text = "'" + text
    if any(ch in text for ch in (",", '"', "\n")):
        text = '"' + text.replace('"', '""') + '"'
    return text


# ---------------- self-drawn SVG ----------------

def _svg_gauge(score: float, grade: str) -> str:
    """A semicircular gauge, drawn with a single arc path. No JS."""
    color = _GRADE_COLOR.get(grade, "#666")
    frac = max(0.0, min(1.0, score / 100.0))
    # semicircle from 180deg to 0deg; angle swept = 180*frac
    cx, cy, r = 100, 100, 80
    ang = math.pi * (1 - frac)
    x = cx + r * math.cos(ang)
    y = cy - r * math.sin(ang)
    large = 0
    bg_path = f"M20,100 A80,80 0 0,1 180,100"
    fg_path = f"M20,100 A80,80 0 {large},1 {x:.1f},{y:.1f}"
    return (f'<svg viewBox="0 0 200 130" width="240" role="img" aria-label="score gauge">'
            f'<path d="{bg_path}" fill="none" stroke="#e5e7eb" stroke-width="16"/>'
            f'<path d="{fg_path}" fill="none" stroke="{color}" stroke-width="16" stroke-linecap="round"/>'
            f'<text x="100" y="95" text-anchor="middle" font-size="34" font-weight="700" fill="{color}">{score:.0f}</text>'
            f'<text x="100" y="120" text-anchor="middle" font-size="16" fill="#555">คะแนน / เกรด {_esc(grade)}</text>'
            f'</svg>')


def _svg_bars(categories: Dict[str, float]) -> str:
    if not categories:
        return ""
    items = sorted(categories.items())
    bar_h, gap, w = 22, 12, 260
    height = len(items) * (bar_h + gap) + 10
    parts = [f'<svg viewBox="0 0 460 {height}" width="100%" role="img" aria-label="category coverage">']
    y = 10
    for name, pct in items:
        pct = max(0.0, min(100.0, pct))
        parts.append(f'<text x="0" y="{y + 16}" font-size="13" fill="#333">{_esc(name)}</text>')
        parts.append(f'<rect x="150" y="{y}" width="{w}" height="{bar_h}" fill="#eef2f5" rx="4"/>')
        parts.append(f'<rect x="150" y="{y}" width="{w * pct / 100:.1f}" height="{bar_h}" fill="#2b7a9b" rx="4"/>')
        parts.append(f'<text x="{150 + w + 6}" y="{y + 16}" font-size="12" fill="#555">{pct:.0f}%</text>')
        y += bar_h + gap
    parts.append("</svg>")
    return "".join(parts)


def _svg_trend(trend: List[float]) -> str:
    if len(trend) < 2:
        return ""
    w, h, pad = 460, 120, 10
    n = len(trend)
    step = (w - 2 * pad) / (n - 1)
    pts = []
    for i, v in enumerate(trend):
        x = pad + i * step
        yv = h - pad - (max(0.0, min(100.0, v)) / 100.0) * (h - 2 * pad)
        pts.append(f"{x:.1f},{yv:.1f}")
    poly = " ".join(pts)
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" role="img" aria-label="score trend">'
            f'<polyline points="{poly}" fill="none" stroke="#2b7a9b" stroke-width="2.5"/>'
            f'<line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#ddd"/>'
            f'</svg>')


# ---------------- HTML ----------------

_CSS = """
:root{--brand:__BRAND__;--ink:#1f2937;--muted:#6b7280;--line:#e5e7eb;--bg:#ffffff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
 font-family:"Noto Sans Thai","Sarabun","Leelawadee UI",-apple-system,Segoe UI,Roboto,sans-serif;
 line-height:1.55;font-size:15px}
.wrap{max-width:820px;margin:0 auto;padding:24px 16px}
header{display:flex;align-items:center;gap:12px;border-bottom:3px solid var(--brand);padding-bottom:12px}
header .logo{font-size:30px}
header h1{font-size:20px;margin:0;color:var(--brand)}
header .sub{color:var(--muted);font-size:13px}
.card{border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
.grid{display:flex;flex-wrap:wrap;gap:16px;align-items:center}
.kpi{flex:1;min-width:200px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;color:#fff}
.s-pass,.s-strong{background:#1b7f4b}.s-partial{background:#c9a227}.s-weak{background:#d97706}
.s-fail{background:#b91c1c}.s-unknown{background:#9ca3af}
.gate{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:8px 12px;border-radius:8px}
footer{color:var(--muted);font-size:12px;margin-top:24px;border-top:1px solid var(--line);padding-top:10px}
@page{size:A4;margin:14mm}
@media print{.card{break-inside:avoid}header{position:running(head)}}
"""


def render_html(m: ReportModel, branding: Branding) -> str:
    # brand_color is validated to a safe token before substitution (no CSS injection)
    safe_color = branding.brand_color if _SAFE_COLOR.match(branding.brand_color or "") else "#0b3d5c"
    css = _CSS.replace("__BRAND__", safe_color)
    rows = []
    for c in m.contributions:
        status = _esc(c.get("status", "unknown"))
        crit = " ★" if c.get("critical") else ""
        rows.append(
            f"<tr><td>{_esc(c.get('name'))}{crit}</td>"
            f"<td><span class='badge s-{status}'>{status}</span></td>"
            f"<td>{_esc(c.get('weight'))}</td>"
            f"<td>{'' if c.get('sub_score') is None else _esc(round(c['sub_score'],2))}</td></tr>")
    actions = "".join(
        f"<li><strong>{_esc(a.get('name'))}</strong> — +{_esc(a.get('potential_gain'))} คะแนน"
        f"{' (สำคัญ)' if a.get('critical') else ''}<br>"
        f"<span style='color:#6b7280'>{_esc(a.get('remediation'))}</span></li>"
        for a in m.top_actions)
    gate_html = ""
    if m.gates:
        gate_html = (f"<div class='gate'>⚠️ เกรดถูกจำกัดโดยการควบคุมสำคัญที่ล้มเหลว: "
                     f"{_esc(', '.join(m.gates))}</div>")
    footer = _esc(branding.footer) or f"{_esc(branding.brand_name)} · รายงานสร้างอัตโนมัติ"
    profile_note = ("ข้อมูลถูกปกปิดเพื่อความเป็นส่วนตัว (client profile)"
                    if m.profile == "client" else "")
    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>{_esc(m.title)}</title><style>{css}</style></head>
<body><div class="wrap">
<header><div class="logo">{_esc(branding.logo_text)}</div>
<div><h1>{_esc(m.title)}</h1>
<div class="sub">{_esc(branding.brand_name)} · กลุ่ม: {_esc(m.subject_label)} · {_esc(m.generated_at)}</div></div>
</header>
<div class="card"><div class="grid">
<div style="text-align:center">{_svg_gauge(m.score, m.grade)}</div>
<div class="kpi">
<p><strong>เกรด:</strong> {_esc(m.grade)} &nbsp; <strong>คะแนน:</strong> {m.score:.1f}/100</p>
<p><strong>ความครอบคลุม (coverage):</strong> {m.coverage*100:.0f}%</p>
{gate_html}
<p style="color:#6b7280;font-size:12px">{_esc(profile_note)}</p>
</div></div></div>
{"<div class='card'><h3>แนวโน้มคะแนน</h3>" + _svg_trend(m.trend) + "</div>" if len(m.trend) >= 2 else ""}
{"<div class='card'><h3>ความครอบคลุมตามหมวด</h3>" + _svg_bars(m.categories) + "</div>" if m.categories else ""}
<div class="card"><h3>สิ่งที่ควรแก้ก่อน (ผลกระทบสูงสุด)</h3><ol>{actions or '<li>ไม่มีรายการ</li>'}</ol></div>
<div class="card"><h3>รายละเอียดการควบคุม</h3>
<table><thead><tr><th>การควบคุม</th><th>สถานะ</th><th>น้ำหนัก</th><th>คะแนนย่อย</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<footer>{footer} · สูตรคะแนน: Σ(น้ำหนัก·คะแนนย่อย·ครอบคลุม) / Σ(น้ำหนัก·ครอบคลุม) · UNKNOWN ไม่นับในตัวหาร</footer>
</div></body></html>"""


def render_markdown(m: ReportModel, branding: Branding) -> str:
    lines = [f"# {m.title}", "",
             f"**{branding.brand_name}** · กลุ่ม: {m.subject_label} · {m.generated_at}", "",
             f"- เกรด: **{m.grade}**", f"- คะแนน: **{m.score:.1f}/100**",
             f"- ความครอบคลุม: {m.coverage*100:.0f}%"]
    if m.gates:
        lines.append(f"- ⚠️ เกรดถูกจำกัดโดย: {', '.join(m.gates)}")
    lines += ["", "## สิ่งที่ควรแก้ก่อน"]
    for a in m.top_actions:
        lines.append(f"- **{a.get('name')}** (+{a.get('potential_gain')}) — {a.get('remediation')}")
    lines += ["", "## การควบคุม", "", "| การควบคุม | สถานะ | น้ำหนัก | คะแนนย่อย |",
              "|---|---|---|---|"]
    for c in m.contributions:
        ss = "" if c.get("sub_score") is None else round(c["sub_score"], 2)
        lines.append(f"| {c.get('name')} | {c.get('status')} | {c.get('weight')} | {ss} |")
    return "\n".join(lines)


def render_json(m: ReportModel) -> str:
    return json.dumps({
        "title": m.title, "subject": m.subject_label, "generated_at": m.generated_at,
        "score": round(m.score, 2), "grade": m.grade, "coverage": round(m.coverage, 4),
        "gates": m.gates, "contributions": m.contributions, "top_actions": m.top_actions,
        "categories": m.categories, "trend": m.trend, "profile": m.profile,
    }, ensure_ascii=False, sort_keys=True, indent=2)


def render_csv(m: ReportModel) -> str:
    buf = io.StringIO()
    buf.write("control,status,weight,sub_score\n")
    for c in m.contributions:
        ss = "" if c.get("sub_score") is None else round(c["sub_score"], 2)
        buf.write(",".join(escape_csv_field(x) for x in
                            (c.get("name"), c.get("status"), c.get("weight"), ss)) + "\n")
    return buf.getvalue()


def report_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def maybe_pdf(html_str: str) -> Optional[bytes]:
    """Render PDF only if an engine is importable; else None (caller keeps HTML)."""
    try:
        from weasyprint import HTML  # type: ignore
    except Exception:
        return None
    try:
        return HTML(string=html_str).write_pdf()
    except Exception:
        return None


__all__ = ["Branding", "ReportModel", "render_html", "render_markdown", "render_json",
           "render_csv", "report_sha256", "maybe_pdf", "escape_csv_field"]
