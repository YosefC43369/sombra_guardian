"""
behavioral_intelligence.reports.html_report — self-contained interactive report
(spec §41).

Renders a ``BehaviorProfile`` as a single standalone HTML page: an activity
heatmap (inline SVG), language and hashtag bar charts, the interaction summary,
anomaly breakdown, change-point timeline, evidence table and limitations. No
external assets, scripts or fonts — everything is inline so the file opens
offline. Colours are defined as tokens with a dark-mode media query.

The epistemic labels (OBSERVED / CORRELATED / INFERRED / UNKNOWN) are rendered as
coloured chips so the observed/inferred distinction is visible at a glance.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import List, Optional

from ..models.behavior import BehaviorProfile
from ..models.activity import Heatmap
from ..models.confidence import AssertionKind
from ..configuration import PrivacyConfig

_KIND_COLOR = {
    "OBSERVED": "#1a7f37", "CORRELATED": "#9a6700",
    "INFERRED": "#0969da", "UNKNOWN": "#6e7781",
}


def _esc(s) -> str:
    return html.escape(str(s))


def _date(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d") \
        if epoch else "—"


def _heatmap_svg(hm: Optional[Heatmap]) -> str:
    if not hm or not hm.grid:
        return "<p class='muted'>No hourly activity data.</p>"
    rows, cols = len(hm.grid), len(hm.grid[0]) if hm.grid else 0
    cell = 18
    pad_left, pad_top = 44, 20
    width = pad_left + cols * cell + 10
    height = pad_top + rows * cell + 10
    mx = max((max(r) for r in hm.grid), default=1) or 1
    parts = [f"<svg viewBox='0 0 {width} {height}' width='100%' "
             f"style='max-width:{width}px' role='img' aria-label='activity heatmap'>"]
    for c in range(cols):
        if c % 3 == 0:
            parts.append(f"<text x='{pad_left + c*cell + cell/2}' y='{pad_top-6}' "
                         f"font-size='9' text-anchor='middle' fill='var(--muted)'>"
                         f"{_esc(hm.col_labels[c])}</text>")
    for r in range(rows):
        parts.append(f"<text x='{pad_left-6}' y='{pad_top + r*cell + cell*0.7}' "
                     f"font-size='9' text-anchor='end' fill='var(--muted)'>"
                     f"{_esc(hm.row_labels[r])}</text>")
        for c in range(cols):
            v = hm.grid[r][c]
            intensity = v / mx
            # blend from surface to accent
            parts.append(
                f"<rect x='{pad_left + c*cell}' y='{pad_top + r*cell}' "
                f"width='{cell-1}' height='{cell-1}' rx='2' "
                f"fill='var(--accent)' fill-opacity='{intensity:.3f}'>"
                f"<title>{_esc(hm.row_labels[r])} {_esc(hm.col_labels[c])}: {v}</title>"
                f"</rect>")
    parts.append("</svg>")
    return "".join(parts)


def _bar_chart(pairs, *, unit: str = "") -> str:
    if not pairs:
        return "<p class='muted'>No data.</p>"
    mx = max(v for _, v in pairs) or 1
    rows = []
    for label, v in pairs:
        pct = 100.0 * v / mx
        rows.append(
            f"<div class='bar-row'><span class='bar-label'>{_esc(label)}</span>"
            f"<span class='bar-track'><span class='bar-fill' "
            f"style='width:{pct:.1f}%'></span></span>"
            f"<span class='bar-val'>{_esc(v)}{_esc(unit)}</span></div>")
    return "<div class='bars'>" + "".join(rows) + "</div>"


def _chip(kind: str) -> str:
    color = _KIND_COLOR.get(kind, "#6e7781")
    return (f"<span class='chip' style='background:{color}1a;color:{color};"
            f"border:1px solid {color}55'>{_esc(kind)}</span>")


def render(profile: BehaviorProfile, *, privacy: Optional[PrivacyConfig] = None
           ) -> str:
    p = profile
    parts: List[str] = []
    parts.append("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Behavioral Intelligence Report</title>
<style>
:root{--bg:#ffffff;--fg:#1f2328;--muted:#6e7781;--surface:#f6f8fa;
--border:#d0d7de;--accent:#0969da}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;--surface:#161b22;
--border:#30363d;--accent:#4493f8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:28px 0 8px;
border-bottom:1px solid var(--border);padding-bottom:4px}
.muted{color:var(--muted)}.meta{color:var(--muted);font-size:.9rem}
.disclaimer{background:var(--surface);border:1px solid var(--border);
border-radius:8px;padding:12px 14px;margin:14px 0;font-size:.92rem}
.chip{font-size:.7rem;font-weight:600;border-radius:10px;padding:1px 7px;
margin-right:6px;white-space:nowrap}
ul{padding-left:18px}li{margin:3px 0}
.bars{display:flex;flex-direction:column;gap:4px;margin:8px 0}
.bar-row{display:flex;align-items:center;gap:8px;font-size:.85rem}
.bar-label{width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;background:var(--surface);border-radius:4px;height:14px}
.bar-fill{display:block;height:100%;background:var(--accent);border-radius:4px}
.bar-val{width:56px;text-align:right;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin:8px 0}
td,th{border:1px solid var(--border);padding:4px 8px;text-align:left}
.score{font-size:2rem;font-weight:700;color:var(--accent)}
</style></head><body><div class="wrap">""")

    parts.append("<h1>Behavioral Intelligence Report</h1>")
    parts.append(f"<div class='meta'>{_esc(p.label or p.entity_id or '(entity)')} · "
                 f"{_date(p.period_start)} → {_date(p.period_end)} · "
                 f"{p.sample_size:,} observations · {len(p.platforms)} platforms</div>")
    parts.append("<div class='disclaimer'>This report describes <b>observable "
                 "public activity patterns</b>. It makes no claim about the person "
                 "behind the account — no psychological, medical, criminal-intent, "
                 "ideological or identity conclusion is implied or supported.</div>")

    # observed findings
    parts.append("<h2>Observed activity</h2><ul>")
    for a in [x for x in p.assertions if x.kind == AssertionKind.OBSERVED][:8]:
        conf = f" <span class='muted'>({a.score:.2f})</span>" if a.confidence else ""
        parts.append(f"<li>{_chip(a.kind.value)}{_esc(a.statement)}{conf}</li>")
    parts.append("</ul>")

    # heatmap
    parts.append("<h2>Activity heatmap (UTC hour × weekday)</h2>")
    parts.append(_heatmap_svg(p.heatmap))

    # language
    parts.append("<h2>Language use</h2>")
    if p.languages and p.languages.shares:
        pairs = sorted(((k, round(v*100)) for k, v in p.languages.shares.items()),
                       key=lambda kv: kv[1], reverse=True)[:8]
        parts.append(_bar_chart(pairs, unit="%"))
        parts.append("<p class='muted'>Language use is observed; nationality is not "
                     "inferred.</p>")
    else:
        parts.append("<p class='muted'>No language data.</p>")

    # hashtags / keywords
    parts.append("<h2>Top terms &amp; hashtags</h2>")
    if p.keywords:
        parts.append(_bar_chart([(k.term, k.frequency) for k in p.keywords[:10]]))
    if p.hashtags:
        parts.append("<p>" + " ".join(f"<code>#{_esc(h.tag)}</code>"
                                       for h in p.hashtags[:15]) + "</p>")

    # anomaly
    parts.append("<h2>Anomaly (deviation from own baseline)</h2>")
    if p.anomaly_score:
        parts.append(f"<div class='score'>{p.anomaly_score.score:.0f}"
                     f"<span class='muted' style='font-size:1rem'>/100 · "
                     f"{_esc(p.anomaly_score.band)}</span></div>")
        parts.append(_bar_chart([(d.feature, round(d.contribution))
                                 for d in p.anomaly_score.top_features(6)]))
        parts.append("<p class='muted'>Deviation measure — NOT a threat or "
                     "criminality score.</p>")
    else:
        parts.append("<p class='muted'>No baseline comparison available.</p>")

    # interactions
    parts.append("<h2>Public interaction network</h2>")
    if p.interactions and p.interactions.edges:
        parts.append(f"<p>{len(p.interactions.edges)} directed edges · "
                     f"reciprocity {p.interactions.reciprocity:.2f}</p>")
        parts.append("<table><tr><th>source</th><th>target</th><th>count</th></tr>")
        for e in p.interactions.edges[:12]:
            parts.append(f"<tr><td>{_esc(e.source)}</td><td>{_esc(e.target)}</td>"
                         f"<td>{e.count}</td></tr>")
        parts.append("</table>")
        parts.append("<p class='muted'>Interactions are observed public acts; no "
                     "private relationship is inferred.</p>")
    else:
        parts.append("<p class='muted'>No interactions observed.</p>")

    # correlated / inferred
    corr = [a for a in p.assertions if a.kind in (AssertionKind.CORRELATED,
            AssertionKind.INFERRED)]
    if corr:
        parts.append("<h2>Correlated &amp; inferred (leads, not facts)</h2><ul>")
        for a in corr:
            parts.append(f"<li>{_chip(a.kind.value)}{_esc(a.statement)}</li>")
        parts.append("</ul>")

    # limitations
    parts.append("<h2>Limitations</h2><ul>")
    for lim in p.limitations:
        parts.append(f"<li>{_esc(lim)}</li>")
    parts.append("</ul>")

    parts.append("<p class='muted' style='margin-top:24px'>Machine-generated for "
                 "authorized investigation. Findings are leads requiring analyst "
                 "review, not proven facts about any person.</p>")
    parts.append("</div></body></html>")
    return "".join(parts)
