"""
geo_osint.reports.html_report — render a GeoReport as a standalone HTML page (spec §46).

A self-contained HTML document (inline CSS, no external assets required) with the
report sections and an embedded Leaflet map of the infrastructure GeoJSON when the
page is opened online. Safe to hand to a stakeholder or attach to a case file.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List

from .geo_report import GeoReport


def render(report: GeoReport) -> str:
    d = report.to_dict()
    s = d["sections"]
    ex = s.get("executive_summary", {})
    fc = json.dumps(s.get("infrastructure_map", {"type": "FeatureCollection", "features": []}))
    rows = _inventory_rows(s.get("geographic_inventory", []))
    evidence = _evidence_rows(s.get("evidence", []))
    limitations = "".join(f"<li>{html.escape(str(l))}</li>"
                          for l in s.get("limitations", []))
    fs = s.get("footprint_score") or {}
    center = _center(s.get("infrastructure_map", {}))
    return _TEMPLATE.format(
        entity=html.escape(d["entity"]),
        generated=html.escape(d["generated_iso"]),
        mode=html.escape(str(ex.get("run_mode", ""))),
        obs=ex.get("observation_count", 0),
        countries=html.escape(", ".join(ex.get("countries", [])) or "—"),
        cities=html.escape(", ".join(ex.get("cities", [])) or "—"),
        score=fs.get("score", "—"),
        rows=rows, evidence=evidence, limitations=limitations,
        fc=fc, lat=center[0], lon=center[1])


def write(report: GeoReport, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report))
    return path


def _inventory_rows(inv: List[Dict[str, Any]]) -> str:
    out = []
    for r in inv[:500]:
        out.append(
            "<tr><td>{t}</td><td>{c}</td><td>{cc}</td><td>{la}</td><td>{lo}</td>"
            "<td>{p}</td><td>{s}</td><td>{cf}</td></tr>".format(
                t=html.escape(str(r.get("type", ""))),
                c=html.escape(str(r.get("city") or "")),
                cc=html.escape(str(r.get("country_code") or "")),
                la=r.get("latitude") if r.get("latitude") is not None else "",
                lo=r.get("longitude") if r.get("longitude") is not None else "",
                p=r.get("precision", ""), s=html.escape(str(r.get("source", ""))),
                cf=r.get("confidence", "")))
    return "".join(out)


def _evidence_rows(ev: List[Dict[str, Any]]) -> str:
    out = []
    for e in ev[:300]:
        out.append("<li><b>{s}</b> ({c}): {claim}{lim}</li>".format(
            s=html.escape(str(e.get("source", ""))), c=e.get("confidence", ""),
            claim=html.escape(str(e.get("claim", ""))),
            lim=(" — <i>" + html.escape(str(e["limitations"])) + "</i>")
                if e.get("limitations") else ""))
    return "".join(out)


def _center(fc: Dict[str, Any]):
    feats = fc.get("features", []) if isinstance(fc, dict) else []
    pts = [f["geometry"]["coordinates"] for f in feats
           if f.get("geometry", {}).get("type") == "Point"]
    if not pts:
        return (20.0, 0.0)
    return (sum(p[1] for p in pts) / len(pts), sum(p[0] for p in pts) / len(pts))


_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Geo-OSINT Report — {entity}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
 body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;color:#1a1a1a;background:#f7f7f8}}
 header{{background:#0b3d5c;color:#fff;padding:20px 28px}}
 header h1{{margin:0 0 4px;font-size:20px}} header .meta{{opacity:.85;font-size:13px}}
 main{{max-width:1100px;margin:0 auto;padding:20px}}
 section{{background:#fff;border:1px solid #e3e3e6;border-radius:8px;padding:16px 20px;margin:16px 0}}
 h2{{font-size:16px;border-bottom:1px solid #eee;padding-bottom:6px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #f0f0f0}}
 th{{background:#fafafa}} #map{{height:420px;border-radius:6px}}
 .kpi{{display:inline-block;margin-right:24px}} .kpi b{{display:block;font-size:22px}}
 .note{{background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:10px 14px;font-size:13px}}
</style></head><body>
<header><h1>Geo-OSINT Report — {entity}</h1>
<div class="meta">Generated {generated} · mode {mode} · public sources only</div></header>
<main>
<section><h2>Executive Summary</h2>
 <div class="kpi"><b>{obs}</b>observations</div>
 <div class="kpi"><b>{score}</b>footprint score</div>
 <p><b>Countries:</b> {countries}<br><b>Cities:</b> {cities}</p></section>
<section><h2>Infrastructure Map</h2><div id="map"></div></section>
<section><h2>Geographic Inventory</h2>
 <table><thead><tr><th>Type</th><th>City</th><th>Country</th><th>Lat</th><th>Lon</th>
 <th>Prec</th><th>Source</th><th>Conf</th></tr></thead><tbody>{rows}</tbody></table></section>
<section><h2>Evidence</h2><ul>{evidence}</ul></section>
<section><h2>Limitations</h2><div class="note"><ul>{limitations}</ul></div></section>
</main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
var fc={fc};
var map=L.map('map').setView([{lat},{lon}],3);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',
  {{maxZoom:19,attribution:'&copy; OpenStreetMap contributors'}}).addTo(map);
try{{var g=L.geoJSON(fc).addTo(map);map.fitBounds(g.getBounds().pad(0.2));}}catch(e){{}}
</script></body></html>"""
