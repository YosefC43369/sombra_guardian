"""
geo_osint.reports.markdown_report — render a GeoReport as Markdown (spec §46).

Human-readable report with every spec section as a heading. Designed to be dropped
into an investigation write-up or a Telegram/GitHub message.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .geo_report import GeoReport


def render(report: GeoReport) -> str:
    d = report.to_dict()
    s = d["sections"]
    out: List[str] = []
    ex = s.get("executive_summary", {})
    out.append(f"# Geo-OSINT Report — {d['entity']}")
    out.append(f"_Generated {d['generated_iso']} · mode `{ex.get('run_mode','')}` · "
               f"{ex.get('observation_count',0)} observation(s) · "
               f"{ex.get('elapsed_s',0)}s_\n")

    out.append("## Executive Summary")
    out.append(f"- **Target kind:** {ex.get('kind','')}")
    pc = ex.get("primary_country")
    if pc:
        out.append(f"- **Primary country:** {pc['value']} "
                   f"(confidence {pc['confidence']:.2f})")
    out.append(f"- **Countries:** {', '.join(ex.get('countries', [])) or '—'}")
    out.append(f"- **Cities:** {', '.join(ex.get('cities', [])) or '—'}")
    fs = s.get("footprint_score") or {}
    if fs:
        out.append(f"- **Geographic-footprint score:** {fs.get('score','—')} "
                   f"(_not a risk score_)")
    out.append("")

    out.append("## Geographic Inventory")
    inv = s.get("geographic_inventory", [])
    if inv:
        out.append("| Type | Place | Country | Lat | Lon | Prec | Source | Conf |")
        out.append("|------|-------|---------|-----|-----|------|--------|------|")
        for r in inv[:100]:
            out.append(f"| {r['type']} | {r.get('city') or '—'} | "
                       f"{r.get('country_code') or '—'} | {_f(r.get('latitude'))} | "
                       f"{_f(r.get('longitude'))} | {r.get('precision')} | "
                       f"{r.get('source')} | {r.get('confidence')} |")
    else:
        out.append("_No geographic observations._")
    out.append("")

    _list_section(out, "Airport Analysis", s.get("airport_analysis", []),
                 lambda o: f"{o.get('metadata',{}).get('iata','')}/"
                           f"{o.get('metadata',{}).get('icao','')} — {o.get('city','')}")
    _list_section(out, "Cloud Regions", s.get("cloud_regions", []),
                 lambda o: f"{o.get('metadata',{}).get('provider','')}:"
                           f"{o.get('metadata',{}).get('region_code','')} — {o.get('city','')}")
    _list_section(out, "ASN / IP / Domain Geolocation", s.get("ip_asn_geolocation", []),
                 lambda o: f"{o.get('location_type')} — {o.get('country_code','')} "
                           f"{o.get('city','')} (conf {o.get('confidence')})")

    out.append("## Country Timeline")
    tl = s.get("country_timeline", [])
    if tl:
        for e in tl[:50]:
            out.append(f"- `{e.get('iso','')}` {e.get('label','')} "
                       f"({e.get('country_code','')}) — {e.get('source','')}")
    else:
        out.append("_No timeline events._")
    out.append("")

    out.append("## Facility Relationships")
    g = s.get("facility_relationships", {})
    out.append(f"- Graph: {len(g.get('nodes', []))} node(s), "
               f"{len(g.get('edges', []))} edge(s)\n")

    out.append("## Evidence")
    ev = s.get("evidence", [])
    for e in ev[:80]:
        out.append(f"- **{e['source']}** ({e['confidence']}): {e['claim']}"
                   + (f" — _{e['limitations']}_" if e.get("limitations") else ""))
    if not ev:
        out.append("_No evidence records._")
    out.append("")

    out.append("## Limitations")
    for lim in s.get("limitations", []):
        out.append(f"- {lim}")
    out.append("")
    return "\n".join(out)


def write(report: GeoReport, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report))
    return path


def _list_section(out: List[str], title: str, rows: List[Dict[str, Any]], fmt) -> None:
    out.append(f"## {title}")
    if rows:
        for r in rows[:50]:
            out.append(f"- {fmt(r)}")
    else:
        out.append("_None._")
    out.append("")


def _f(v: Any) -> str:
    return f"{v:.4f}" if isinstance(v, (int, float)) else "—"
