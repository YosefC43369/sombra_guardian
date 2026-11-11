# -*- coding: utf-8 -*-
"""attack_surface_correlation/report.py — เรนเดอร์รายงาน correlation (pure)

concise (บรรทัดสรุปในแชต) · detailed markdown · json · txt · graph export
reuse รูปแบบเดียวกับ red_team_orchestrator/report.py (ไม่สร้างตัวเรนเดอร์คนละแนว)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

_OWN = {"confirmed": "✅", "observed": "≈", "observed_shared_infra": "🔗"}


def summary_line(result: Dict[str, Any]) -> str:
    if result.get("error"):
        return f"❌ {result['error']}"
    c = result.get("counts", {})
    return (f"🕸 {result.get('target') or '(dataset)'}: assets {c.get('total_assets',0)} · "
            f"relationships {c.get('total_relationships',0)} "
            f"(ยืนยัน {c.get('confirmed_relationships',0)}/สมมติฐาน {c.get('hypothesis_relationships',0)}) · "
            f"insights {c.get('total_insights',0)}")


def concise_report(result: Dict[str, Any]) -> str:
    """รายงานสั้นสำหรับส่งเข้าแชต (ตามสเปคหัวข้อ 12)"""
    if result.get("error"):
        return f"❌ Attack Surface Correlation: {result['error']}"
    c = result.get("counts", {})
    L = [f"🕸 *Attack Surface Correlation* — `{result.get('result_id','(preview)')}`",
         f"target: {result.get('target') or '(dataset)'} · "
         f"modules: {', '.join(result.get('source_modules', [])) or '—'}",
         f"unique assets: {c.get('total_assets',0)} "
         f"({_fmt_counts(c.get('assets_by_type', {}))})",
         f"relationships: {c.get('total_relationships',0)} "
         f"— ยืนยัน {c.get('confirmed_relationships',0)} / สมมติฐาน {c.get('hypothesis_relationships',0)}",
         f"correlated findings: "
         f"{c.get('assets_by_type', {}).get('finding', 0)}"]

    shared = [r for r in result.get("correlations", [])
              if r["relationship"] == "shared_infrastructure"]
    if shared:
        L.append(f"⚠️ โครงสร้างพื้นฐานร่วม (สังเกต ไม่ใช่เจ้าของเดียวกัน): {len(shared)} รายการ")

    hi = [i for i in result.get("insights", [])
          if float(i.get("confidence", 0)) >= 0.75 and not i.get("hypothesis")]
    if hi:
        L.append("\n*insight ความเชื่อมั่นสูง:*")
        for i in hi[:5]:
            L.append(f"• {i['title']}")

    roots = [i for i in result.get("insights", [])
             if i.get("category") == "shared_root_cause"]
    if roots:
        L.append("\n*อาจมีสาเหตุร่วม (สมมติฐาน):*")
        for i in roots[:3]:
            L.append(f"• {i['title']}")

    h = result.get("history") or {}
    if h and not h.get("baseline") and not h.get("error"):
        L.append(f"\n*เทียบประวัติ:* asset ใหม่ {len(h.get('new_assets', []))} · "
                 f"ไม่พบรอบนี้ {len(h.get('not_observed_now', []))} · "
                 f"finding ใหม่ {len(h.get('new_findings', []))} · "
                 f"IP เปลี่ยน {len(h.get('changed_ip_associations', []))}")

    if result.get("ai_summary"):
        L.append(f"\n🧠 AI: {result['ai_summary'][:500]}")
    return "\n".join(L)


def _fmt_counts(d: Dict[str, int]) -> str:
    return ", ".join(f"{k}:{v}" for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:6]) or "—"


def render_markdown(result: Dict[str, Any]) -> str:
    if result.get("error"):
        return f"# Attack Surface Correlation\n\n❌ {result['error']}"
    c = result.get("counts", {})
    L = [f"# Attack Surface Correlation Report — {result.get('result_id','(preview)')}",
         f"- target: {result.get('target') or '(dataset)'}",
         f"- generated: {result.get('generated_iso')} · source task: {result.get('source_task_id')}",
         f"- source modules: {', '.join(result.get('source_modules', [])) or '—'}",
         f"- policy: confidence≥{result.get('policy',{}).get('confidence_threshold')} · "
         f"max_assets={result.get('policy',{}).get('max_assets')}",
         ""]

    L.append("## Summary")
    L.append(f"- unique assets: {c.get('total_assets',0)} — {_fmt_counts(c.get('assets_by_type', {}))}")
    L.append(f"- relationships: {c.get('total_relationships',0)} "
             f"(confirmed {c.get('confirmed_relationships',0)} / hypothesis {c.get('hypothesis_relationships',0)})")
    L.append(f"- insights: {c.get('total_insights',0)} "
             f"(high-confidence {c.get('high_confidence_insights',0)})")
    if c.get("assets_dropped_over_limit"):
        L.append(f"- ⚠️ assets dropped over max_assets limit: {c['assets_dropped_over_limit']}")

    if result.get("ai_summary"):
        L.append(f"\n## AI analysis\n{result['ai_summary']}")

    L.append("\n## Assets")
    for a in result.get("assets", [])[:200]:
        extra = ""
        if a.get("ip_addresses"):
            extra += f" · ips: {', '.join(a['ip_addresses'][:4])}"
        if a.get("technologies"):
            extra += f" · tech: {', '.join(a['technologies'][:4])}"
        L.append(f"- `{a['asset_id']}` **{a['asset_type']}** {a['value']} "
                 f"(conf {a.get('confidence')}, src {', '.join(a.get('source_modules', []))}){extra}")

    L.append("\n## Relationships")
    if not result.get("correlations"):
        L.append("_ไม่พบความสัมพันธ์ที่ผ่านเกณฑ์ความเชื่อมั่น_")
    for r in result.get("correlations", [])[:300]:
        mark = _OWN.get(r.get("ownership"), "•")
        tag = " [สมมติฐาน]" if r.get("hypothesis") else ""
        L.append(f"- {mark} `{r['correlation_id']}` **{r['relationship']}**{tag} "
                 f"{r['source']} → {r['target']} (conf {r['confidence']}, {r['ownership']})")
        L.append(f"  - {r['explanation']}")
        if r.get("evidence"):
            L.append(f"  - evidence: {'; '.join(str(e) for e in r['evidence'][:3])}")

    L.append("\n## Insights")
    if not result.get("insights"):
        L.append("_ไม่มี insight_")
    for i in result.get("insights", []):
        tag = "สมมติฐาน" if i.get("hypothesis") else "สังเกตยืนยัน"
        L.append(f"\n### [{tag}] {i['title']}  (conf {i.get('confidence')})")
        L.append(f"- {i['description']}")
        if i.get("potential_impact"):
            L.append(f"- potential impact: {i['potential_impact']}")
        if i.get("recommended_next_step"):
            L.append(f"- next step: {i['recommended_next_step']}")
        if i.get("related_assets"):
            L.append(f"- related assets: {', '.join(i['related_assets'][:10])}")

    h = result.get("history") or {}
    L.append("\n## Historical comparison")
    if h.get("baseline"):
        L.append(f"- {h.get('note')}")
    elif h.get("error"):
        L.append(f"- (เทียบประวัติล้มเหลว: {h['error']})")
    elif h:
        L.append(f"- new assets: {len(h.get('new_assets', []))} — {', '.join(h.get('new_assets', [])[:8])}")
        L.append(f"- not observed now: {len(h.get('not_observed_now', []))} — "
                 f"{', '.join(h.get('not_observed_now', [])[:8])}")
        L.append(f"- new relationships: {len(h.get('new_relationships', []))}")
        L.append(f"- new findings: {len(h.get('new_findings', []))}")
        L.append(f"- resolved/unobserved findings: {len(h.get('resolved_or_unobserved_findings', []))}")
        for ch in h.get("changed_ip_associations", [])[:8]:
            L.append(f"- IP change: {ch['host']} {ch['was']} → {ch['now']}")
        L.append(f"- _{h.get('note','')}_")

    g = result.get("graph", {}).get("stats", {})
    L.append("\n## Graph")
    L.append(f"- nodes: {g.get('node_count',0)} · edges: {g.get('edge_count',0)} "
             f"(confirmed {g.get('confirmed_edges',0)} / hypothesis {g.get('hypothesis_edges',0)})")

    L.append("\n## Limitations")
    L.append("- passive data-processing เท่านั้น — ไม่สแกน/ไม่ส่ง payload/ไม่ยืนยันการโจมตี")
    L.append("- IP/CDN/โครงสร้าง/เทคโนโลยีร่วม = การสังเกต ไม่ใช่หลักฐานความเป็นเจ้าของ")
    L.append("- การเชื่อมกับ asset ที่เปราะบาง ไม่ได้แปลว่า asset นี้เปราะบาง")
    L.append("- ทุก asset/ความสัมพันธ์ traceable กลับไปที่โมดูลต้นทาง (source_modules/evidence)")
    return "\n".join(L)


def render_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)


def render_txt(result: Dict[str, Any]) -> str:
    import re
    return re.sub(r"[#`*]", "", render_markdown(result))


def graph_json(result: Dict[str, Any]) -> str:
    """export เฉพาะกราฟ (nodes/edges) — ให้ไปวาด/วิเคราะห์ต่อได้"""
    return json.dumps(result.get("graph", {}), ensure_ascii=False, indent=2, default=str)
