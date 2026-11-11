# -*- coding: utf-8 -*-
"""attack_surface_correlation/insights.py — สร้าง insight เชิงวิเคราะห์ + เทียบประวัติ (pure)

insight มาจาก correlation/graph ที่สร้างแล้ว — แยก "สิ่งที่สังเกตได้ยืนยัน" ออกจาก
"สมมติฐานเชิงวิเคราะห์" เสมอ และ "ไม่สรุปว่า asset เปราะบางเพียงเพราะเชื่อมกับ asset ที่
เปราะบาง"

insight:
  {insight_id, title, description, category, related_assets, related_findings,
   evidence, confidence, hypothesis, potential_impact, recommended_next_step}
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import graph as graphmod

_SEV_ORDER = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _finding_meta(assets_by_id: Dict[str, Dict[str, Any]], fid: str) -> Dict[str, Any]:
    a = assets_by_id.get(fid)
    return (a.get("metadata") or {}) if a else {}


def generate_insights(assets: List[Dict[str, Any]], correlations: List[Dict[str, Any]],
                      graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """รวม insight ทั้งหมด — เรียงตาม (confidence, จำนวน asset เกี่ยวข้อง)"""
    assets_by_id = {a["asset_id"]: a for a in assets}
    out: List[Dict[str, Any]] = []
    seq = [0]

    def _emit(**kw):
        seq[0] += 1
        kw.setdefault("hypothesis", False)
        kw.setdefault("related_findings", [])
        kw.setdefault("evidence", [])
        kw["insight_id"] = f"INSIGHT-{seq[0]:04d}"
        out.append(kw)

    _insight_multi_finding_assets(assets, correlations, assets_by_id, _emit)
    _insight_shared_infra(correlations, assets_by_id, _emit)
    _insight_many_endpoints(assets, correlations, assets_by_id, _emit)
    _insight_repeated_tech(correlations, _emit)
    _insight_cross_module_assets(assets, _emit)
    _insight_shared_root_cause(assets, assets_by_id, _emit)
    _insight_hub_assets(graph, assets_by_id, _emit)

    out.sort(key=lambda i: (-round(float(i.get("confidence", 0)), 2),
                            -len(i.get("related_assets", []))))
    return out


def _insight_multi_finding_assets(assets, correlations, by_id, emit) -> None:
    """asset ที่มีหลาย finding ที่เป็นอิสระต่อกัน"""
    per_asset: Dict[str, List[str]] = {}
    for c in correlations:
        if c["relationship"] == "has_finding":
            per_asset.setdefault(c["source"], []).append(c["target"])
    for aid, fids in per_asset.items():
        if len(fids) < 2:
            continue
        asset = by_id.get(aid, {})
        sevs = [_finding_meta(by_id, f).get("severity", "INFORMATIONAL") for f in fids]
        top = max(sevs, key=lambda s: _SEV_ORDER.get(s, 0))
        emit(title=f"{asset.get('value','asset')} มี {len(fids)} finding",
             description=(f"asset นี้มี finding อิสระ {len(fids)} รายการ (สูงสุด {top}) — "
                          f"ควรจัดลำดับตรวจสอบก่อน เพราะพื้นที่ถูกกระทบหลายจุด"),
             category="multi_finding_asset",
             related_assets=[aid], related_findings=fids,
             evidence=[f"{len(fids)} findings: " +
                       ", ".join(_finding_meta(by_id, f).get("title", "?") for f in fids[:5])],
             confidence=0.8, hypothesis=False,
             potential_impact=f"asset ที่ถูกกระทบหลายจุด (top severity {top})",
             recommended_next_step="ตรวจสอบและแก้ตามลำดับความรุนแรง เริ่มจาก finding ที่ยืนยันแล้ว")


def _insight_shared_infra(correlations, by_id, emit) -> None:
    """โครงสร้างพื้นฐานร่วมที่สำคัญ (shared IP/cert) — เป็นการสังเกต ไม่ใช่ข้อสรุปเจ้าของ"""
    groups = [c for c in correlations
              if c["relationship"] == "shared_infrastructure"]
    if not groups:
        return
    assets_involved = sorted({c["source"] for c in groups} | {c["target"] for c in groups})
    emit(title=f"พบความสัมพันธ์โครงสร้างพื้นฐานร่วม {len(groups)} รายการ",
         description=("asset หลายตัวใช้ IP/ใบรับรองร่วมกัน — บันทึกเป็น 'การสังเกตโครงสร้างร่วม' "
                      "เท่านั้น ไม่ใช่หลักฐานว่าเป็นเจ้าของเดียวกัน (อาจเป็น shared hosting/CDN)"),
         category="shared_infrastructure",
         related_assets=[a for a in assets_involved if not str(a).endswith(":san")],
         evidence=[c["explanation"] for c in groups[:4]],
         confidence=0.65, hypothesis=True,
         potential_impact="ถ้ายืนยันว่าเป็นเจ้าของเดียวกัน พื้นที่โจมตีจะเชื่อมถึงกัน",
         recommended_next_step="ยืนยันความเป็นเจ้าของด้วย WHOIS/องค์กร/นโยบาย ก่อนถือว่าเกี่ยวข้อง")


def _insight_many_endpoints(assets, correlations, by_id, emit) -> None:
    """application/host ที่เปิด API endpoint จำนวนมาก"""
    per_host: Dict[str, List[str]] = {}
    for c in correlations:
        if c["relationship"] == "exposes_endpoint":
            per_host.setdefault(c["source"], []).append(c["target"])
    for hid, eps in per_host.items():
        if len(eps) < 3:
            continue
        host = by_id.get(hid, {})
        emit(title=f"{host.get('value','host')} เปิด {len(eps)} API endpoint",
             description=(f"host นี้เปิด endpoint จำนวนมาก ({len(eps)}) — พื้นที่โจมตีฝั่ง API กว้าง "
                          f"ควรตรวจ auth/authorization ให้ครบทุก endpoint"),
             category="api_surface",
             related_assets=[hid] + eps[:20],
             evidence=[", ".join(by_id.get(e, {}).get("value", "?") for e in eps[:6])],
             confidence=0.7, hypothesis=False,
             potential_impact="endpoint ที่ไม่ได้ป้องกันครบอาจเปิดช่องเข้าถึงข้อมูล",
             recommended_next_step="ตรวจสอบ authentication/authorization ของทุก endpoint ที่ลิสต์")


def _insight_repeated_tech(correlations, emit) -> None:
    """เทคโนโลยี/ลายนิ้วมือซ้ำข้ามหลาย asset"""
    for c in correlations:
        if c["relationship"] != "shared_technology":
            continue
        emit(title=f"เทคโนโลยีซ้ำ: {c['target'].split(':',1)[-1]}",
             description=c["explanation"],
             category="repeated_technology",
             related_assets=[c["source"]],
             evidence=c.get("evidence", []),
             confidence=c.get("confidence", 0.6),
             hypothesis=c.get("hypothesis", True),
             potential_impact="ช่องโหว่ของเทคโนโลยีนี้อาจกระทบทุก asset ที่ใช้ร่วมกัน (ต้องตรวจทีละตัว)",
             recommended_next_step="ตรวจเวอร์ชันของเทคโนโลยีนี้บนแต่ละ asset — อย่าเหมารวมว่าเปราะบางเท่ากัน")


def _insight_cross_module_assets(assets, emit) -> None:
    """asset ที่ปรากฏข้ามหลายโมดูล (ยืนยันหนักแน่นกว่า)"""
    for a in assets:
        mods = [m for m in a.get("source_modules", []) if m]
        if len(set(mods)) >= 2 and a["asset_type"] not in ("finding",):
            emit(title=f"{a['value']} ปรากฏใน {len(set(mods))} โมดูล",
                 description=(f"asset นี้ถูกสังเกตโดย {', '.join(sorted(set(mods)))} — "
                              f"ความเชื่อมั่นสูง เป็นจุดอ้างอิงที่ดีของพื้นที่โจมตี"),
                 category="cross_module_asset",
                 related_assets=[a["asset_id"]],
                 evidence=[f"source modules: {', '.join(sorted(set(mods)))}"],
                 confidence=min(0.95, 0.6 + 0.15 * len(set(mods))), hypothesis=False,
                 potential_impact="จุดยืนยันร่วม — เหมาะเป็นจุดเริ่มการประเมินเชิงลึก",
                 recommended_next_step="ใช้เป็น anchor ในการตรวจสอบความสัมพันธ์รอบข้าง")


def _insight_shared_root_cause(assets, by_id, emit) -> None:
    """หลาย finding ที่ category เดียวกันบนหลาย asset -> อาจมี root cause ร่วม (สมมติฐาน)"""
    by_cat: Dict[str, List[str]] = {}
    for a in assets:
        if a["asset_type"] != "finding":
            continue
        cat = (a.get("metadata") or {}).get("category")
        if cat:
            by_cat.setdefault(cat, []).append(a["asset_id"])
    for cat, fids in by_cat.items():
        affected = {(_finding_meta(by_id, f).get("affected_asset") or "") for f in fids}
        affected.discard("")
        if len(fids) >= 3 and len(affected) >= 2:
            emit(title=f"อาจมีสาเหตุร่วม: {cat} ({len(fids)} finding)",
                 description=(f"finding ประเภท {cat} เกิดบน {len(affected)} asset — อาจมาจาก "
                              f"การตั้งค่า/คอมโพเนนต์ร่วมตัวเดียว (สมมติฐาน ต้องยืนยัน)"),
                 category="shared_root_cause",
                 related_assets=[], related_findings=fids,
                 evidence=[f"affected: {', '.join(list(affected)[:6])}"],
                 confidence=0.55, hypothesis=True,
                 potential_impact="ถ้าเป็นสาเหตุร่วม แก้ที่ต้นทางเดียวจะปิดได้หลายจุดพร้อมกัน",
                 recommended_next_step="ตรวจว่า asset เหล่านี้ใช้ config/คอมโพเนนต์ร่วมกันหรือไม่")


def _insight_hub_assets(graph, by_id, emit) -> None:
    """asset ศูนย์กลาง (degree สูง) — จุดที่พื้นที่โจมตีกระจุก"""
    deg = graphmod.degree_map(graph)
    if not deg:
        return
    top = sorted(deg.items(), key=lambda kv: -kv[1])[:3]
    for nid, d in top:
        if d < 3:
            continue
        a = by_id.get(nid)
        label = a["value"] if a else nid
        emit(title=f"asset ศูนย์กลาง: {label} ({d} ความสัมพันธ์)",
             description=(f"asset นี้เชื่อมกับ asset อื่น {d} รายการ — เป็นจุดศูนย์กลางของพื้นที่โจมตี "
                          f"การเปลี่ยนแปลง/ช่องโหว่ที่นี่กระทบวงกว้าง"),
             category="hub_asset",
             related_assets=[nid],
             evidence=[f"degree={d}"],
             confidence=0.7, hypothesis=False,
             potential_impact="จุดศูนย์กลางมีผลกระทบเชิงโครงสร้างสูง",
             recommended_next_step="ให้ความสำคัญกับการตรวจสอบและเฝ้าระวัง asset ศูนย์กลางนี้")


# ---------------------------------------------------------------------------
# historical comparison (เทียบ snapshot) — ไม่ลบประวัติ
# ---------------------------------------------------------------------------

def compare_snapshots(previous: Optional[Dict[str, Any]],
                      current: Dict[str, Any]) -> Dict[str, Any]:
    """เทียบผลครั้งก่อน (previous) กับครั้งนี้ (current) — คืน diff เชิงพรรณนา

    แยก "ยืนยันว่าหายไป" (removed) ออกจาก "ไม่ถูกสังเกตรอบนี้" ไม่ได้จาก snapshot เดียว
    จึงรายงานเป็น "not_observed_now" (ระวังการตีความว่าถูกถอนออกจริง)
    """
    if not previous:
        return {"baseline": True, "note": "ไม่มีข้อมูลก่อนหน้า — นี่คือ baseline แรก"}

    def _vals(snap, kind):
        return {a["value"] for a in snap.get("assets", []) if a["asset_type"] == kind} \
            if kind else {a["value"] for a in snap.get("assets", [])}

    prev_assets = {a["value"]: a for a in previous.get("assets", [])}
    cur_assets = {a["value"]: a for a in current.get("assets", [])}
    new_assets = sorted(set(cur_assets) - set(prev_assets))
    not_observed = sorted(set(prev_assets) - set(cur_assets))
    still = sorted(set(prev_assets) & set(cur_assets))

    def _rel_keys(snap):
        return {(c["relationship"], c["source"], c["target"]) for c in snap.get("correlations", [])}
    # relationship เทียบด้วย value (เพราะ asset_id ไม่คงที่ข้าม run)
    def _rel_value_keys(snap):
        byid = {a["asset_id"]: a["value"] for a in snap.get("assets", [])}
        out = set()
        for c in snap.get("correlations", []):
            s = byid.get(c["source"], c["source"])
            t = byid.get(c["target"], c["target"])
            out.add((c["relationship"], s, t))
        return out
    prev_rels = _rel_value_keys(previous)
    cur_rels = _rel_value_keys(current)
    new_rels = sorted(cur_rels - prev_rels)
    gone_rels = sorted(prev_rels - cur_rels)

    def _finding_set(snap):
        out = set()
        for a in snap.get("assets", []):
            if a["asset_type"] == "finding":
                m = a.get("metadata") or {}
                out.add((m.get("category"), m.get("title"), m.get("affected_asset")))
        return out
    prev_f = _finding_set(previous)
    cur_f = _finding_set(current)
    new_findings = sorted(cur_f - prev_f)
    resolved_findings = sorted(prev_f - cur_f)       # ไม่พบรอบนี้ (อาจแก้แล้ว/ไม่ถูกสังเกต)
    reappearing = sorted(cur_f & prev_f)

    # changed IP associations (host -> ip)
    def _host_ips(snap):
        out: Dict[str, set] = {}
        for a in snap.get("assets", []):
            if a["asset_type"] in ("root_domain", "subdomain", "hostname"):
                out[a["value"]] = set(a.get("ip_addresses", []))
        return out
    pi, ci = _host_ips(previous), _host_ips(current)
    changed_ip = []
    for host in sorted(set(pi) & set(ci)):
        if pi[host] != ci[host] and (pi[host] or ci[host]):
            changed_ip.append({"host": host, "was": sorted(pi[host]), "now": sorted(ci[host])})

    return {
        "baseline": False,
        "previous_iso": previous.get("generated_iso") or previous.get("created_iso"),
        "current_iso": current.get("generated_iso") or current.get("created_iso"),
        "new_assets": new_assets,
        "not_observed_now": not_observed,
        "persisting_assets": still,
        "new_relationships": [list(r) for r in new_rels],
        "removed_relationships": [list(r) for r in gone_rels],
        "new_findings": [list(f) for f in new_findings],
        "resolved_or_unobserved_findings": [list(f) for f in resolved_findings],
        "reappearing_findings": [list(f) for f in reappearing],
        "changed_ip_associations": changed_ip,
        "note": ("'not_observed_now'/'resolved_or_unobserved' = ไม่พบในรอบนี้ ไม่ได้ยืนยันว่า "
                 "ถูกถอน/แก้แล้ว — ประวัติเดิมไม่ถูกลบ"),
    }
