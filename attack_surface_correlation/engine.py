# -*- coding: utf-8 -*-
"""attack_surface_correlation/engine.py — ประสาน normalize→relate→graph→insights (+AI ออปชัน)

เอนจินนี้ "ไม่สแกน" — รับ output ที่โมดูลเดิมเก็บมาแล้วเท่านั้น (passive_recon report,
wva/api assessment, active_scan, unified findings จาก orchestrator) แล้ว:
  normalize assets (dedupe) -> correlate (rules + กันผลบวกลวง) -> graph -> insights ->
  เทียบประวัติ -> (AI อธิบายออปชัน) -> เก็บผล

ทุกขั้น deterministic: ถ้า AI ไม่พร้อม ผล correlation ยังออกครบ

การผูกกับ orchestrator: analyze_task(task_id) อ่าน task ที่ orchestrator เก็บไว้
(reuse red_team_orchestrator.store) แล้ว correlate โดยไม่ต้องสแกนใหม่
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import normalize, relate, graph as graphmod, insights, store

logger = logging.getLogger("modbot.asc.engine")

# ชื่อ key ของ native output ที่รู้จัก -> extractor
_EXTRACTORS = {
    "passive_recon": normalize.extract_passive_recon,
    "web_vulnerability_assessment": normalize.extract_web_assessment,
    "api_security_assessment": normalize.extract_api_assessment,
    "active_scan": normalize.extract_active_scan,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# core deterministic build (ไม่แตะ I/O นอกจาก store ที่ส่งเข้ามา)
# ---------------------------------------------------------------------------

def build_result(module_outputs: Optional[Dict[str, Any]] = None, *,
                 findings: Optional[List[Dict[str, Any]]] = None,
                 target: Optional[str] = None,
                 previous: Optional[Dict[str, Any]] = None,
                 policy: Optional[Dict[str, Any]] = None,
                 source_task_id: Optional[str] = None) -> Dict[str, Any]:
    """สร้าง correlation result (deterministic, ไม่มี AI) จาก output ที่ให้มา

    module_outputs: {module_name: native_output} — คีย์ที่ไม่รู้จักจะถูกข้ามอย่างปลอดภัย
    findings: unified findings (เสริม/ใช้แทนเมื่อไม่มี native output)
    previous: result ก่อนหน้า (ไว้เทียบประวัติ)
    """
    pol = dict(store.DEFAULT_POLICY)
    if policy:
        pol.update(policy)
    threshold = float(pol.get("confidence_threshold", 0.70))
    max_assets = int(pol.get("max_assets", 10000))

    builder = normalize.AssetBuilder(max_assets=max_assets)
    used_modules: List[str] = []
    errors: List[str] = []

    for name, output in (module_outputs or {}).items():
        extractor = _EXTRACTORS.get(name)
        if extractor is None:
            continue
        try:
            extractor(output, builder)
            used_modules.append(name)
        except Exception as e:                      # ทน record เพี้ยน ไม่ให้ pipeline ล้ม
            logger.warning("ASC extractor %s failed: %s", name, e)
            errors.append(f"{name}: {type(e).__name__}")

    if findings:
        try:
            normalize.extract_unified_findings(findings, builder)
            used_modules.append("orchestrator")
        except Exception as e:
            logger.warning("ASC unified findings failed: %s", e)
            errors.append(f"findings: {type(e).__name__}")

    assets = builder.assets()
    correlations = relate.correlate_assets(assets, confidence_threshold=threshold)
    graph = graphmod.build_graph(assets, correlations)
    insight_list = (insights.generate_insights(assets, correlations, graph)
                    if pol.get("enabled", True) else [])

    history = {}
    if pol.get("history_enabled", True):
        try:
            history = insights.compare_snapshots(previous, {
                "assets": assets, "correlations": correlations,
                "generated_iso": _now()})
        except Exception as e:
            logger.warning("ASC history compare failed: %s", e)
            history = {"error": type(e).__name__}

    result = {
        "target": target or "",
        "source_task_id": source_task_id,
        "created_iso": _now(),
        "generated_iso": _now(),
        "policy": {k: pol[k] for k in ("confidence_threshold", "max_assets",
                                       "history_enabled", "use_ai")},
        "source_modules": sorted(set(used_modules)),
        "assets": assets,
        "correlations": correlations,
        "graph": graph,
        "insights": insight_list,
        "history": history,
        "counts": _counts(assets, correlations, insight_list, builder),
        "errors": errors,
        "ai_summary": None,
        "notes": ("passive data-processing · ทุกความสัมพันธ์อ้างหลักฐานหรือระบุเป็นสมมติฐาน · "
                  "IP/CDN/โครงสร้างร่วม ไม่ถือเป็นหลักฐานความเป็นเจ้าของ"),
    }
    return result


def _counts(assets, correlations, insight_list, builder) -> Dict[str, Any]:
    by_type: Dict[str, int] = {}
    for a in assets:
        by_type[a["asset_type"]] = by_type.get(a["asset_type"], 0) + 1
    rel_types: Dict[str, int] = {}
    hypo = 0
    for c in correlations:
        rel_types[c["relationship"]] = rel_types.get(c["relationship"], 0) + 1
        if c.get("hypothesis"):
            hypo += 1
    return {
        "total_assets": len(assets),
        "assets_by_type": by_type,
        "total_relationships": len(correlations),
        "relationships_by_type": rel_types,
        "hypothesis_relationships": hypo,
        "confirmed_relationships": len(correlations) - hypo,
        "total_insights": len(insight_list),
        "high_confidence_insights": sum(1 for i in insight_list
                                        if float(i.get("confidence", 0)) >= 0.75
                                        and not i.get("hypothesis")),
        "assets_dropped_over_limit": builder.dropped,
    }


# ---------------------------------------------------------------------------
# AI อธิบาย (ออปชัน, reuse gemini เดิม, ทนล้มเหลว)
# ---------------------------------------------------------------------------

async def ai_explain(result: Dict[str, Any]) -> Optional[str]:
    """ส่งผล correlation (ย่อ) ให้ AI เดิมอธิบาย — คืน None ถ้า AI ไม่พร้อม/ล้มเหลว

    reuse gemini.ask_gemini (ไม่สร้าง client ใหม่) — AI ห้ามกุ asset/ความสัมพันธ์
    """
    try:
        import gemini
    except Exception:
        return None

    c = result.get("counts", {})
    top_rel = [f"- {r['relationship']} ({r['ownership']}" +
               (", สมมติฐาน" if r.get("hypothesis") else "") + f"): {r['explanation']}"
               for r in result.get("correlations", [])[:12]]
    top_ins = [f"- [{'สมมติฐาน' if i.get('hypothesis') else 'สังเกตยืนยัน'}] {i['title']}: "
               f"{i['description']}" for i in result.get("insights", [])[:8]]
    prompt = (
        "คุณคือผู้ช่วยวิเคราะห์ Attack Surface ของทีม Red Team ที่ได้รับอนุญาต "
        "สรุปพื้นที่โจมตีจากผลการ correlate ด้านล่าง (ไทย กระชับ เป็นหัวข้อ)\n"
        "ข้อบังคับ: อธิบายเฉพาะจากข้อมูลที่ให้ · ห้ามกุ asset/ความสัมพันธ์/หลักฐาน · "
        "แยก 'สังเกตยืนยัน' ออกจาก 'สมมติฐาน' · ห้ามสรุปว่าเป็นเจ้าของเดียวกันเพราะใช้ "
        "IP/CDN/เทคโนโลยีร่วม · ห้ามบอกว่า asset เปราะบางเพียงเพราะเชื่อมกับ asset ที่เปราะบาง · "
        "อธิบายความไม่แน่นอน/ข้อจำกัดของความเชื่อมั่นด้วย\n\n"
        f"เป้าหมาย: {result.get('target')}\n"
        f"สรุปตัวเลข: assets={c.get('total_assets')} "
        f"relationships={c.get('total_relationships')} "
        f"(ยืนยัน {c.get('confirmed_relationships')} / สมมติฐาน {c.get('hypothesis_relationships')}) "
        f"insights={c.get('total_insights')}\n\n"
        "ความสัมพันธ์เด่น:\n" + "\n".join(top_rel) + "\n\n"
        "insight เด่น:\n" + "\n".join(top_ins)
    )
    try:
        ok, text = await gemini.ask_gemini(prompt)
        return text[:1500] if ok else None
    except Exception:
        logger.warning("ASC ai_explain failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# public: correlate (deterministic + optional AI) + persist
# ---------------------------------------------------------------------------

async def correlate(module_outputs: Optional[Dict[str, Any]] = None, *,
                    findings: Optional[List[Dict[str, Any]]] = None,
                    target: Optional[str] = None,
                    source_task_id: Optional[str] = None,
                    ai: Optional[bool] = None,
                    persist: bool = True,
                    path: Optional[str] = None) -> Dict[str, Any]:
    """เอนทรีหลัก: correlate ชุด output -> result (เทียบประวัติ + AI ออปชัน + เก็บผล)"""
    pol = store.get_policy(path)
    if not pol.get("enabled", True):
        return {"error": "ASC_DISABLED",
                "note": "ตั้ง ATTACK_SURFACE_CORRELATION_ENABLED=true เพื่อเปิด"}

    previous = store.latest_for_target(target, path) if (target and pol.get("history_enabled")) else None
    result = build_result(module_outputs, findings=findings, target=target,
                          previous=previous, policy=pol, source_task_id=source_task_id)

    use_ai = pol.get("use_ai", False) if ai is None else bool(ai)
    if use_ai and result.get("counts", {}).get("total_assets"):
        result["ai_summary"] = await ai_explain(result)

    if persist:
        result = store.save_result(result, path)
    return result


# ---------------------------------------------------------------------------
# orchestrator integration — วิเคราะห์ข้อมูลที่เก็บไว้แล้ว (ไม่สแกนใหม่)
# ---------------------------------------------------------------------------

def from_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """แกะ module_outputs/findings จาก orchestrator task record

    task record เก็บ unified findings + module_results (ไม่เก็บ native passive report)
    จึงใช้ findings เป็นหลัก — lossy แต่ยัง traceable (คง detection_source/evidence)
    native output ที่ sink มา (ถ้ามี) ถูกส่งแยกผ่าน correlate(module_outputs=...)
    """
    return {
        "findings": task.get("findings", []) or [],
        "target": task.get("target", ""),
        "source_task_id": task.get("task_id"),
    }


async def analyze_task(task_id: str, *, ai: Optional[bool] = None,
                       path: Optional[str] = None,
                       rt_path: Optional[str] = None,
                       module_outputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """โหลด task ที่ orchestrator เก็บไว้แล้ว correlate โดยไม่สแกนใหม่

    module_outputs (ออปชัน): native output ที่ orchestrator ส่ง sink มา (ถ้าเปิด hook)
    """
    try:
        from red_team_orchestrator import store as rt_store
    except Exception:
        return {"error": "ORCHESTRATOR_UNAVAILABLE"}
    task = rt_store.get_task(task_id, rt_path)
    if task is None:
        return {"error": "TASK_NOT_FOUND", "task_id": task_id}
    extracted = from_task(task)
    return await correlate(module_outputs or {}, findings=extracted["findings"],
                           target=extracted["target"],
                           source_task_id=extracted["source_task_id"],
                           ai=ai, persist=True, path=path)
