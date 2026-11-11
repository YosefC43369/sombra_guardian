# -*- coding: utf-8 -*-
"""red_team_orchestrator/engine.py — วงจรชีวิต task + ไปป์ไลน์ประสานโมดูล (async)

ขั้นตอน: validate -> build plan -> (approval) -> run pipeline (ตามลำดับ + timeout + cancel)
-> collect ModuleResults -> correlate -> AI (ออปชัน) -> finalize + notify

ความปลอดภัย: ไม่ bypass scope — โมดูล active ต้องมี program_id (จาก simple_scope เดิม)
ที่ผูกกับโดเมนที่ /allowscan แล้ว; ถ้าไม่มี จะไม่รันโมดูล active และอธิบายเหตุผล
passive กับ active แยก permission (passive ไม่ต้องมี program)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from . import store, registry

logger = logging.getLogger("modbot.rt_orch.engine")

try:
    from web_vulnerability_assessment import simple_scope
    from scope_policy import normalize_target
    _HAS_DEPS = True
except Exception:  # pragma: no cover
    _HAS_DEPS = False

ProgressCb = Optional[Callable[[str], Awaitable[None]]]


async def _progress(cb, msg):
    if cb is not None:
        try:
            await cb(msg)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# validate + plan
# ---------------------------------------------------------------------------

def _valid_target(target: str) -> bool:
    if not _HAS_DEPS:
        return bool(target)
    return normalize_target(target) is not None


def build_plan(task_type: str, target: str, requested_modules: Optional[List[str]],
               path: Optional[str] = None) -> Dict[str, Any]:
    """สร้าง execution plan (ยังไม่รัน) — คืน dict plan"""
    modules = registry.select_modules(task_type, requested_modules)
    active = [m for m in modules if registry.REGISTRY[m].kind == "active"]
    program_id = simple_scope.program_for(target) if (_HAS_DEPS and active) else None
    authorization_required = bool(active)
    scope_ok = (program_id is not None) if active else True
    pol = store.get_policy(path)
    return {
        "task_type": task_type, "target": target,
        "selected_modules": modules, "execution_order": modules,
        "passive_modules": [m for m in modules if registry.REGISTRY[m].kind == "passive"],
        "active_modules": active,
        "authorization_required": authorization_required,
        "scope_authorized": scope_ok, "program_id": program_id,
        "approval_required": bool(pol.get("require_approval", True)),
        "expected_outputs": ["unified findings", "per-module results", "report (JSON/MD)",
                             "severity summary"] + (["AI summary"] if pol.get("use_ai") else []),
        "operational_risks": (["active testing: non-destructive safe-validation only, "
                               "scope-gated per request"] if active else
                              ["passive only: no active requests to target"]),
    }


def create_task(task_type: str, target: str, actor: int, chat_id: int,
                options: Optional[Dict[str, Any]] = None,
                requested_modules: Optional[List[str]] = None,
                path: Optional[str] = None) -> Dict[str, Any]:
    """สร้าง task + plan, คืน task record (สถานะ AWAITING_APPROVAL หรือ VALIDATING-fail)"""
    options = options or {}
    pol = store.get_policy(path)

    # กันรันซ้ำ (type,target เดียวกันที่ยัง active)
    dup = store.active_task_for(task_type, target, path)
    if dup:
        return {"error": "DUPLICATE_ACTIVE_TASK", "existing": dup["task_id"]}

    if task_type not in registry.PIPELINES and not requested_modules:
        return {"error": f"UNKNOWN_TASK_TYPE: {task_type}"}

    rec = store.create_task(task_type, target, actor, chat_id, options, path)
    tid = rec["task_id"]
    store.audit(tid, "created", f"type={task_type} target={target} actor={actor}", path)

    # VALIDATING
    store.update_task(tid, lambda r: r.__setitem__("status", "VALIDATING"), path)
    if not _valid_target(target):
        return _fail(tid, "TARGET_INVALID", path)

    plan = build_plan(task_type, target, requested_modules, path)
    if not plan["selected_modules"]:
        return _fail(tid, "NO_MODULES_AVAILABLE", path)

    # scope: ถ้ามีโมดูล active แต่ยังไม่ authorize -> หยุด + อธิบาย (ไม่ bypass)
    if plan["active_modules"] and not plan["scope_authorized"]:
        store.update_task(tid, lambda r: r.update({"plan": plan}), path)
        store.audit(tid, "authorization_denied",
                    f"active modules need /allowscan {target}", path)
        return _fail(tid, f"NOT_AUTHORIZED: ต้อง /allowscan {target} ก่อน "
                          f"(โมดูล active: {', '.join(plan['active_modules'])})", path)

    store.update_task(tid, lambda r: r.update({"plan": plan}), path)
    store.audit(tid, "planned", f"modules={plan['selected_modules']}", path)

    if plan["approval_required"]:
        store.update_task(tid, lambda r: r.__setitem__("status", "AWAITING_APPROVAL"), path)
    else:
        store.update_task(tid, lambda r: r.__setitem__("status", "RUNNING"), path)
    return store.get_task(tid, path)


def _fail(task_id, reason, path):
    store.update_task(task_id, lambda r: r.update(
        {"status": "FAILED", "status_reason": reason, "finished_iso": store.iso()}), path)
    store.audit(task_id, "failed", reason, path)
    return store.get_task(task_id, path)


# ---------------------------------------------------------------------------
# run pipeline
# ---------------------------------------------------------------------------

async def run_task(task_id: str, *, progress: ProgressCb = None, notify=None,
                   path: Optional[str] = None) -> Dict[str, Any]:
    """รันไปป์ไลน์ของ task ที่อนุมัติแล้ว — คืน task record สุดท้าย"""
    rec = store.get_task(task_id, path)
    if rec is None:
        return {"error": "TASK_NOT_FOUND"}
    if rec["status"] not in ("AWAITING_APPROVAL", "RUNNING", "PENDING"):
        return {"error": f"NOT_RUNNABLE: status={rec['status']}"}

    pol = store.get_policy(path)
    if store.running_count(path) > int(pol.get("max_concurrent_tasks", 2)):
        return _fail(task_id, "MAX_CONCURRENT_TASKS_REACHED", path)

    plan = rec["plan"]
    program_id = plan.get("program_id")
    actor = rec["actor"]
    timeout = int(pol.get("module_timeout", 900))
    options = rec.get("options", {})
    # ใส่ token กลับจาก options จริง (ไม่ได้เก็บใน record — รับจากผู้เรียกถ้ามี)
    options = dict(options)

    store.update_task(task_id, lambda r: r.update(
        {"status": "RUNNING", "started_iso": store.iso()}), path)
    store.audit(task_id, "run_start", f"modules={plan['execution_order']}", path)

    module_results: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []
    # sink สำหรับ attack_surface_correlation (in-memory เท่านั้น — ไม่ persist ลง task)
    asset_sink: Dict[str, Any] = {}
    ran_ok = 0
    ran_fail = 0

    for name in plan["execution_order"]:
        if store.is_cancelled(task_id, path):
            store.update_task(task_id, lambda r: r.update(
                {"status": "CANCELLED", "module_results": module_results,
                 "findings": all_findings, "finished_iso": store.iso()}), path)
            store.audit(task_id, "cancelled", f"before {name}", path)
            return store.get_task(task_id, path)

        spec = registry.REGISTRY[name]
        await _progress(progress, f"▶️ {name} …")
        ctx = {"target": rec["target"], "program_id": program_id, "actor": actor,
               "options": options, "progress": None, "asset_sink": asset_sink}
        try:
            result = await asyncio.wait_for(spec.adapter(ctx), timeout=timeout)
        except asyncio.TimeoutError:
            result = registry.module_result(name, "failed",
                                            errors=[f"TIMEOUT>{timeout}s"],
                                            started=registry._now(), completed=registry._now())
        except Exception as e:
            logger.exception("RT_ORCH adapter crash %s", name)
            result = registry.module_result(name, "failed", errors=[str(e)],
                                            started=registry._now(), completed=registry._now())

        module_results.append(result)
        if result["status"] == "failed":
            ran_fail += 1
            store.audit(task_id, "module_failed", f"{name}: {result['errors'][:1]}", path)
            # dependency: ถ้า passive_recon (ตัวแรก) ล้ม ยังรัน active ต่อได้ (optional feed)
        else:
            ran_ok += 1
            all_findings.extend(result["findings"])
            store.audit(task_id, "module_ok",
                        f"{name}: {len(result['findings'])} findings", path)

        # บันทึกผลระหว่างทาง (กู้คืนได้ถ้า process ตาย)
        store.update_task(task_id, lambda r, mr=list(module_results), af=list(all_findings):
                          r.update({"module_results": mr, "findings": af}), path)

    # correlate + counts
    all_findings = _correlate(all_findings)
    counts = _counts(all_findings, module_results)

    # Attack Surface Correlation (ออปชัน, non-invasive, ทนความล้มเหลว) —
    # ใช้ native output ที่ sink มา + unified findings; เก็บผลเต็มใน asc store,
    # แนบเฉพาะ pointer ย่อใน task record (กัน bloat)
    correlation_ref = await _attack_surface_correlation(
        rec["target"], asset_sink, all_findings, task_id, pol.get("use_ai"))

    # AI summary (ออปชัน, ทนความล้มเหลว)
    ai_summary = None
    if pol.get("use_ai") and all_findings:
        ai_summary = await _ai_summary(rec["target"], all_findings)

    # final status
    if ran_ok == 0:
        final = "FAILED"
    elif ran_fail > 0:
        final = "PARTIALLY_COMPLETED"
    else:
        final = "COMPLETED"

    # Evidence Management (ออปชัน, non-invasive) — ingest evidence จากผลที่ได้ (ไม่สแกนใหม่)
    evidence_ref = await _collect_evidence(
        task_id, rec, plan, all_findings, module_results, asset_sink, correlation_ref)

    store.update_task(task_id, lambda r: r.update(
        {"status": final, "module_results": module_results, "findings": all_findings,
         "counts": counts, "ai_summary": ai_summary, "correlation": correlation_ref,
         "evidence": evidence_ref, "finished_iso": store.iso()}), path)
    store.audit(task_id, "run_end", f"status={final} findings={len(all_findings)}", path)
    await _progress(progress, f"✅ {final}: {len(all_findings)} findings "
                              f"({ran_ok} โมดูลสำเร็จ / {ran_fail} ล้ม)")
    return store.get_task(task_id, path)


def _correlate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """ตัดซ้ำข้ามโมดูล (category+asset+title เดียวกัน) เก็บตัว severity สูงสุด"""
    order = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    best: Dict[tuple, Dict[str, Any]] = {}
    for f in findings:
        key = (f["category"], f["affected_asset"], f["title"])
        cur = best.get(key)
        if cur is None or order.get(f["severity"], 0) > order.get(cur["severity"], 0):
            if cur is not None:
                f = dict(f)
                f.setdefault("raw", {})["correlated_from"] = [cur["detection_source"],
                                                              f["detection_source"]]
            best[key] = f
    out = list(best.values())
    out.sort(key=lambda x: -order.get(x["severity"], 0))
    return out


def _counts(findings, module_results) -> Dict[str, Any]:
    c = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL",
                        "CONFIRMED", "POTENTIAL")}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
        v = f.get("verification_status")
        if v in c:
            c[v] = c.get(v, 0) + 1
    c["modules_ok"] = sum(1 for m in module_results if m["status"] != "failed")
    c["modules_failed"] = sum(1 for m in module_results if m["status"] == "failed")
    c["total_findings"] = len(findings)
    return c


async def _attack_surface_correlation(target, asset_sink, findings, task_id, use_ai):
    """เรียก attack_surface_correlation (ออปชัน) — คืน pointer ย่อ หรือ None

    ไม่ทำให้ pipeline ล้มถ้าโมดูลไม่มี/ปิดอยู่/ล้มเหลว — เป็นส่วนเสริมล้วน
    """
    try:
        import attack_surface_correlation as asc
    except Exception:
        return None
    try:
        if not asc.store.get_policy().get("enabled", True):
            return None
        result = await asc.correlate(asset_sink or {}, findings=findings, target=target,
                                     source_task_id=task_id, ai=bool(use_ai), persist=True)
        if result.get("error"):
            return {"status": result["error"]}
        return {"result_id": result.get("result_id"), "counts": result.get("counts", {}),
                "summary": asc.report.summary_line(result)}
    except Exception:
        logger.warning("RT_ORCH attack_surface_correlation failed", exc_info=True)
        return None


async def _collect_evidence(task_id, rec, plan, findings, module_results, asset_sink,
                            correlation_ref):
    """ingest evidence เข้า evidence_management (ออปชัน) — คืน pointer ย่อ หรือ None

    ไม่ทำให้ pipeline ล้มถ้าโมดูลไม่มี/ปิด/ล้มเหลว — เป็นส่วนเสริมล้วน
    """
    try:
        import evidence_management as evd
    except Exception:
        return None
    try:
        if not evd.store.get_policy().get("enabled", True):
            return None
        snapshot = {"task_id": task_id, "target": rec.get("target"), "plan": plan,
                    "findings": findings, "module_results": module_results,
                    "started_iso": rec.get("started_iso"), "finished_iso": store.iso()}
        correlation = None
        if correlation_ref and correlation_ref.get("result_id"):
            try:
                import attack_surface_correlation as asc
                correlation = asc.store.get_result(correlation_ref["result_id"])
            except Exception:
                correlation = None
        res = await asyncio.to_thread(
            evd.service.ingest_task, snapshot, module_outputs=asset_sink,
            correlation=correlation, actor="red_team_orchestrator")
        if res.get("error"):
            return {"status": res["error"]}
        return {"ingested": res.get("count", 0), "errors": len(res.get("errors", []))}
    except Exception:
        logger.warning("RT_ORCH evidence collection failed", exc_info=True)
        return None


async def _ai_summary(target, findings):
    try:
        import gemini
    except Exception:
        return None
    top = findings[:20]
    lines = [f"- [{f['severity']}/{f['verification_status']}] {f['category']} "
             f"{f['title']} @ {f['affected_asset']}" for f in top]
    prompt = ("สรุปผลประเมินความปลอดภัยต่อไปนี้ (ไทย, กระชับ): จัดลำดับความสำคัญตามผลกระทบ+ความเชื่อมั่น, "
              "อธิบายความเชื่อมโยง, แยก confirmed ออกจาก indicator, ห้ามกุผลหรืออ้าง exploit สำเร็จ\n\n"
              f"เป้าหมาย: {target}\nfindings:\n" + "\n".join(lines))
    try:
        ok, text = await gemini.ask_gemini(prompt)
        return text[:1200] if ok else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# approve / cancel
# ---------------------------------------------------------------------------

def approve(task_id: str, actor: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    rec = store.get_task(task_id, path)
    if rec is None or rec["status"] != "AWAITING_APPROVAL":
        return rec
    store.audit(task_id, "approved", f"by {actor}", path)
    store.update_task(task_id, lambda r: r.__setitem__("status", "RUNNING"), path)
    return store.get_task(task_id, path)
