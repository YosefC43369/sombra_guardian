# -*- coding: utf-8 -*-
"""
osint_cases.py — คลังจัดเก็บ "เคส OSINT" ที่เก็บผลเต็มจาก /osint (ต่อยอด osint.collector)

ต่างจาก osint_db.py อย่างไร
--------------------------
osint_db.py เก็บ "ผลการค้น /search ที่ยืนยันแล้ว" (ระเบียนแบน จัดหมวดตาม selector)
โมดูลนี้เก็บ "เคสข่าวกรองเต็ม" ที่ /osint สร้าง (profile + assessment + merged +
สถานะแหล่ง) โดย *คีย์ด้วย case_id* เพื่อเรียกดูทีหลังผ่าน /browse ได้ตรง ๆ

ออกแบบตามแบบเดียวกับ osint_db.py:
- ไลบรารีมาตรฐานล้วน (+ osint_es สำหรับดัชนี ES แบบ best-effort เท่านั้น)
- เขียนไฟล์แบบ atomic (temp + os.replace) — ไฟล์ถูกสร้าง "ครั้งแรกเมื่อบันทึกเคสแรก"
- เพดานจำนวนเคส ตัด FIFO
การเข้าถึงถูกจำกัดที่ชั้น Admin ใน app.py (callback ยืนยันบันทึก + /browse ตรวจสิทธิ์)
"""

import os
import io
import json
import logging
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.osint_cases")

DB_PATH = os.getenv("OSINT_CASES_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource", "osint_cases.json")

SCHEMA = "sombra_guardian.osint_cases"
SCHEMA_VERSION = 1
MAX_CASES = int(os.getenv("OSINT_CASES_MAX", "500") or "500")


def _db_path(path: Optional[str] = None) -> str:
    return path or DB_PATH


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_db() -> dict:
    now = _now_iso()
    return {"schema": SCHEMA, "version": SCHEMA_VERSION,
            "created_at": now, "updated_at": now, "cases": {}}


def load_db(path: Optional[str] = None) -> dict:
    target = _db_path(path)
    if not os.path.exists(target):
        return _empty_db()
    try:
        with io.open(target, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("OSINT CASES | อ่าน %s ไม่ได้ (%s) — เริ่มจากคลังว่าง", target, e)
        return _empty_db()
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), dict):
        logger.warning("OSINT CASES | รูปแบบไฟล์ %s ไม่ถูกต้อง — เริ่มจากคลังว่าง", target)
        return _empty_db()
    raw.setdefault("schema", SCHEMA)
    raw.setdefault("version", SCHEMA_VERSION)
    raw.setdefault("created_at", _now_iso())
    return raw


def _atomic_write(db: dict, path: Optional[str] = None) -> str:
    target = _db_path(path)
    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".osint_cases.", suffix=".tmp", dir=parent)
    try:
        with io.open(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def save_case(case: dict, path: Optional[str] = None) -> dict:
    """บันทึกเคสลงคลัง (คีย์ด้วย case_id) แบบ atomic — คืนสรุป
    {"ok","case_id","path","total","created","duplicate"}

    duplicate=True เมื่อมีเคส signature เดียวกันอยู่แล้ว (กันบันทึกซ้ำจากการกดยืนยันซ้ำ)
    """
    target = _db_path(path)
    created = not os.path.exists(target)
    db = load_db(target)
    cases: Dict[str, Any] = db["cases"]

    case_id = case.get("case_id")
    if not case_id:
        raise ValueError("case must have a case_id")
    signature = case.get("signature")

    if signature:
        for cid, existing in cases.items():
            if existing.get("signature") == signature:
                return {"ok": True, "case_id": cid, "path": target,
                        "total": len(cases), "created": False, "duplicate": True}

    cases[case_id] = case
    # ตัด FIFO ถ้าเกินเพดาน (dict รักษาลำดับการใส่)
    while MAX_CASES > 0 and len(cases) > MAX_CASES:
        cases.pop(next(iter(cases)))
    db["updated_at"] = _now_iso()
    _atomic_write(db, target)
    logger.info("OSINT CASES | บันทึก %s (รวม %d เคส) -> %s",
                case_id, len(cases), target)
    return {"ok": True, "case_id": case_id, "path": target,
            "total": len(cases), "created": created, "duplicate": False}


def get_case(case_id: str, path: Optional[str] = None) -> Optional[dict]:
    """ดึงเคสตาม case_id — รองรับ prefix ย่อ (จับคู่ถ้ามีเคสเดียวที่ขึ้นต้นด้วยค่านี้)
    และจับคู่ตาม target ถ้าไม่ตรง case_id"""
    db = load_db(path)
    cases: Dict[str, Any] = db["cases"]
    if case_id in cases:
        return cases[case_id]
    # prefix match บน case_id
    pref = [c for cid, c in cases.items() if cid.startswith(case_id)]
    if len(pref) == 1:
        return pref[0]
    # target match (ล่าสุดก่อน)
    by_target = [c for c in cases.values()
                 if str(c.get("target", "")).lower() == case_id.lower()]
    if by_target:
        return sorted(by_target, key=lambda c: c.get("created_at", ""))[-1]
    return None


def search_cases(query: str, limit: int = 10, path: Optional[str] = None) -> List[dict]:
    """ค้นในคลังแบบ local (target / registrar / breach / tech / subdomain) — คืนเคสที่แมตช์"""
    q = (query or "").strip().lower()
    if not q:
        return []
    db = load_db(path)
    hits = []
    for case in db["cases"].values():
        blob_parts = [str(case.get("target", ""))]
        prof = case.get("profile", {})
        infra = prof.get("infrastructure", {})
        blob_parts += infra.get("subdomains", []) + infra.get("ips", [])
        reg = prof.get("registration", {})
        if reg.get("registrar"):
            blob_parts.append(reg["registrar"])
        for b in prof.get("exposure", {}).get("breaches", []):
            blob_parts.append(str(b.get("name", "")))
        for t in prof.get("technology", []):
            blob_parts.append(str(t.get("value", "")))
        blob = " ".join(blob_parts).lower()
        if q in blob:
            hits.append(case)
    hits.sort(key=lambda c: c.get("created_at", ""), reverse=True)
    return hits[:limit]


def list_cases(limit: int = 20, path: Optional[str] = None) -> List[dict]:
    """คืนสรุปเคสล่าสุด (case_id, target, level, created_at) สำหรับแสดงรายการ"""
    db = load_db(path)
    rows = [
        {"case_id": c.get("case_id"), "target": c.get("target"),
         "security_level": c.get("assessment", {}).get("security_level"),
         "created_at": c.get("created_at")}
        for c in db["cases"].values()
    ]
    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return rows[:limit]


def index_case_es(case: dict) -> bool:
    """ทำดัชนีเคสลง Elasticsearch แบบ best-effort — คืน False เงียบ ๆ ถ้าไม่ได้ตั้งค่า ES"""
    try:
        import osint_es
    except Exception:
        return False
    if not osint_es.es_configured() or not osint_es.es_available():
        return False
    try:
        client = osint_es.get_client()
        if client is None:
            return False
        index = os.getenv("OSINT_CASES_ES_INDEX", "osint-cases")
        doc = {
            "case_id": case.get("case_id"),
            "target": case.get("target"),
            "kind": case.get("kind"),
            "created_at": case.get("created_at"),
            "security_level": case.get("assessment", {}).get("security_level"),
            "risk_level": case.get("assessment", {}).get("risk_level"),
            "score": case.get("assessment", {}).get("score"),
            "subdomains": case.get("profile", {}).get("infrastructure", {}).get("subdomains", []),
            "breaches": [b.get("name") for b in
                         case.get("profile", {}).get("exposure", {}).get("breaches", [])],
        }
        client.index(index=index, id=case.get("case_id"), document=doc)
        return True
    except Exception:
        logger.exception("OSINT CASES | index ES ล้มเหลว case_id=%s", case.get("case_id"))
        return False
