# -*- coding: utf-8 -*-
"""osint_db.py — ฐานข้อมูล "ผลการค้น OSINT ที่ยืนยันแล้ว" (ต่อยอดจาก /search)

แนวคิด
------
/search ดึงข้อมูลดิบจากเว็บ (clearnet + dark web) มาแสดง แต่ *ไม่* เก็บอะไรไว้
โมดูลนี้เพิ่มขั้น "ยืนยันเพื่อบันทึก": เมื่อ Admin กดยืนยัน ระบบจะ

  1. จัดหมวดหมู่สิ่งที่ค้นเจอ (แหล่งตามฝั่งที่มา + ตัวระบุตามชนิด IOC)
  2. ประกอบเป็นระเบียนเดียว (finding record) พร้อม metadata (คำค้น/เวลา/ผู้บันทึก)
  3. เขียนต่อท้ายไฟล์ JSON — ไฟล์จะถูก "สร้างขึ้นครั้งแรกหลังการยืนยันบันทึก"
     (ถ้ายังไม่มีไฟล์) ไม่ใช่มีมาก่อน

ออกแบบให้พึ่งพาแค่ไลบรารีมาตรฐาน + osint.py (สำหรับตรรกะจัดหมวดหมู่/ยืนยันข้ามแหล่ง)
เพื่อให้ import ได้โดยไม่ต้องมี dependency ภายนอก และเทสต์ได้ง่าย

การเข้าถึง: เรียกใช้เฉพาะจากเส้นทางที่ผ่านการตรวจ Admin แล้วใน app.py เท่านั้น
(callback ยืนยันบันทึกจะตรวจ is_admin ซ้ำก่อนเรียก save_finding)
"""

import os
import io
import json
import hashlib
import logging
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import osint

logger = logging.getLogger("modbot.osint_db")

# ที่อยู่ไฟล์ฐานข้อมูล — override ได้ด้วย env OSINT_FINDINGS_DB
# ค่าเริ่มต้น: resource/osint_db.json (คนละไฟล์กับ resource/data.json ซึ่งเป็น
# ฐานข้อมูลรายชื่อเว็บแบบ maigret — ไม่ทับกัน) จงใจไม่ใช้ชื่อ env OSINT_DB_PATH
# เพราะสภาพแวดล้อมบางชุดตั้งค่านั้นชี้ไปที่ไฟล์ .sqlite3 ของระบบอื่น
DB_PATH = os.getenv("OSINT_FINDINGS_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource", "osint_db.json")

SCHEMA = "sombra_guardian.osint_db"
SCHEMA_VERSION = 1

# เพดานกันไฟล์บวมเกินเหตุ — เก็บระเบียนล่าสุดไว้เท่านี้ (ตัดของเก่าทิ้งแบบ FIFO)
MAX_ENTRIES = int(os.getenv("OSINT_DB_MAX_ENTRIES", "1000") or "1000")


def _db_path(path: Optional[str] = None) -> str:
    return path or DB_PATH


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_of(url: str) -> str:
    try:
        return urlsplit(str(url or "")).netloc.lower()
    except ValueError:
        return ""


def _empty_db() -> dict:
    now = _now_iso()
    return {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "created_at": now,
        "updated_at": now,
        "entries": [],
    }


def load_db(path: Optional[str] = None) -> dict:
    """โหลดฐานข้อมูลจากไฟล์ — คืนโครงว่าง (ยังไม่เขียนไฟล์) ถ้ายังไม่มีไฟล์/อ่านไม่ได้

    ไม่โยน exception ให้ผู้เรียก: ถ้าไฟล์เสีย/ไม่ใช่ JSON จะ log แล้วคืนโครงว่าง
    เพื่อให้การบันทึกครั้งถัดไปยังทำงานต่อได้ (ของเดิมที่เสียจะถูกเขียนทับ)
    """
    target = _db_path(path)
    if not os.path.exists(target):
        return _empty_db()
    try:
        with io.open(target, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("OSINT DB | อ่าน %s ไม่ได้ (%s) — เริ่มจากฐานข้อมูลว่าง", target, e)
        return _empty_db()
    if not isinstance(raw, dict) or not isinstance(raw.get("entries"), list):
        logger.warning("OSINT DB | รูปแบบไฟล์ %s ไม่ถูกต้อง — เริ่มจากฐานข้อมูลว่าง", target)
        return _empty_db()
    raw.setdefault("schema", SCHEMA)
    raw.setdefault("version", SCHEMA_VERSION)
    raw.setdefault("created_at", _now_iso())
    return raw


def _atomic_write(db: dict, path: Optional[str] = None) -> str:
    """เขียนไฟล์แบบ atomic (เขียนไฟล์ชั่วคราวในโฟลเดอร์เดียวกันแล้ว os.replace)
    เพื่อไม่ให้ไฟล์ฐานข้อมูลเสียหายถ้าถูกขัดจังหวะกลางคัน สร้างโฟลเดอร์ให้ถ้ายังไม่มี
    """
    target = _db_path(path)
    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".osint_db.", suffix=".tmp", dir=parent)
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


def build_finding_record(query: str, selector_summary: str,
                         display_records: List[dict],
                         actor: Optional[int] = None,
                         min_sources: int = None) -> dict:
    """ประกอบระเบียน finding เดียวจากผลที่ /search แสดง (display_records)

    - จัดหมวดแหล่งตามฝั่งที่มา (clearnet/darkweb/username) โดยใช้ตรรกะเดียวกับ
      ที่หน้าจอ /search ใช้ (osint.categorize_by_origin) — เลข Sxx จึงตรงกัน
    - จัดหมวดตัวระบุที่ "ยืนยันข้ามแหล่ง" ตามชนิด IOC (osint.corroborated_identifiers)

    หมายเหตุ PII: ระเบียนนี้คือ "บันทึกข่าวกรอง" ของ Admin จึงเก็บค่าที่ค้นเจอจริง
    (ไม่ปกปิด) การเข้าถึงถูกจำกัดที่ชั้น Admin + audit log ในตัวคำสั่งแล้ว ส่วนการ
    "แสดงผล" ต่อผู้ใช้ยังปกปิด PII เสมอผ่าน mask_pii
    """
    if min_sources is None:
        min_sources = osint.IDENTITY_MIN_SOURCES
    records = list(display_records or [])

    # (1) แหล่งจัดกลุ่มตามฝั่งที่มา
    categories: Dict[str, dict] = {}
    for group in osint.categorize_by_origin(records):
        items = []
        for it in group["items"]:
            rec = it["record"]
            items.append({
                "ref": it["ref"],
                "title": str(rec.get("title", "") or ""),
                "url": str(rec.get("link", "") or ""),
                "host": _host_of(rec.get("link", "")),
                "engine": str(rec.get("engine", "") or ""),
                "relevance": int(rec.get("relevance", 0) or 0),
                "seen": int(rec.get("engines", 1) or 1),
                "snippet": str(rec.get("snippet", "") or "")[:500],
                "on_target": bool(int(rec.get("relevance", 0) or 0) > 0),
            })
        categories[group["origin"]] = {
            "emoji": group["emoji"],
            "label": group["label"],
            "count": len(items),
            "sources": items,
        }

    # (2) ตัวระบุที่ยืนยันข้ามแหล่ง จัดกลุ่มตามชนิด IOC
    corroborated = osint.corroborated_identifiers(records, min_sources=min_sources)
    identifiers: Dict[str, dict] = {}
    for item in corroborated:
        slot = identifiers.setdefault(item["type"], {
            "emoji": osint.ioc_emoji(item["type"]),
            "label": osint.IOC_LABELS.get(item["type"], item["type"]),
            "values": [],
        })
        slot["values"].append({
            "value": item["value"],
            "sources": int(item["sources"]),
            "refs": list(item["refs"]),
        })

    record = {
        "query": str(query or "").strip()[:500],
        "selector": str(selector_summary or "").strip()[:500],
        "saved_by": actor,
        "saved_at": _now_iso(),
        "stats": {
            "sources": len(records),
            "categories": {k: v["count"] for k, v in categories.items()},
            "corroborated": len(corroborated),
        },
        "categories": categories,
        "identifiers": identifiers,
    }
    record["signature"] = _signature(record)
    record["id"] = _make_id(record["signature"])
    return record


def _signature(record: dict) -> str:
    """ลายเซ็นเนื้อหา = คำค้น + ชุด URL ที่เจอ ใช้กันการบันทึกซ้ำจากการกดยืนยันซ้ำ"""
    urls = sorted(
        src["url"]
        for cat in record.get("categories", {}).values()
        for src in cat.get("sources", [])
        if src.get("url")
    )
    blob = (record.get("query", "") + "\n" + "\n".join(urls)).encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()


def _make_id(signature: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"OSINT-{stamp}-{signature[:8]}"


def save_finding(record: dict, path: Optional[str] = None) -> dict:
    """บันทึกระเบียนลงไฟล์ JSON (สร้างไฟล์ถ้ายังไม่มี) แบบ atomic

    คืน dict สรุปผล:
      {"ok", "id", "path", "total", "created", "duplicate"}
    - duplicate=True เมื่อมีระเบียนลายเซ็นเดียวกันอยู่แล้ว (ไม่เพิ่มซ้ำ)
    - created=True เมื่อไฟล์ฐานข้อมูลถูกสร้างขึ้นในการบันทึกครั้งนี้
    """
    target = _db_path(path)
    created = not os.path.exists(target)
    db = load_db(target)

    signature = record.get("signature") or _signature(record)
    for existing in db["entries"]:
        if existing.get("signature") == signature:
            logger.info("OSINT DB | ข้ามการบันทึกซ้ำ signature=%s id=%s",
                        signature[:8], existing.get("id"))
            return {
                "ok": True, "id": existing.get("id"), "path": target,
                "total": len(db["entries"]), "created": False, "duplicate": True,
            }

    db["entries"].append(record)
    # ตัดของเก่าทิ้งแบบ FIFO ถ้าเกินเพดาน
    if MAX_ENTRIES > 0 and len(db["entries"]) > MAX_ENTRIES:
        db["entries"] = db["entries"][-MAX_ENTRIES:]
    db["updated_at"] = _now_iso()
    _atomic_write(db, target)
    logger.info("OSINT DB | บันทึก id=%s (รวม %d ระเบียน) -> %s",
                record.get("id"), len(db["entries"]), target)
    return {
        "ok": True, "id": record.get("id"), "path": target,
        "total": len(db["entries"]), "created": created, "duplicate": False,
    }


def format_saved_summary(record: dict, save_result: dict) -> str:
    """ข้อความยืนยันหลังบันทึก (แสดงต่อ Admin) — สรุปหมวดหมู่ที่บันทึก + จำนวน"""
    lines = []
    if save_result.get("duplicate"):
        lines.append("ℹ️ ข้อมูลชุดนี้เคยถูกบันทึกไว้แล้ว (ไม่บันทึกซ้ำ)")
    elif save_result.get("created"):
        lines.append("✅ สร้างฐานข้อมูลและบันทึกผลการค้นเรียบร้อย")
    else:
        lines.append("✅ บันทึกผลการค้นลงฐานข้อมูลเรียบร้อย")

    lines.append(f"🆔 รหัสระเบียน: {record.get('id')}")
    lines.append(f"🔎 คำค้น: {record.get('query', '-')}")

    cats = record.get("categories", {})
    if cats:
        lines.append("")
        lines.append("📂 หมวดหมู่แหล่งที่บันทึก:")
        for cat in sorted(cats.values(), key=lambda c: -c.get("count", 0)):
            lines.append(f"   {cat['emoji']} {cat['label']} — {cat['count']} แหล่ง")

    idents = record.get("identifiers", {})
    if idents:
        lines.append("")
        lines.append("🔗 ตัวระบุที่ยืนยันข้ามแหล่ง:")
        for slot in idents.values():
            lines.append(f"   {slot['emoji']} {slot['label']} — {len(slot['values'])} รายการ")

    lines.append("")
    lines.append(f"🗂️ รวมในฐานข้อมูลตอนนี้: {save_result.get('total', 0)} ระเบียน")
    return "\n".join(lines)
