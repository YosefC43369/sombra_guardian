# -*- coding: utf-8 -*-
"""search_es.py — Telemetry/สุขภาพการค้นหา ลง Elasticsearch (ต่อยอด search.py)

ขอบเขตโดยเจตนา (เส้นความปลอดภัย)
-------------------------------
โมดูลนี้บันทึกเฉพาะ "เมทาดาทาของการค้นหา" ลง Elasticsearch เพื่อดูประสิทธิภาพ/
สุขภาพของ engine เท่านั้น — **ไม่เก็บเนื้อหาผลค้น ไม่เก็บชื่อเรื่อง/คำโปรย/ลิงก์/PII**
จึงไม่กลายเป็น "คลังผลค้นดิบที่ค้นได้ถาวร" (ซึ่งเป็นสิ่งที่ระบบนี้จงใจไม่ทำ)

ค่าที่เก็บต่อการค้น 1 ครั้ง:
  - เวลา, จำนวนผลรวม, เวลาที่ใช้ (ms), มาจาก cache ไหม
  - จำนวนผลแยกตามฝั่ง (clearnet/darkweb/username) — เป็นตัวเลขนับ ไม่ใช่เนื้อหา
  - รายชื่อ engine ที่ยิงในรอบนั้น (ชื่อ engine ไม่ใช่ผลลัพธ์)
  - คำค้น: เก็บเป็น "แฮช" โดยดีฟอลต์ (กันเผลอเก็บชื่อ/อีเมลเป้าหมายเป็น PII)
    ตั้ง env OSINT_ES_STORE_RAW_QUERY=1 ถ้าต้องการเก็บคำค้นดิบ (ผู้ดูแลเลือกเอง)

ใช้ client/คอนฟิกร่วมกับ osint_es (คลัสเตอร์เดียว คนละ index) และทำงานแบบ
best-effort ไม่บล็อก hot path ของการค้นหา — ถ้าไม่ตั้งค่า ES ไว้ก็เป็น no-op
"""

import os
import time
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

import osint_es

logger = logging.getLogger("modbot.search_es")

TELEMETRY_INDEX = os.getenv("OSINT_ES_TELEMETRY_INDEX", "").strip() or "sombra_search_telemetry"
# เก็บคำค้นดิบไหม (ดีฟอลต์: ไม่ เก็บเป็นแฮชเพื่อกัน PII ของเป้าหมายค้นหา)
STORE_RAW_QUERY = os.getenv("OSINT_ES_STORE_RAW_QUERY", "").strip().lower() in (
    "1", "true", "yes", "on")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _query_hash(query: str) -> str:
    return hashlib.sha256(str(query or "").strip().lower().encode("utf-8", "replace")).hexdigest()


def telemetry_doc(query: str, origin_counts: Optional[Dict[str, int]], total: int,
                  elapsed_ms: float, cache_hit: bool = False,
                  tor_reachable: Optional[bool] = None,
                  engines: Optional[List[str]] = None) -> dict:
    """ประกอบเอกสาร telemetry (เมทาดาทาล้วน) — แยกออกมาเพื่อให้เทสต์ได้โดยไม่ต้องมี ES"""
    doc = {
        "ts": _now_iso(),
        "total": int(total or 0),
        "elapsed_ms": int(max(0, elapsed_ms)),
        "cache_hit": bool(cache_hit),
        "origin_counts": {str(k): int(v) for k, v in (origin_counts or {}).items()},
        "engines": list(engines or []),
        "query_hash": _query_hash(query),
    }
    if tor_reachable is not None:
        doc["tor_reachable"] = bool(tor_reachable)
    if STORE_RAW_QUERY:
        doc["query"] = str(query or "")[:200]
    return doc


def _index_doc(doc: dict) -> None:
    """เขียนเอกสาร telemetry (รันในเธรดพื้นหลัง) — best-effort ปิดเงียบเมื่อ ES ล่ม"""
    client = osint_es.get_client()
    if client is None:
        return
    try:
        client.index(index=TELEMETRY_INDEX, document=doc)
    except Exception as e:
        logger.debug("SEARCH ES | index telemetry ไม่สำเร็จ (%s)", e)


def record_search(query: str, origin_counts: Optional[Dict[str, int]] = None,
                  total: int = 0, elapsed_ms: float = 0.0, cache_hit: bool = False,
                  tor_reachable: Optional[bool] = None,
                  engines: Optional[List[str]] = None) -> bool:
    """บันทึก telemetry ของการค้น 1 ครั้ง แบบ non-blocking (คืน True ถ้าส่งเข้าคิว)

    ปลอดภัยที่จะเรียกใน hot path ของ search.py: ถ้าไม่ได้ตั้งค่า ES ไว้ (ดีฟอลต์)
    จะคืนทันทีด้วยการเช็ก bool ราคาถูก ไม่มีการเชื่อมต่อใด ๆ
    """
    if not osint_es.es_configured():
        return False
    try:
        doc = telemetry_doc(query, origin_counts, total, elapsed_ms,
                            cache_hit=cache_hit, tor_reachable=tor_reachable,
                            engines=engines)
        threading.Thread(target=_index_doc, args=(doc,), daemon=True).start()
        return True
    except Exception as e:
        logger.debug("SEARCH ES | record_search ข้าม (%s)", e)
        return False


def engine_health(days: int = 7) -> Optional[dict]:
    """สรุปสุขภาพการค้นหาจาก telemetry ที่เก็บไว้ (ต้องมี ES) — คืน None ถ้าไม่มี ES

    คืน dict: {searches, avg_elapsed_ms, cache_hit_rate, by_engine{engine:count},
              window_days}
    """
    client = osint_es.get_client()
    if client is None:
        return None
    body = {
        "size": 0,
        "query": {"range": {"ts": {"gte": f"now-{max(1, int(days))}d"}}},
        "aggs": {
            "avg_elapsed": {"avg": {"field": "elapsed_ms"}},
            "cache_hits": {"terms": {"field": "cache_hit"}},
            "engines": {"terms": {"field": "engines", "size": 20}},
        },
    }
    try:
        resp = client.search(index=TELEMETRY_INDEX, body=body)
    except Exception as e:
        logger.debug("SEARCH ES | engine_health ค้นไม่สำเร็จ (%s)", e)
        return None
    aggs = resp.get("aggregations", {})
    total = resp.get("hits", {}).get("total", {})
    searches = total.get("value", 0) if isinstance(total, dict) else total
    cache_true = 0
    for b in aggs.get("cache_hits", {}).get("buckets", []):
        if b.get("key_as_string") == "true" or b.get("key") in (1, True):
            cache_true = b.get("doc_count", 0)
    by_engine = {b["key"]: b["doc_count"]
                 for b in aggs.get("engines", {}).get("buckets", [])}
    return {
        "searches": searches,
        "avg_elapsed_ms": round((aggs.get("avg_elapsed", {}).get("value") or 0), 1),
        "cache_hit_rate": round(cache_true / searches, 3) if searches else 0.0,
        "by_engine": by_engine,
        "window_days": int(days),
    }


def format_engine_health(health: Optional[dict]) -> str:
    """จัดข้อความสรุปสุขภาพการค้นหาสำหรับ Telegram"""
    if not health:
        return ""
    lines = [
        f"📈 สุขภาพการค้นหา ({health.get('window_days', 7)} วันล่าสุด)",
        f"   🔎 ค้นทั้งหมด: {health.get('searches', 0)} ครั้ง",
        f"   ⏱️ เฉลี่ย: {health.get('avg_elapsed_ms', 0)} ms · "
        f"⚡ cache hit: {round(health.get('cache_hit_rate', 0) * 100)}%",
    ]
    by_engine = health.get("by_engine", {})
    if by_engine:
        top = sorted(by_engine.items(), key=lambda kv: -kv[1])[:8]
        lines.append("   🔧 engine ที่ใช้บ่อย: "
                     + ", ".join(f"{k}({v})" for k, v in top))
    return "\n".join(lines)
