# -*- coding: utf-8 -*-
"""osint_es.py — ชั้นค้นหา/ทำดัชนีด้วย Elasticsearch สำหรับ "ฐานข้อมูลผลค้น OSINT
ที่ยืนยันแล้ว" (osint_db)

ขอบเขตโดยเจตนา
--------------
โมดูลนี้ *ไม่* ดึงข้อมูลใหม่จากที่ไหนทั้งสิ้น มันทำงานกับ "ระเบียนที่ Admin กดยืนยัน
บันทึกแล้ว" ใน osint_db เท่านั้น — คือเอา Elasticsearch มาเป็น backend การค้นหา
ย้อนหลังให้กับสิ่งที่ /search เคยเจอและถูกยืนยันไว้ (ต่อยอดการค้นหาของ OSINT เดิม)

ออกแบบให้ "ทำงานได้แม้ไม่มี Elasticsearch":
  - ถ้าไม่ได้ตั้งค่า OSINT_ES_URL หรือไม่ได้ติดตั้งไลบรารี elasticsearch -> ปิดเงียบ
  - ผู้เรียก (app.py) มี fallback ค้นในไฟล์ JSON ตรง ๆ ผ่าน local_search() ซึ่งเป็น
    ฟังก์ชัน pure-python เทสต์ได้โดยไม่ต้องมี ES จริง

การเข้าถึง: เรียกจากเส้นทางที่ผ่าน Admin แล้วใน app.py เท่านั้น (เหมือน osint_db)
"""

import os
import logging
from typing import Dict, List, Optional

import osint

logger = logging.getLogger("modbot.osint_es")

# ---------------- การตั้งค่า (ผ่าน env) ----------------
# ว่าง = ปิดการใช้ Elasticsearch (ใช้ fallback ค้นในไฟล์ JSON แทน)
ES_URL = os.getenv("OSINT_ES_URL", "").strip()
ES_API_KEY = os.getenv("OSINT_ES_API_KEY", "").strip()
ES_USERNAME = os.getenv("OSINT_ES_USERNAME", "").strip()
ES_PASSWORD = os.getenv("OSINT_ES_PASSWORD", "").strip()
ES_INDEX = os.getenv("OSINT_ES_INDEX", "sombra_osint_findings").strip() or "sombra_osint_findings"
# ยืนยัน TLS cert (ตั้ง 0 เพื่อปิดเฉพาะตอนทดสอบกับ ES self-signed ภายใน)
ES_VERIFY_CERTS = os.getenv("OSINT_ES_VERIFY_CERTS", "1").strip().lower() not in (
    "0", "false", "no", "off")

_client = None
_client_tried = False


def es_configured() -> bool:
    """ตั้งค่า Elasticsearch ไว้หรือยัง (มี URL) — ยังไม่ได้แปลว่าต่อติด"""
    return bool(ES_URL)


def _import_es():
    """import ไลบรารี elasticsearch แบบไม่ล้มถ้าไม่มี — คืน module หรือ None"""
    try:
        import elasticsearch  # type: ignore
        return elasticsearch
    except Exception:
        return None


def get_client():
    """สร้าง/แคช Elasticsearch client — คืน None ถ้าปิดใช้/ไลบรารีไม่มี/ต่อไม่ติด

    เก็บผลไว้ (รวมถึงกรณี None) เพื่อไม่ให้พยายามต่อซ้ำทุกครั้งที่ค้น
    """
    global _client, _client_tried
    if _client_tried:
        return _client
    _client_tried = True

    if not es_configured():
        return None
    es = _import_es()
    if es is None:
        logger.warning("OSINT ES | ตั้งค่า OSINT_ES_URL ไว้แต่ไม่ได้ติดตั้งไลบรารี "
                       "elasticsearch (pip install elasticsearch) — ปิดการใช้ ES")
        return None

    kwargs: Dict[str, object] = {"verify_certs": ES_VERIFY_CERTS}
    if ES_API_KEY:
        kwargs["api_key"] = ES_API_KEY
    elif ES_USERNAME:
        kwargs["basic_auth"] = (ES_USERNAME, ES_PASSWORD)
    try:
        client = es.Elasticsearch(ES_URL, **kwargs)
        # ping เพื่อยืนยันว่าต่อได้จริงก่อนใช้งาน
        if not client.ping():
            logger.warning("OSINT ES | ping %s ไม่สำเร็จ — ปิดการใช้ ES", ES_URL)
            return None
        _client = client
        logger.info("OSINT ES | เชื่อมต่อ %s (index=%s) สำเร็จ", ES_URL, ES_INDEX)
    except Exception as e:
        logger.warning("OSINT ES | เชื่อมต่อ %s ไม่สำเร็จ (%s) — ปิดการใช้ ES", ES_URL, e)
        _client = None
    return _client


def es_available() -> bool:
    """ต่อ Elasticsearch ได้จริงไหม (ใช้ตัดสินใจระหว่าง ES กับ fallback)"""
    return get_client() is not None


# ---------------- แปลงระเบียน -> เอกสารสำหรับค้นหา ----------------

def to_document(record: dict) -> dict:
    """แผ่ระเบียน osint_db ให้เป็นเอกสาร flat ที่ค้น full-text ได้

    รวมชื่อเรื่อง/ลิงก์/คำโปรยของทุกแหล่ง และค่าตัวระบุทุกชนิดไว้ในฟิลด์ค้นหา
    """
    categories = record.get("categories", {}) or {}
    identifiers = record.get("identifiers", {}) or {}

    titles, urls, snippets, hosts = [], [], [], []
    for cat in categories.values():
        for src in cat.get("sources", []) or []:
            if src.get("title"):
                titles.append(str(src["title"]))
            if src.get("url"):
                urls.append(str(src["url"]))
            if src.get("host"):
                hosts.append(str(src["host"]))
            if src.get("snippet"):
                snippets.append(str(src["snippet"]))

    ident_values: List[str] = []
    ident_types: List[str] = []
    for ioc_type, slot in identifiers.items():
        ident_types.append(ioc_type)
        for v in slot.get("values", []) or []:
            if v.get("value"):
                ident_values.append(str(v["value"]))

    return {
        "id": record.get("id"),
        "query": record.get("query", ""),
        "selector": record.get("selector", ""),
        "saved_at": record.get("saved_at"),
        "saved_by": record.get("saved_by"),
        "origins": list(categories.keys()),
        "ioc_types": ident_types,
        "identifiers": ident_values,
        "titles": titles,
        "urls": urls,
        "hosts": hosts,
        "snippets": snippets,
        # ฟิลด์รวมสำหรับค้น full-text ทีเดียว
        "text": " \n".join([record.get("query", "")] + titles + snippets
                           + ident_values + urls),
        "stats": record.get("stats", {}),
    }


_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "query": {"type": "text"},
            "selector": {"type": "text"},
            "saved_at": {"type": "date"},
            "saved_by": {"type": "long"},
            "origins": {"type": "keyword"},
            "ioc_types": {"type": "keyword"},
            "identifiers": {"type": "keyword"},
            "hosts": {"type": "keyword"},
            "titles": {"type": "text"},
            "urls": {"type": "text"},
            "snippets": {"type": "text"},
            "text": {"type": "text"},
        }
    }
}


def ensure_index(client=None) -> bool:
    """สร้าง index พร้อม mapping ถ้ายังไม่มี — คืน True เมื่อพร้อมใช้"""
    client = client or get_client()
    if client is None:
        return False
    try:
        if not client.indices.exists(index=ES_INDEX):
            client.indices.create(index=ES_INDEX, body=_INDEX_MAPPING)
            logger.info("OSINT ES | สร้าง index %s", ES_INDEX)
        return True
    except Exception as e:
        logger.warning("OSINT ES | สร้าง/ตรวจ index %s ไม่สำเร็จ (%s)", ES_INDEX, e)
        return False


def index_finding(record: dict) -> bool:
    """ทำดัชนีระเบียนที่ยืนยันแล้ว 1 รายการ (best-effort) — คืน True เมื่อสำเร็จ

    ใช้ id ของระเบียนเป็น _id เพื่อให้ index ซ้ำ = อัปเดต ไม่เกิดซ้ำ
    """
    client = get_client()
    if client is None:
        return False
    if not ensure_index(client):
        return False
    try:
        client.index(index=ES_INDEX, id=record.get("id"), document=to_document(record))
        return True
    except Exception as e:
        logger.warning("OSINT ES | index ระเบียน %s ไม่สำเร็จ (%s)", record.get("id"), e)
        return False


def reindex_all(records: List[dict]) -> int:
    """ทำดัชนีใหม่ทั้งหมดจากรายการระเบียน osint_db — คืนจำนวนที่สำเร็จ"""
    client = get_client()
    if client is None or not ensure_index(client):
        return 0
    ok = 0
    for rec in records or []:
        try:
            client.index(index=ES_INDEX, id=rec.get("id"), document=to_document(rec))
            ok += 1
        except Exception as e:
            logger.warning("OSINT ES | reindex %s ไม่สำเร็จ (%s)", rec.get("id"), e)
    try:
        client.indices.refresh(index=ES_INDEX)
    except Exception:
        pass
    return ok


def search(query_text: str, limit: int = 10) -> Optional[List[dict]]:
    """ค้นระเบียนที่ทำดัชนีไว้ด้วย Elasticsearch — คืน list ของ hit หรือ None ถ้า ES
    ใช้ไม่ได้ (ให้ผู้เรียก fallback ไป local_search)

    hit แต่ละตัว: {id, query, saved_at, score, identifiers, hosts, urls}
    """
    client = get_client()
    if client is None:
        return None
    q = str(query_text or "").strip()
    if not q:
        return []
    body = {
        "size": max(1, int(limit)),
        "query": {
            "multi_match": {
                "query": q,
                "fields": ["text", "query^2", "identifiers^3", "hosts^2",
                           "titles", "urls", "snippets"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        },
    }
    try:
        resp = client.search(index=ES_INDEX, body=body)
    except Exception as e:
        logger.warning("OSINT ES | ค้นหาไม่สำเร็จ (%s) — ให้ผู้เรียก fallback", e)
        return None
    hits = []
    for h in resp.get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        hits.append({
            "id": src.get("id"),
            "query": src.get("query"),
            "saved_at": src.get("saved_at"),
            "score": h.get("_score"),
            "identifiers": src.get("identifiers", []),
            "hosts": src.get("hosts", []),
            "urls": src.get("urls", []),
            "origins": src.get("origins", []),
        })
    return hits


# ---------------- Fallback: ค้นในไฟล์ JSON ตรง ๆ (ไม่ต้องมี ES) ----------------

def local_search(records: List[dict], query_text: str, limit: int = 10) -> List[dict]:
    """ค้นระเบียน osint_db แบบ pure-python (ใช้เมื่อไม่มี Elasticsearch)

    ให้คะแนนแบบง่าย: นับจำนวนโทเคนของคำค้นที่ปรากฏใน blob ของแต่ละระเบียน
    (query + ชื่อเรื่อง + คำโปรย + ตัวระบุ + โฮสต์ + ลิงก์) เรียงมาก->น้อย
    เทสต์ได้โดยไม่ต้องมี ES จริง และให้รูปผลลัพธ์เหมือน search()
    """
    tokens = [t for t in str(query_text or "").lower().split() if t]
    if not tokens:
        return []
    scored = []
    for rec in records or []:
        doc = to_document(rec)
        blob = " ".join([
            str(doc.get("query", "")),
            " ".join(doc.get("titles", [])),
            " ".join(doc.get("snippets", [])),
            " ".join(doc.get("identifiers", [])),
            " ".join(doc.get("hosts", [])),
            " ".join(doc.get("urls", [])),
        ]).lower()
        score = sum(blob.count(tok) for tok in tokens)
        if score <= 0:
            continue
        scored.append((score, doc))
    scored.sort(key=lambda x: (-x[0], str(x[1].get("saved_at") or "")))
    out = []
    for score, doc in scored[: max(1, int(limit))]:
        out.append({
            "id": doc.get("id"),
            "query": doc.get("query"),
            "saved_at": doc.get("saved_at"),
            "score": score,
            "identifiers": doc.get("identifiers", []),
            "hosts": doc.get("hosts", []),
            "urls": doc.get("urls", []),
            "origins": doc.get("origins", []),
        })
    return out


def format_search_hits(hits: List[dict], query_text: str, via: str = "") -> str:
    """จัดข้อความผลค้นฐานข้อมูล OSINT สำหรับส่งกลับผู้ใช้ (Telegram)"""
    backend = f" (ผ่าน {via})" if via else ""
    if not hits:
        return (f"🔍 ค้นฐานข้อมูล OSINT: ไม่พบระเบียนที่ตรงกับ “{query_text}”{backend}\n"
                "บันทึกผลจาก /search ก่อน แล้วค่อยค้นย้อนหลังได้")
    lines = [f"🔍 ผลค้นฐานข้อมูล OSINT: “{query_text}” — พบ {len(hits)} ระเบียน{backend}", ""]
    for i, h in enumerate(hits, start=1):
        origins = ", ".join(h.get("origins", []) or []) or "-"
        lines.append(f"{i}. 🆔 {h.get('id')} · 🔎 {h.get('query', '-')}")
        lines.append(f"      🗓️ {h.get('saved_at', '-')} · 📂 {origins} · 🎯 score {h.get('score')}")
        idents = h.get("identifiers", []) or []
        if idents:
            shown = ", ".join(idents[:6])
            more = f" (+{len(idents) - 6})" if len(idents) > 6 else ""
            lines.append(f"      🔗 ตัวระบุ: {shown}{more}")
    return "\n".join(lines)


# ---------------- สถิติ/วิเคราะห์ฐานข้อมูลผลที่ยืนยันแล้ว ----------------

def aggregate_findings(records: List[dict]) -> dict:
    """สรุปสถิติภาพรวมของ "ระเบียนผลค้นที่ยืนยันแล้ว" (osint_db)

    ใช้ osint.summarize_findings (บริสุทธิ์ stdlib) เป็นแกน จึงทำงานได้แม้ไม่มี
    Elasticsearch — ถือเป็นการต่อยอด ES ฝั่งวิเคราะห์: เมื่อมี ES จะ index/ค้นเร็ว
    ส่วนสถิติรวบยอดคำนวณจากคลังเดียวกันได้ทันทีไม่ว่าจะมี ES หรือไม่
    """
    return osint.summarize_findings(records)


def format_findings_stats(summary: dict, es_on: bool = False) -> str:
    """จัดข้อความสถิติฐานข้อมูล OSINT สำหรับ Telegram (/dbstats)"""
    total = summary.get("total", 0)
    if not total:
        return ("📊 ฐานข้อมูล OSINT ยังว่าง — ยังไม่มีระเบียนที่ยืนยันบันทึก\n"
                "ใช้ /search แล้วกดปุ่มบันทึกเพื่อเริ่มสะสมข้อมูล")
    lines = [f"📊 สถิติฐานข้อมูล OSINT — {total} ระเบียน"]
    latest = summary.get("latest_saved_at")
    if latest:
        lines.append(f"   🗓️ บันทึกล่าสุด: {latest}")

    by_origin = summary.get("by_origin", {})
    if by_origin:
        parts = []
        for origin, count in sorted(by_origin.items(), key=lambda kv: -kv[1]):
            meta = osint.origin_meta(origin)
            parts.append(f"{meta['emoji']} {meta['label']} {count}")
        lines.append("   📂 แหล่งสะสม: " + "  ".join(parts))

    by_ioc = summary.get("by_ioc_type", {})
    if by_ioc:
        lines.append(f"   🔗 ตัวระบุยืนยันข้ามแหล่ง: {summary.get('corroborated_total', 0)} ค่า")
        for ioc_type, count in by_ioc.items():
            label = osint.IOC_LABELS.get(ioc_type, ioc_type)
            lines.append(f"      {osint.ioc_emoji(ioc_type)} {label}: {count}")

    top_hosts = summary.get("top_hosts", [])
    if top_hosts:
        lines.append("   🌐 โฮสต์ที่พบบ่อย:")
        for host, count in top_hosts[:5]:
            lines.append(f"      • {host} ({count})")

    lines.append("   ⚙️ backend: " + ("Elasticsearch + ไฟล์ JSON" if es_on else "ไฟล์ JSON"))
    return "\n".join(lines)
