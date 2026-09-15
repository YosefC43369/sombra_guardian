# -*- coding: utf-8 -*-
"""airports.py — ค้นหาสนามบินจากฐานข้อมูล resource/airports.json

ต่อยอดแนวทาง Elasticsearch เดิมของโปรเจกต์: ค้นข้อความจากฐานข้อมูลที่เรามีอยู่
(ไฟล์ airports.json) แล้วตอบชื่อ/เมือง/ประเทศ ฯลฯ

รองรับสคีมายอดนิยม (mwgg/Airports) — เป็น dict ที่คีย์ด้วยรหัส ICAO และแต่ละค่ามี
ฟิลด์ icao/iata/name/city/state/country/lat/lon/elevation/tz — แต่ยืดหยุ่นพอที่จะ
รับได้ทั้งแบบ dict-คีย์-ด้วยรหัส และแบบ list ของ object

ทำงานได้แม้ไม่มี Elasticsearch: ถ้าตั้งค่า ES ไว้จะค้นผ่าน ES (เร็ว/fuzzy) ถ้าไม่มี
ก็ค้นในหน่วยความจำจากไฟล์ตรง ๆ (search_airports) ซึ่งเป็น pure-python เทสต์ได้
"""

import os
import re
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("modbot.airports")

# ที่อยู่ไฟล์ฐานข้อมูลสนามบิน — override ได้ด้วย env AIRPORTS_DB
AIRPORTS_PATH = os.getenv("AIRPORTS_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource", "airports.json")

# ดัชนี Elasticsearch สำหรับสนามบิน (ใช้ client/คอนฟิกร่วมกับ osint_es)
ES_INDEX = os.getenv("AIRPORTS_ES_INDEX", "").strip() or "sombra_airports"

_cache = {"path": None, "mtime": None, "records": None}

# ---------- regex สำหรับ "สกัดข้อความ" ----------
_RE_IATA = re.compile(r"^[A-Za-z]{3}$")     # รหัส IATA 3 ตัว (เช่น BKK)
_RE_ICAO = re.compile(r"^[A-Za-z]{4}$")     # รหัส ICAO 4 ตัว (เช่น VTBS)
_RE_WS = re.compile(r"\s+")


# ---------------- โหลด + normalize ฐานข้อมูล ----------------

def _normalize(rec: dict, key: Optional[str] = None) -> Optional[dict]:
    """ทำระเบียนดิบจากไฟล์ให้อยู่ในรูปฟิลด์มาตรฐานเดียวกัน — คืน None ถ้าไม่มีข้อมูลพอ"""
    if not isinstance(rec, dict):
        return None
    def g(*names):
        for n in names:
            v = rec.get(n)
            if v not in (None, ""):
                return v
        return ""
    icao = str(g("icao", "ICAO", "ident") or (key or "")).strip().upper()
    iata = str(g("iata", "IATA", "iata_code")).strip().upper()
    name = str(g("name", "airport", "Name")).strip()
    city = str(g("city", "municipality", "City")).strip()
    country = str(g("country", "iso_country", "Country")).strip()
    state = str(g("state", "region", "State")).strip()
    if not (name or iata or icao):
        return None
    out = {
        "icao": icao, "iata": iata, "name": name, "city": city,
        "country": country, "state": state,
        "lat": g("lat", "latitude", "latitude_deg"),
        "lon": g("lon", "lng", "longitude", "longitude_deg"),
        "elevation": g("elevation", "elevation_ft", "alt"),
        "tz": g("tz", "timezone"),
    }
    return out


def load_airports(path: Optional[str] = None) -> List[dict]:
    """โหลดและ normalize ฐานข้อมูลสนามบิน (แคชตาม mtime) — คืน [] ถ้าไม่มีไฟล์/อ่านไม่ได้

    รองรับทั้ง dict (คีย์ = รหัสสนามบิน) และ list ของ object
    """
    target = path or AIRPORTS_PATH
    try:
        mtime = os.path.getmtime(target)
    except OSError:
        logger.warning("AIRPORTS | ไม่พบไฟล์ฐานข้อมูล: %s", target)
        return []
    if _cache["path"] == target and _cache["mtime"] == mtime:
        return _cache["records"] or []
    try:
        with open(target, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("AIRPORTS | อ่านไฟล์ไม่ได้ %s (%s)", target, e)
        return []

    records: List[dict] = []
    if isinstance(raw, dict):
        # เผื่อไฟล์ห่อด้วยคีย์ เช่น {"airports": {...}} หรือ {"airports": [...]}
        inner = raw.get("airports", raw) if "airports" in raw else raw
        if isinstance(inner, dict):
            for key, rec in inner.items():
                norm = _normalize(rec, key)
                if norm:
                    records.append(norm)
        elif isinstance(inner, list):
            for rec in inner:
                norm = _normalize(rec)
                if norm:
                    records.append(norm)
    elif isinstance(raw, list):
        for rec in raw:
            norm = _normalize(rec)
            if norm:
                records.append(norm)

    _cache.update(path=target, mtime=mtime, records=records)
    logger.info("AIRPORTS | โหลด %d สนามบินจาก %s", len(records), target)
    return records


def airports_count(path: Optional[str] = None) -> int:
    return len(load_airports(path))


# ---------------- สกัดข้อความ (extraction) ----------------

def extract_query(text: str) -> dict:
    """สกัดคำค้นของผู้ใช้ให้เป็นโครงสร้าง: ระบุว่าเป็นรหัส IATA/ICAO หรือชื่อ/เมือง

    คืน dict: {"raw", "value", "kind"} โดย kind ∈ {"iata","icao","text"}
    - "ALT", "bkk"        -> iata
    - "VTBS"              -> icao
    - "Suvarnabhumi", "กรุงเทพ" -> text
    """
    raw = str(text or "")
    value = _RE_WS.sub(" ", raw).strip()
    if _RE_IATA.match(value):
        return {"raw": raw, "value": value.upper(), "kind": "iata"}
    if _RE_ICAO.match(value):
        return {"raw": raw, "value": value.upper(), "kind": "icao"}
    return {"raw": raw, "value": value, "kind": "text"}


# ---------------- ค้นหาในหน่วยความจำ (fallback ไม่ต้องมี ES) ----------------

def _score(rec: dict, q: dict) -> int:
    """ให้คะแนนความเข้ากันของระเบียนกับคำค้น (มาก = ตรงกว่า) 0 = ไม่ตรง"""
    value = q["value"]
    low = value.lower()
    kind = q["kind"]
    icao = (rec.get("icao") or "").lower()
    iata = (rec.get("iata") or "").lower()
    name = (rec.get("name") or "").lower()
    city = (rec.get("city") or "").lower()

    # รหัสตรงเป๊ะ = คะแนนสูงสุด
    if kind == "iata" and iata and iata == low:
        return 100
    if kind == "icao" and icao and icao == low:
        return 100
    # เผื่อผู้ใช้พิมพ์รหัสแต่ไปตรงอีกระบบ (พิมพ์ IATA 3 ตัวแต่ตรง ICAO บางส่วน ฯลฯ)
    if low and (low == iata or low == icao):
        return 95

    if kind == "text":
        if name == low or city == low:
            return 90
        if name.startswith(low) or city.startswith(low):
            return 70
        if low in name or low in city:
            return 40
    return 0


def search_airports(records: List[dict], query: str, limit: int = 5) -> List[dict]:
    """ค้นสนามบินจากรายการที่โหลดไว้ (pure-python) — คืนระเบียนที่ตรงเรียงตามคะแนน"""
    q = extract_query(query)
    if not q["value"]:
        return []
    scored = []
    for rec in records or []:
        s = _score(rec, q)
        if s > 0:
            scored.append((s, rec))
    # คะแนนมากก่อน แล้วเรียงตามชื่อเพื่อผลคงที่
    scored.sort(key=lambda x: (-x[0], (x[1].get("name") or "").lower()))
    return [rec for _, rec in scored[: max(1, int(limit))]]


# ---------------- Elasticsearch (ทางเลือก, ใช้ client ร่วมกับ osint_es) ----------------

def _es_client():
    try:
        import osint_es
        return osint_es.get_client()
    except Exception:
        return None


def es_configured() -> bool:
    try:
        import osint_es
        return osint_es.es_configured()
    except Exception:
        return False


def reindex_es(path: Optional[str] = None) -> int:
    """ทำดัชนีสนามบินทั้งหมดลง Elasticsearch — คืนจำนวนที่ index สำเร็จ (0 ถ้าไม่มี ES)"""
    client = _es_client()
    if client is None:
        return 0
    records = load_airports(path)
    if not records:
        return 0
    try:
        if not client.indices.exists(index=ES_INDEX):
            client.indices.create(index=ES_INDEX, body={"mappings": {"properties": {
                "icao": {"type": "keyword"}, "iata": {"type": "keyword"},
                "name": {"type": "text"}, "city": {"type": "text"},
                "country": {"type": "keyword"}, "state": {"type": "text"},
            }}})
    except Exception as e:
        logger.warning("AIRPORTS ES | สร้าง index ไม่สำเร็จ (%s)", e)
        return 0
    ok = 0
    for rec in records:
        doc_id = rec.get("icao") or rec.get("iata") or rec.get("name")
        try:
            client.index(index=ES_INDEX, id=doc_id, document=rec)
            ok += 1
        except Exception as e:
            logger.debug("AIRPORTS ES | index %s ไม่สำเร็จ (%s)", doc_id, e)
    try:
        client.indices.refresh(index=ES_INDEX)
    except Exception:
        pass
    logger.info("AIRPORTS ES | ทำดัชนี %d สนามบิน", ok)
    return ok


def es_search(query: str, limit: int = 5) -> Optional[List[dict]]:
    """ค้นสนามบินผ่าน Elasticsearch — คืน list ระเบียน หรือ None ถ้า ES ใช้ไม่ได้
    (ให้ผู้เรียก fallback ไป search_airports)"""
    client = _es_client()
    if client is None:
        return None
    q = extract_query(query)
    if not q["value"]:
        return []
    if q["kind"] in ("iata", "icao"):
        body = {"size": limit, "query": {"bool": {"should": [
            {"term": {"iata": q["value"]}}, {"term": {"icao": q["value"]}},
        ], "minimum_should_match": 1}}}
    else:
        body = {"size": limit, "query": {"multi_match": {
            "query": q["value"], "fields": ["name^2", "city", "state", "country"],
            "type": "best_fields", "fuzziness": "AUTO",
        }}}
    try:
        resp = client.search(index=ES_INDEX, body=body)
    except Exception as e:
        logger.debug("AIRPORTS ES | ค้นไม่สำเร็จ (%s) — fallback", e)
        return None
    return [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]


# ---------------- จัดข้อความตอบกลับ ----------------

def format_airport(rec: dict) -> str:
    """จัดรายละเอียดสนามบิน 1 แห่งเป็นข้อความ (ชื่อ/เมือง/ประเทศ + รหัส/พิกัด)"""
    def line(emoji, label, value):
        return f"{emoji} {label}: {value}" if value not in (None, "") else None
    codes = " / ".join(c for c in [rec.get("iata"), rec.get("icao")] if c)
    parts = [
        line("🛫", "ชื่อ", rec.get("name")),
        line("🏙️", "เมือง", rec.get("city")),
        line("🌏", "ประเทศ", rec.get("country")),
        line("🗺️", "รัฐ/ภูมิภาค", rec.get("state")),
        line("🔖", "รหัส (IATA/ICAO)", codes),
    ]
    latlon = ""
    if rec.get("lat") not in (None, "") and rec.get("lon") not in (None, ""):
        latlon = f"{rec.get('lat')}, {rec.get('lon')}"
    parts.append(line("📍", "พิกัด", latlon))
    parts.append(line("🕓", "โซนเวลา", rec.get("tz")))
    return "\n".join(p for p in parts if p)


def format_results(hits: List[dict], query: str, via: str = "") -> str:
    """จัดข้อความผลค้นสนามบินสำหรับ Telegram"""
    backend = f" (ผ่าน {via})" if via else ""
    if not hits:
        return (f"🔍 ค้นสนามบิน: ไม่พบข้อมูลที่ตรงกับ “{query}”{backend}\n"
                "ลองพิมพ์รหัส IATA (เช่น BKK), ICAO (เช่น VTBS) หรือชื่อ/เมือง")
    if len(hits) == 1:
        return "🔍 ผลการค้นสนามบิน" + backend + "\n\n" + format_airport(hits[0])
    lines = [f"🔍 พบ {len(hits)} สนามบินที่ตรงกับ “{query}”{backend}", ""]
    for i, rec in enumerate(hits, start=1):
        codes = " / ".join(c for c in [rec.get("iata"), rec.get("icao")] if c)
        loc = ", ".join(x for x in [rec.get("city"), rec.get("country")] if x)
        lines.append(f"{i}. 🛫 {rec.get('name') or '-'}"
                     + (f" [{codes}]" if codes else "")
                     + (f" — {loc}" if loc else ""))
    lines.append("")
    lines.append("พิมพ์รหัสให้เจาะจงขึ้น (เช่น BKK) เพื่อดูรายละเอียดสนามบินเดียว")
    return "\n".join(lines)
