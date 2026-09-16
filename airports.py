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
import unicodedata
from difflib import SequenceMatcher
from typing import Dict, List, Optional

logger = logging.getLogger("modbot.airports")

# ที่อยู่ไฟล์ฐานข้อมูลสนามบิน — override ได้ด้วย env AIRPORTS_DB
AIRPORTS_PATH = os.getenv("AIRPORTS_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource", "airports.json")


def _resolve_source_path() -> str:
    """หา path ของไฟล์ airports.json ที่จะเปิดอ่าน

    ถ้าตั้งค่า Google Drive ไว้ (reference_data) จะได้ path ของ cache ที่ซิงก์จาก
    Drive มาแล้ว (source of truth บน Drive) มิฉะนั้นถอยไปใช้ไฟล์ในเครื่อง AIRPORTS_PATH
    ตามพฤติกรรมเดิมทุกประการ — import แบบกันพังเพื่อไม่ให้ airports.py พึ่ง reference_data
    """
    if os.getenv("AIRPORTS_DB", "").strip():
        return AIRPORTS_PATH   # ผู้ใช้ override path ตรง ๆ = เคารพเสมอ ไม่ผ่าน Drive
    try:
        import reference_data
        resolved = reference_data.get_dataset_path("airports.json")
        if resolved:
            return resolved
    except Exception:
        logger.debug("AIRPORTS | reference_data ใช้ไม่ได้ ใช้ไฟล์ในเครื่องแทน")
    return AIRPORTS_PATH

# ดัชนี Elasticsearch สำหรับสนามบิน (ใช้ client/คอนฟิกร่วมกับ osint_es)
ES_INDEX = os.getenv("AIRPORTS_ES_INDEX", "").strip() or "sombra_airports"

# เพดานจำนวนระเบียนที่จะยอมทำ fuzzy (กันไฟล์ใหญ่มากช้าเกินไป) และเกณฑ์ความคล้าย
FUZZY_MAX_RECORDS = int(os.getenv("AIRPORTS_FUZZY_MAX", "60000") or "60000")
FUZZY_MIN_RATIO = float(os.getenv("AIRPORTS_FUZZY_MIN_RATIO", "0.72") or "0.72")

_cache = {"path": None, "mtime": None, "records": None}
# ดัชนีค้นหาในหน่วยความจำ (สร้างครั้งเดียวต่อชุดข้อมูล เพื่อความไว)
_index_cache = {"key": None, "index": None}

# ---------- regex สำหรับ "สกัดข้อความ" ----------
_RE_IATA = re.compile(r"^[A-Za-z]{3}$")     # รหัส IATA 3 ตัว (เช่น BKK)
_RE_ICAO = re.compile(r"^[A-Za-z]{4}$")     # รหัส ICAO 4 ตัว (เช่น VTBS)
_RE_WS = re.compile(r"\s+")
_RE_TOKEN = re.compile(r"[a-z0-9]+")


def _deaccent(text: str) -> str:
    """ตัดเครื่องหมายกำกับเสียง (accent/diacritic) ออก เพื่อให้ "Suárez"≈"Suarez\""""
    if not text:
        return ""
    nfkd = unicodedata.normalize("NFKD", str(text))
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _norm(text: str) -> str:
    """normalize สำหรับเทียบข้อความ: ตัด accent + lowercase + ยุบช่องว่าง"""
    return _RE_WS.sub(" ", _deaccent(text)).strip().lower()


def _tokenize(text: str) -> List[str]:
    """ตัดคำเป็นโทเคน a-z0-9 หลัง normalize (ใช้จับคำแยกในชื่อ/เมือง)"""
    return _RE_TOKEN.findall(_norm(text))


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
    icao = str(g("icao", "ICAO", "ident")).strip().upper()
    iata = str(g("iata", "IATA", "iata_code")).strip().upper()
    # ฟิลด์ "code" แบบทั่วไป (บางไฟล์ใช้ code เดี่ยว ๆ ไม่แยก iata/icao) รวมถึงคีย์ dict
    code = str(g("code", "Code") or (key or "")).strip().upper()
    # เดารหัสตามความยาวถ้ายังไม่มี iata/icao ชัดเจน (3 ตัว = IATA, 4 ตัว = ICAO)
    if not iata and len(code) == 3:
        iata = code
    if not icao and len(code) == 4:
        icao = code
    name = str(g("name", "airport", "Name")).strip()
    city = str(g("city", "municipality", "City")).strip()
    country = str(g("country", "iso_country", "Country")).strip()
    state = str(g("state", "region", "State")).strip()
    if not (name or iata or icao or code):
        return None
    out = {
        "icao": icao, "iata": iata, "code": code or iata or icao,
        "name": name, "city": city, "country": country, "state": state,
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
    target = path or _resolve_source_path()
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


# ---------------- ดัชนีค้นหาในหน่วยความจำ (fallback ไม่ต้องมี ES) ----------------

def _build_index(records: List[dict]) -> dict:
    """สร้างดัชนีค้นหา: precompute ชื่อ/เมือง normalize + โทเคน + รหัส และ map รหัส->ระเบียน
    เพื่อให้ค้นซ้ำ ๆ ไว (ไม่ต้อง normalize ใหม่ทุกครั้ง) — ไม่แก้ไขระเบียนเดิม"""
    entries = []
    by_code: Dict[str, dict] = {}
    for rec in records or []:
        codes = {c.lower() for c in (rec.get("iata"), rec.get("icao"), rec.get("code")) if c}
        name_n = _norm(rec.get("name"))
        city_n = _norm(rec.get("city"))
        entries.append({
            "rec": rec, "codes": codes, "name_n": name_n, "city_n": city_n,
            "country_n": _norm(rec.get("country")),
            "tokens": set(_tokenize(rec.get("name")) + _tokenize(rec.get("city"))),
        })
        for c in codes:
            by_code.setdefault(c, rec)
    return {"entries": entries, "by_code": by_code, "n": len(entries)}


def _get_index(records: List[dict]) -> dict:
    """คืนดัชนีของชุดข้อมูลนี้ (แคชไว้ตาม identity+ขนาด เพื่อไม่สร้างซ้ำทุกครั้ง)"""
    key = (id(records), len(records or []))
    if _index_cache["key"] == key and _index_cache["index"] is not None:
        return _index_cache["index"]
    index = _build_index(records or [])
    _index_cache.update(key=key, index=index)
    return index


def _text_score(e: dict, qn: str, qtokens: List[str], allow_fuzzy: bool) -> int:
    """ให้คะแนนความเข้ากันของ 'ชื่อ/เมือง' กับคำค้นที่ normalize แล้ว (0 = ไม่ตรง)

    ไล่จากตรงที่สุดไปหลวมสุด: ตรงเป๊ะ > ขึ้นต้น > ทุกโทเคนขึ้นต้นตรง > substring > fuzzy
    """
    name, city = e["name_n"], e["city_n"]
    if not qn:
        return 0
    if qn == name or qn == city:
        return 96
    if name.startswith(qn) or city.startswith(qn):
        return 82
    # ทุกโทเคนของคำค้นต้องมีคำในชื่อ/เมืองที่ "ขึ้นต้นตรง" (เช่น "los ang" -> Los Angeles)
    if qtokens:
        toks = e["tokens"]
        if all(any(tok == t or tok.startswith(t) for tok in toks) for t in qtokens):
            return 68
    if qn in name or qn in city:
        return 52
    if allow_fuzzy and len(qn) >= 4:
        ratio = max(SequenceMatcher(None, qn, name).ratio(),
                    SequenceMatcher(None, qn, city).ratio())
        # เทียบกับโทเคนเดี่ยว ๆ ด้วย เผื่อชื่อยาว (เช่น "…Airport") ทำให้ ratio รวมต่ำ
        # จำกัดเฉพาะโทเคนที่ยาวใกล้เคียงคำค้น เพื่อไม่ให้เสียเวลาโดยเปล่าประโยชน์
        for tok in e["tokens"]:
            if abs(len(tok) - len(qn)) <= 3:
                ratio = max(ratio, SequenceMatcher(None, qn, tok).ratio())
        if ratio >= FUZZY_MIN_RATIO:
            return int(35 + ratio * 20)   # ~49..55 (สะกดผิดเล็กน้อยยังเจอ)
    return 0


def search_airports(records: List[dict], query: str, limit: int = 5) -> List[dict]:
    """ค้นสนามบินจากรายการที่โหลดไว้ (pure-python) — คืนระเบียนที่ตรงเรียงตามคะแนน

    รองรับ: รหัสตรงเป๊ะ (IATA/ICAO/code), รหัสขึ้นต้น (BK->BKK), ชื่อ/เมืองตรง/ขึ้นต้น/
    ตรงเป็นคำ, substring และ fuzzy (สะกดผิดเล็กน้อย เช่น "Suvarnabumi") — ตัด accent ให้
    อัตโนมัติ ("Suarez"≈"Suárez")
    """
    val = extract_query(query)["value"]
    if not val:
        return []
    index = _get_index(records)
    qn = _norm(val)
    qtokens = _tokenize(val)
    allow_fuzzy = index["n"] <= FUZZY_MAX_RECORDS

    scored = []
    for e in index["entries"]:
        codes = e["codes"]
        if qn in codes:
            s = 100                                   # รหัสตรงเป๊ะ
        elif len(qn) >= 2 and any(c.startswith(qn) for c in codes):
            s = 88                                    # รหัสขึ้นต้น (BK -> BKK)
        else:
            s = _text_score(e, qn, qtokens, allow_fuzzy)
        if s > 0:
            scored.append((s, e["name_n"], e["rec"]))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [rec for _, _, rec in scored[: max(1, int(limit))]]


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
    """ทำดัชนีสนามบินลง Elasticsearch — คืนจำนวนที่ index สำเร็จ (0 ถ้าไม่มี ES)

    ต่อยอดผ่านชั้นค้นหากลาง reference_data.search_index (bulk + analyzer autocomplete/
    folding/code-normalizer) โดยส่ง "record ที่ normalize แล้ว" ของสนามบินเข้าไป index
    """
    records = load_airports(path)
    if not records:
        return 0
    try:
        from reference_data import search_index
    except Exception:
        return 0
    return search_index.index_dataset("airports.json", records=records)


def es_search(query: str, limit: int = 5) -> Optional[List[dict]]:
    """ค้นสนามบินผ่าน Elasticsearch — คืน list ระเบียน หรือ None ถ้า ES ใช้ไม่ได้
    (ให้ผู้เรียก fallback ไป search_airports)"""
    if not extract_query(query)["value"]:
        return []
    try:
        from reference_data import search_index
    except Exception:
        return None
    return search_index.search("airports", query, limit)


def es_suggest(prefix: str, limit: int = 8) -> Optional[List[dict]]:
    """typeahead ผ่าน completion suggester — คืน list ระเบียน หรือ None ถ้าไม่มี ES"""
    try:
        from reference_data import search_index
    except Exception:
        return None
    return search_index.suggest("airports", prefix, limit)


def es_did_you_mean(query: str) -> Optional[str]:
    """แก้คำสะกดผิด (did you mean) — คืนคำที่น่าจะหมายถึง หรือ None"""
    try:
        from reference_data import search_index
    except Exception:
        return None
    return search_index.did_you_mean("airports", query)


# ---------------- จัดข้อความตอบกลับ ----------------

def format_airport(rec: dict) -> str:
    """จัดรายละเอียดสนามบิน 1 แห่งเป็นข้อความ (ชื่อ/เมือง/ประเทศ + รหัส/พิกัด)"""
    def line(emoji, label, value):
        return f"{emoji} {label}: {value}" if value not in (None, "") else None
    _seen = []
    for c in (rec.get("iata"), rec.get("icao"), rec.get("code")):
        if c and c not in _seen:
            _seen.append(c)
    codes = " / ".join(_seen)
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
        _seen = []
        for c in (rec.get("iata"), rec.get("icao"), rec.get("code")):
            if c and c not in _seen:
                _seen.append(c)
        codes = " / ".join(_seen)
        loc = ", ".join(x for x in [rec.get("city"), rec.get("country")] if x)
        lines.append(f"{i}. 🛫 {rec.get('name') or '-'}"
                     + (f" [{codes}]" if codes else "")
                     + (f" — {loc}" if loc else ""))
    lines.append("")
    lines.append("พิมพ์รหัสให้เจาะจงขึ้น (เช่น BKK) เพื่อดูรายละเอียดสนามบินเดียว")
    return "\n".join(lines)
