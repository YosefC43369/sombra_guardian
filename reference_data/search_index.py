# -*- coding: utf-8 -*-
"""reference_data/search_index.py — ชั้นค้นหา Elasticsearch สำหรับ dataset อ้างอิง

ต่อยอดจาก get_records() (JSON/CSV/SQL) ให้ค้นได้เร็ว/ฉลาดขึ้นด้วย Elasticsearch:
  - bulk indexing (helpers) — เร็วกว่ายิงทีละ doc มาก เหมาะกับไฟล์ใหญ่
  - analyzer ชั้นดี: folding (ตัด accent) + autocomplete (edge-ngram, พิมพ์ไปค้นไป)
    + normalizer ของรหัส (lowercase+asciifold) ให้ค้นรหัสแบบไม่สนตัวพิมพ์/accent
  - query หลายสัญญาณ: รหัสตรงเป๊ะ (boost สูง) > prefix/autocomplete > fuzzy

ขอบเขตปลอดภัย (เหมือนเดิม): index ได้เฉพาะ dataset ใน whitelist ของ reference_data
(airports, programming-languages) เท่านั้น — ไม่ใช่ engine ค้นฐานข้อมูล/PII ทั่วไป

ใช้ client/คอนฟิกร่วมกับ osint_es (คลัสเตอร์เดียว) และทำงานแบบ optional: ไม่มี ES
= search() คืน None (ให้ผู้เรียก fallback ไปค้นในหน่วยความจำ), index_dataset() คืน 0
"""

import os
import logging
from typing import Iterable, List, Optional

from . import dataset_manager

logger = logging.getLogger("modbot.reference_data.search_index")

# ชื่อ index = <PREFIX>_<stem>  (เช่น sombra_ref_airports)
ES_PREFIX = (os.getenv("REFERENCE_ES_PREFIX", "").strip() or "sombra_ref")
BULK_CHUNK = int(os.getenv("REFERENCE_ES_BULK", "1000") or "1000")

# ---------- ความฉลาดเพิ่มเติม (เปิด/ปิดได้) ----------
# phonetic matching (Double Metaphone) — จับชื่อที่ "ออกเสียงคล้าย" เช่น Bankok≈Bangkok
# ต้องติดตั้งปลั๊กอิน analysis-phonetic ของ Elasticsearch ก่อน (ดีฟอลต์ปิด; ถ้าเปิดแต่
# ไม่มีปลั๊กอิน index_dataset จะถอยไปสร้าง index แบบไม่มี phonetic ให้อัตโนมัติ)
PHONETIC_ENABLED = os.getenv("REFERENCE_ES_PHONETIC", "").strip().lower() in (
    "1", "true", "yes", "on")
# Thai word segmentation — ใช้ tokenizer "thai" ที่มากับ Elasticsearch (โมดูล
# analysis-common ในตัว ไม่ต้องลงปลั๊กอิน) แบ่งคำไทยด้วยพจนานุกรม ทำให้ค้นชื่อ/เมือง
# ภาษาไทยได้ "ตรงคำ" แทนที่จะตัดเป็นตัวอักษรเดี่ยว ๆ แบบ standard tokenizer (ดีฟอลต์เปิด;
# ถ้าคลัสเตอร์ใดไม่มี ให้ index_dataset ถอยไปสร้างแบบไม่มี thai ให้อัตโนมัติ)
THAI_ENABLED = os.getenv("REFERENCE_ES_THAI", "1").strip().lower() not in (
    "0", "false", "no", "off")
# synonym expansion ตอนค้น — ดีฟอลต์มีชุดคำพ้องของ "ข้อมูลอ้างอิง" ที่ปลอดภัย
# override ได้ด้วย env REFERENCE_ES_SYNONYMS (คั่นด้วย ; หรือขึ้นบรรทัดใหม่)
_DEFAULT_SYNONYMS = ["international, intl, int'l", "airport, airfield, aerodrome"]

# ฟิลด์ช่วยค้นที่เติมตอน index (ไม่ส่งคืนในผลลัพธ์)
_HELPER_FIELDS = ("_all_text", "_all_auto", "_codes", "_suggest", "_all_phon", "_all_thai")

# ช่วง Unicode อักษรไทย — ใช้ตัดสินใจว่าคำค้นเป็นภาษาไทยไหม (เลือก field/สัญญาณให้เหมาะ)
def _has_thai(s: str) -> bool:
    return any("฀" <= ch <= "๿" for ch in str(s or ""))
# ฟิลด์ที่มักเป็น "รหัส" ใช้เดา _id ของ doc
_ID_FIELDS = ("code", "email", "SSN", "id", "key", "name")


def _synonyms():
    raw = os.getenv("REFERENCE_ES_SYNONYMS", "").strip()
    if raw:
        lines = raw.replace(";", "\n").splitlines()
        return [ln.strip() for ln in lines if ln.strip()]
    return list(_DEFAULT_SYNONYMS)


def _index_body(phonetic: bool, thai: Optional[bool] = None) -> dict:
    """ประกอบ settings/mappings ของ index (เปิด/ปิด phonetic + thai + synonym ได้)

    - folding: ตัด accent + lowercase (ค้น full-text)
    - autocomplete_index: edge-ngram ตอน index (พิมพ์ไปค้นไป เร็วมาก)
    - folding_syn: folding + synonym (ใช้เป็น search_analyzer ของ _all_text -> ค้นด้วย
      คำพ้องได้ เช่น "intl" เจอ "International")
    - thai_text (optional): tokenizer "thai" แบ่งคำไทยด้วยพจนานุกรม + decimal_digit
      (แปลงเลขไทย ๑๒๓ -> 123) + asciifolding — ค้นคำไทย "ตรงคำ" แม่นขึ้นมาก
    - _suggest (completion): FST suggester สำหรับ typeahead ที่เร็วและ fuzzy ได้
    - _all_phon (optional): ค้นด้วยเสียงคล้าย (Double Metaphone)
    """
    if thai is None:
        thai = THAI_ENABLED
    syns = _synonyms()
    analysis = {
        "filter": {"edge_ngram_filter": {"type": "edge_ngram", "min_gram": 2, "max_gram": 20}},
        "analyzer": {
            "folding": {"tokenizer": "standard", "filter": ["lowercase", "asciifolding"]},
            "autocomplete_index": {"tokenizer": "standard",
                                   "filter": ["lowercase", "asciifolding", "edge_ngram_filter"]},
        },
        "normalizer": {"code_norm": {"type": "custom", "filter": ["lowercase", "asciifolding"]}},
    }
    text_search_analyzer = "folding"
    if syns:
        analysis["filter"]["syn_filter"] = {"type": "synonym", "synonyms": syns}
        analysis["analyzer"]["folding_syn"] = {
            "tokenizer": "standard", "filter": ["lowercase", "asciifolding", "syn_filter"]}
        text_search_analyzer = "folding_syn"
    if thai:
        # tokenizer "thai" = แบ่งคำไทยด้วย BreakIterator ในตัว ES (ไม่ต้องลงปลั๊กอิน)
        analysis["analyzer"]["thai_text"] = {
            "tokenizer": "thai",
            "filter": ["lowercase", "decimal_digit", "asciifolding"]}
    if phonetic:
        analysis["filter"]["dm_filter"] = {"type": "phonetic", "encoder": "double_metaphone",
                                           "replace": False}
        analysis["analyzer"]["phonetic"] = {"tokenizer": "standard",
                                            "filter": ["lowercase", "dm_filter"]}

    properties = {
        "_all_text": {"type": "text", "analyzer": "folding", "search_analyzer": text_search_analyzer},
        "_all_auto": {"type": "text", "analyzer": "autocomplete_index", "search_analyzer": "folding"},
        "_codes": {"type": "keyword", "normalizer": "code_norm"},
        # completion suggester (FST) — typeahead ที่เร็วและรองรับ fuzzy
        "_suggest": {"type": "completion", "analyzer": "simple",
                     "preserve_separators": True, "preserve_position_increments": True,
                     "max_input_length": 50},
    }
    if thai:
        properties["_all_thai"] = {"type": "text", "analyzer": "thai_text"}
    if phonetic:
        properties["_all_phon"] = {"type": "text", "analyzer": "phonetic"}

    return {
        "settings": {"index": {"number_of_replicas": 0}, "analysis": analysis},
        "mappings": {
            "dynamic_templates": [
                {"strings": {"match_mapping_type": "string", "mapping": {
                    "type": "text", "analyzer": "folding",
                    "fields": {"kw": {"type": "keyword", "normalizer": "code_norm",
                                      "ignore_above": 256}}}}}
            ],
            "properties": properties,
        },
    }


# ---------------- client (ใช้ร่วมกับ osint_es) ----------------

def _client():
    try:
        import osint_es
        return osint_es.get_client()
    except Exception:
        return None


def es_available() -> bool:
    try:
        import osint_es
        return osint_es.es_available()
    except Exception:
        return False


def _helpers():
    try:
        from elasticsearch import helpers  # type: ignore
        return helpers
    except Exception:
        return None


# ---------------- ชื่อ index + whitelist ----------------

def _stem(name: str) -> str:
    return os.path.splitext(os.path.basename(str(name)))[0]


def _allowed_stems() -> set:
    return {_stem(n) for n in dataset_manager.ALLOWED_DATASETS}


def index_name(name_or_stem: str) -> str:
    return f"{ES_PREFIX}_{_stem(name_or_stem)}"


# ---------------- แปลง record -> เอกสาร ----------------

def _looks_like_code(s: str) -> bool:
    return isinstance(s, str) and s.isalnum() and 2 <= len(s) <= 6


def doc_from_record(rec: dict) -> dict:
    """เติมฟิลด์ช่วยค้น (_all_text/_all_auto/_codes/_suggest[/_all_phon]) โดยคงฟิลด์เดิมครบ"""
    doc = dict(rec)
    parts: List[str] = []
    codes = set()
    for value in rec.values():
        if isinstance(value, str):
            if value:
                parts.append(value)
                if _looks_like_code(value):
                    codes.add(value)
        elif isinstance(value, (int, float)):
            parts.append(str(value))
    blob = " ".join(parts)
    doc["_all_text"] = blob
    doc["_all_auto"] = blob
    if codes:
        doc["_codes"] = sorted(codes)
    # completion suggester: อินพุตที่ผู้ใช้น่าจะพิมพ์ (ชื่อ/เมือง/รหัส) — ดันตามลำดับ
    inputs = []
    for f in ("name", "city", "title", "label"):
        v = rec.get(f)
        if isinstance(v, str) and v.strip():
            inputs.append(v.strip())
    inputs.extend(sorted(codes))
    inputs = list(dict.fromkeys(inputs))   # dedupe คงลำดับ
    if inputs:
        doc["_suggest"] = {"input": inputs}
    if THAI_ENABLED:
        doc["_all_thai"] = blob      # วิเคราะห์ด้วย thai_text ตอน index (แบ่งคำไทย)
    if PHONETIC_ENABLED:
        doc["_all_phon"] = blob
    return doc


def _doc_id(rec: dict):
    for f in _ID_FIELDS:
        v = rec.get(f)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v)
    return None


def _strip_helpers(src: dict) -> dict:
    return {k: v for k, v in (src or {}).items() if k not in _HELPER_FIELDS}


# ---------------- index ----------------

def index_dataset(name: str, records: Optional[Iterable[dict]] = None) -> int:
    """(สร้างใหม่แล้ว) ทำดัชนี dataset ลง Elasticsearch — คืนจำนวน doc ที่ index สำเร็จ

    records: ถ้าให้มา จะ index จากชุดนี้ (เช่น airports ส่ง record ที่ normalize แล้ว)
             ถ้าไม่ให้ จะดึงผ่าน reference_data.get_records(name) (รองรับ .json/.csv/.sql)
    index เป็นข้อมูลอนุพันธ์: rebuild ใหม่ทั้ง index ทุกครั้ง (ต้นฉบับบน Drive คงเดิม)
    """
    client = _client()
    if client is None:
        return 0
    if _stem(name) not in _allowed_stems():
        logger.warning("REF ES | ปฏิเสธ index นอก whitelist: %s", name)
        return 0
    idx = index_name(name)
    try:
        if client.indices.exists(index=idx):
            client.indices.delete(index=idx)
    except Exception as e:
        logger.warning("REF ES | ลบ index เก่า %s ไม่สำเร็จ (%s)", idx, e)
        return 0
    # ลองสร้างด้วยความสามารถครบก่อน (thai + phonetic) แล้วค่อย ๆ ถอยความสามารถที่คลัสเตอร์
    # นี้ไม่รองรับออก โดยพยายามคง thai ไว้ให้นานที่สุด (ค้นไทยแม่นสำคัญกว่า phonetic)
    # ลำดับพยายาม: (phon,thai) richest -> plainest ตามแฟล็กที่เปิดไว้
    def _attempts():
        seen = set()
        for th in ([True, False] if THAI_ENABLED else [False]):
            for ph in ([True, False] if PHONETIC_ENABLED else [False]):
                key = (ph, th)
                if key not in seen:
                    seen.add(key)
                    yield key
    created = False
    for want_phon, want_thai in _attempts():
        try:
            client.indices.create(index=idx, body=_index_body(want_phon, want_thai))
            created = True
            if PHONETIC_ENABLED and not want_phon:
                logger.warning("REF ES | ไม่มีปลั๊กอิน analysis-phonetic — สร้าง index "
                               "แบบไม่มี phonetic ให้แทน")
            if THAI_ENABLED and not want_thai:
                logger.warning("REF ES | คลัสเตอร์ไม่รองรับ tokenizer thai — สร้าง index "
                               "แบบไม่มี thai ให้แทน (ค้นไทยจะหยาบลง)")
            break
        except Exception as e:
            logger.info("REF ES | สร้าง index %s (phonetic=%s, thai=%s) ไม่สำเร็จ (%s)",
                        idx, want_phon, want_thai, e)
    if not created:
        return 0

    recs = records if records is not None else dataset_manager.get_records(name)

    def _actions():
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            action = {"_index": idx, "_source": doc_from_record(rec)}
            doc_id = _doc_id(rec)
            if doc_id:
                action["_id"] = doc_id
            yield action

    ok = 0
    helpers = _helpers()
    try:
        if helpers is not None:
            for success, _info in helpers.streaming_bulk(
                    client, _actions(), chunk_size=BULK_CHUNK, raise_on_error=False):
                if success:
                    ok += 1
        else:
            for a in _actions():
                client.index(index=idx, id=a.get("_id"), document=a["_source"])
                ok += 1
        client.indices.refresh(index=idx)
    except Exception as e:
        logger.warning("REF ES | bulk index %s ล้มเหลว (%s)", idx, e)
    logger.info("REF ES | ทำดัชนี %s: %d เอกสาร", idx, ok)
    return ok


# ---------------- search ----------------

def build_query(query_text: str, limit: int = 10) -> dict:
    """สร้าง ES query หลายสัญญาณ (เรียงจากตรงสุด -> หลวมสุด) ให้ทั้งเร็ว แม่น และฉลาด:

        รหัสตรงเป๊ะ (_codes) > วลีตรง (_all_text phrase) > prefix/autocomplete >
        คำไทยตรงคำ (_all_thai) > fuzzy (สะกดผิด) > phonetic (เสียงคล้าย, ถ้าเปิด)

    เพิ่มความฉลาด: วลีตรง (match_phrase) ดันผลที่ "ตรงทั้งวลี" ขึ้นบน, และเมื่อคำค้นมี
    หลายคำจะใช้ minimum_should_match แบบ "70%" กับสัญญาณคำไทย/ข้อความ เพื่อไม่ให้คำเดียว
    ที่บังเอิญตรงลากผลที่ไม่เกี่ยวขึ้นมา
    """
    q = str(query_text or "").strip()
    is_thai = THAI_ENABLED and _has_thai(q)
    signals = [
        {"term": {"_codes": {"value": q, "boost": 12}}},          # รหัสตรงเป๊ะ
        {"match_phrase": {"_all_text": {"query": q, "boost": 7}}},  # ตรงทั้งวลี (แม่นสุด)
        {"match_phrase_prefix": {"_all_text": {"query": q, "boost": 5}}},
        {"match": {"_all_auto": {"query": q, "boost": 4}}},        # autocomplete (edge-ngram)
        {"match": {"_all_text": {"query": q, "fuzziness": "AUTO",
                                 "prefix_length": 1, "boost": 2}}},  # สะกดผิดเล็กน้อย
    ]
    if THAI_ENABLED:
        # คำไทยตรงคำ (ผ่าน thai tokenizer) — วลีตรงดันสูง, ตามด้วยตรงหลายคำแบบ 70%
        signals.append({"match_phrase": {"_all_thai": {"query": q, "boost": 6}}})
        signals.append({"match": {"_all_thai": {
            "query": q, "boost": 4 if is_thai else 2,
            "minimum_should_match": "70%"}}})
    if PHONETIC_ENABLED:
        # จับชื่อที่ออกเสียงคล้าย (เช่น Bankok≈Bangkok) — คะแนนต่ำสุด กันรบกวนผลตรง
        signals.append({"match": {"_all_phon": {"query": q, "boost": 1.5}}})
    return {
        "size": max(1, int(limit)),
        "track_total_hits": False,     # เร็วขึ้น: ไม่ต้องนับผลทั้งหมด
        # ประสิทธิภาพ: ไม่ต้องส่งฟิลด์ช่วยค้น (_all_text/_all_auto/…) กลับมา (ตัดทิ้งฝั่ง ES)
        "_source": {"excludes": list(_HELPER_FIELDS)},
        # ความแม่นยำ: ใช้ dis_max + tie_breaker — เอา "สัญญาณที่ตรงที่สุด" เป็นคะแนนหลัก
        # แล้วบวกสัญญาณอื่นแบบถ่วงน้ำหนักน้อย (0.3) แทนการรวมคะแนนทุก clause (bool should)
        # ซึ่งทำให้เอกสารที่บังเอิญตรงหลาย ๆ จุดเล็กน้อยพองคะแนนเกินจริง
        "query": {"dis_max": {"tie_breaker": 0.3, "queries": signals}},
    }


def search(name_or_stem: str, query_text: str, limit: int = 10) -> Optional[List[dict]]:
    """ค้น dataset ผ่าน Elasticsearch — คืน list ของ record dict (ตัดฟิลด์ช่วยค้นออก)
    หรือ None ถ้า ES ใช้ไม่ได้ (ให้ผู้เรียก fallback ไปค้นในหน่วยความจำ)"""
    q = str(query_text or "").strip()
    if not q:
        return []
    client = _client()
    if client is None:
        return None
    idx = index_name(name_or_stem)
    try:
        resp = client.search(index=idx, body=build_query(q, limit))
    except Exception as e:
        logger.debug("REF ES | ค้น %s ล้มเหลว (%s) — fallback", idx, e)
        return None
    return [_strip_helpers(h.get("_source", {}))
            for h in resp.get("hits", {}).get("hits", [])]


# ---------------- ความฉลาดเพิ่มเติม: suggester + "did you mean" ----------------

def suggest(name_or_stem: str, prefix: str, limit: int = 8) -> Optional[List[dict]]:
    """typeahead: แนะนำ record จากตัวอักษรที่พิมพ์ (completion suggester + fuzzy)

    ใช้ FST suggester ของ Elasticsearch — เร็วมากและทนสะกดผิดเล็กน้อย
    คืน list ของ record dict หรือ None ถ้า ES ใช้ไม่ได้ / [] ถ้า prefix ว่าง
    """
    prefix = str(prefix or "").strip()
    if not prefix:
        return []
    client = _client()
    if client is None:
        return None
    idx = index_name(name_or_stem)
    body = {"suggest": {"s": {"prefix": prefix, "completion": {
        "field": "_suggest", "size": max(1, int(limit)),
        "skip_duplicates": True, "fuzzy": {"fuzziness": "AUTO"}}}}}
    try:
        resp = client.search(index=idx, body=body)
    except Exception as e:
        logger.debug("REF ES | suggest %s ล้มเหลว (%s)", idx, e)
        return None
    out = []
    groups = resp.get("suggest", {}).get("s", [])
    for group in groups:
        for opt in group.get("options", []):
            src = opt.get("_source")
            out.append(_strip_helpers(src) if isinstance(src, dict) else {"text": opt.get("text")})
    return out


def did_you_mean(name_or_stem: str, text: str) -> Optional[str]:
    """แก้คำสะกดผิด (term suggester) — คืนคำค้นที่ "น่าจะหมายถึง" หรือ None ถ้าไม่มี

    ช่วยกรณีผู้ใช้พิมพ์ผิดจนไม่เจอผล เช่น "Bangkkok" -> เสนอ "Bangkok"
    """
    text = str(text or "").strip()
    if not text:
        return None
    client = _client()
    if client is None:
        return None
    idx = index_name(name_or_stem)
    # คำค้นไทย -> แก้คำบน field ที่แบ่งคำไทยแล้ว (_all_thai) จะได้คำแนะนำที่ตรงกว่า
    field = "_all_thai" if (THAI_ENABLED and _has_thai(text)) else "_all_text"
    body = {"suggest": {"dym": {"text": text, "term": {
        "field": field, "suggest_mode": "missing"}}}}
    try:
        resp = client.search(index=idx, body=body)
    except Exception as e:
        logger.debug("REF ES | did_you_mean %s ล้มเหลว (%s)", idx, e)
        return None
    tokens = resp.get("suggest", {}).get("dym", [])
    if not tokens:
        return None
    corrected, changed = [], False
    for tok in tokens:
        opts = tok.get("options", [])
        if opts:
            corrected.append(str(opts[0].get("text") or tok.get("text")))
            changed = True
        else:
            corrected.append(str(tok.get("text")))
    result = " ".join(w for w in corrected if w)
    return result if (changed and result.lower() != text.lower()) else None


def search_smart(name_or_stem: str, query_text: str, limit: int = 10) -> Optional[dict]:
    """ค้นหา + แนบ "did you mean" อัตโนมัติเมื่อไม่พบผล — คืน {"hits","suggestion"}
    หรือ None ถ้า ES ใช้ไม่ได้ (ให้ผู้เรียก fallback)"""
    hits = search(name_or_stem, query_text, limit)
    if hits is None:
        return None
    suggestion = did_you_mean(name_or_stem, query_text) if not hits else None
    return {"hits": hits, "suggestion": suggestion}
