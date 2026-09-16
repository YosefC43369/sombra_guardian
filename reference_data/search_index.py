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

# ฟิลด์ช่วยค้นที่เติมตอน index (ไม่ส่งคืนในผลลัพธ์)
_HELPER_FIELDS = ("_all_text", "_all_auto", "_codes")
# ฟิลด์ที่มักเป็น "รหัส" ใช้เดา _id ของ doc
_ID_FIELDS = ("code", "iata", "icao", "id", "key", "name")

_INDEX_BODY = {
    "settings": {
        "index": {"number_of_replicas": 0},
        "analysis": {
            "filter": {"edge_ngram_filter": {"type": "edge_ngram", "min_gram": 2, "max_gram": 20}},
            "analyzer": {
                # ตัด accent + lowercase สำหรับค้น full-text ทั่วไป
                "folding": {"tokenizer": "standard", "filter": ["lowercase", "asciifolding"]},
                # edge-ngram ตอน index เพื่อ "พิมพ์ไปค้นไป" ที่เร็วมาก
                "autocomplete_index": {"tokenizer": "standard",
                                       "filter": ["lowercase", "asciifolding", "edge_ngram_filter"]},
            },
            "normalizer": {"code_norm": {"type": "custom", "filter": ["lowercase", "asciifolding"]}},
        },
    },
    "mappings": {
        # ทุกฟิลด์ string -> ค้น full-text (folding) + มี subfield keyword (kw) ไว้ filter/exact
        "dynamic_templates": [
            {"strings": {"match_mapping_type": "string", "mapping": {
                "type": "text", "analyzer": "folding",
                "fields": {"kw": {"type": "keyword", "normalizer": "code_norm", "ignore_above": 256}},
            }}}
        ],
        "properties": {
            "_all_text": {"type": "text", "analyzer": "folding"},
            "_all_auto": {"type": "text", "analyzer": "autocomplete_index",
                          "search_analyzer": "folding"},
            "_codes": {"type": "keyword", "normalizer": "code_norm"},
        },
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
    """เติมฟิลด์ช่วยค้น (_all_text/_all_auto/_codes) ให้ record โดยคงฟิลด์เดิมไว้ครบ"""
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
        client.indices.create(index=idx, body=_INDEX_BODY)
    except Exception as e:
        logger.warning("REF ES | สร้าง index %s ไม่สำเร็จ (%s)", idx, e)
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
    """สร้าง ES query หลายสัญญาณ: รหัสตรง > prefix/autocomplete > fuzzy (เร็วและแม่น)"""
    q = str(query_text or "").strip()
    return {
        "size": max(1, int(limit)),
        "track_total_hits": False,     # เร็วขึ้น: ไม่ต้องนับผลทั้งหมด
        "query": {"bool": {"should": [
            {"term": {"_codes": {"value": q, "boost": 12}}},          # รหัสตรงเป๊ะ
            {"match_phrase_prefix": {"_all_text": {"query": q, "boost": 5}}},
            {"match": {"_all_auto": {"query": q, "boost": 4}}},        # autocomplete (edge-ngram)
            {"match": {"_all_text": {"query": q, "fuzziness": "AUTO",
                                     "prefix_length": 1, "boost": 2}}},  # สะกดผิดเล็กน้อย
        ], "minimum_should_match": 1}},
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
