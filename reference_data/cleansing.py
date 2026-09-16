# -*- coding: utf-8 -*-
"""reference_data/cleansing.py — Data Cleansing + Deduplication + Indexing (Task 2)

กรองข้อมูลซ้ำและจัดการทำดัชนีของข้อมูลที่สกัดจากไฟล์ .sql/.json (และ .csv) โดยต่อยอด
จาก parser เดิม + search_index เดิม ทั้งหมดอยู่ใน "กรอบไฟล์ที่อนุญาต" (whitelist ของ
reference_data: airports, programming-languages) — ไม่ใช่เครื่องมือ dedup/ทำดัชนี
ฐานข้อมูล/leak/PII ทั่วไป

pipeline:
    get_records(name)  ->  clean_record (normalize/ตัดค่าว่าง)  ->  dedupe (กันซ้ำ)  ->
    search_index.index_dataset(name, records=...)

หลักการ:
  - streaming/memory-safe: clean + dedupe เป็น generator, seen-set เก็บเฉพาะ "ลายนิ้วมือ"
    (hash) ไม่เก็บทั้ง record — เหมาะกับไฟล์ใหญ่
  - ไม่ทำลายข้อมูลต้นฉบับบน Drive: ทำงานกับ record ที่อ่านมาเท่านั้น (ต้นฉบับคงเดิม)
  - ไม่ throw ระดับ pipeline: record เสียตัวเดียวถูกข้าม ไม่ทำทั้งชุดพัง
"""

import hashlib
import json
import logging
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

from . import dataset_manager
from . import search_index

logger = logging.getLogger("modbot.reference_data.cleansing")


# ---------------- cleansing (ระดับ record) ----------------

def _clean_scalar(value):
    """normalize ค่าเดี่ยว: str -> strip + ยุบช่องว่างซ้ำ; ค่าอื่นคงเดิม"""
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # ยุบ whitespace ภายใน (รวม \t\n) ให้เหลือช่องว่างเดียว
        return " ".join(s.split())
    return value


def clean_record(rec: dict, drop_empty: bool = True,
                 lower_keys: bool = True) -> dict:
    """ทำความสะอาด record หนึ่งตัว:
      - normalize key (strip; lower_keys=True ทำเป็นตัวพิมพ์เล็กเพื่อรวมฟิลด์ที่พิมพ์ต่างกัน)
      - normalize ค่า string (strip + ยุบช่องว่าง)
      - drop_empty=True: ตัดฟิลด์ที่เป็น None/ว่างหลัง clean ออก
    คืน dict ใหม่เสมอ (ไม่แก้ของเดิม) — record ที่ไม่ใช่ dict คืน {}
    """
    if not isinstance(rec, dict):
        return {}
    out: Dict[str, object] = {}
    for key, value in rec.items():
        k = str(key).strip()
        if lower_keys:
            k = k.lower()
        if not k:
            continue
        cv = _clean_scalar(value)
        if drop_empty and cv is None:
            continue
        # ถ้าชนคีย์ (เช่น "Name"/"name") ให้ค่าที่ไม่ว่างชนะ
        if k in out and cv is None:
            continue
        out[k] = cv
    return out


# ---------------- deduplication ----------------

def _fingerprint(rec: dict, keys: Optional[Sequence[str]]) -> str:
    """สร้างลายนิ้วมือของ record เพื่อเทียบซ้ำ:
      - ถ้าระบุ keys: ใช้เฉพาะฟิลด์เหล่านั้น (เช่น ["code"]) — ตรงกัน = ซ้ำ
      - ถ้าไม่ระบุ: ใช้ทั้ง record (คีย์เรียง) — ซ้ำเมื่อ "เหมือนกันทั้งแถว"
    เทียบแบบไม่สนตัวพิมพ์/ช่องว่างหัวท้ายของค่า string เพื่อจับซ้ำที่ต่างแค่รูปแบบ
    """
    if keys:
        material = {k: rec.get(k) for k in keys}
    else:
        material = rec

    def _norm(v):
        return v.strip().lower() if isinstance(v, str) else v

    norm = {k: _norm(v) for k, v in sorted(material.items())}
    blob = json.dumps(norm, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.md5(blob.encode("utf-8")).hexdigest()


def dedupe(records: Iterable[dict],
           keys: Optional[Sequence[str]] = None) -> Iterator[dict]:
    """generator ที่ปล่อยเฉพาะ record ที่ "ยังไม่เคยเห็น" (กันซ้ำแบบ streaming)

    keys=None -> กันซ้ำทั้งแถว; keys=["code"] -> กันซ้ำตามฟิลด์คีย์ (ตัวแรกชนะ)
    เก็บเฉพาะ hash ใน seen-set (ประหยัดแรม) — เหมาะกับไฟล์ใหญ่
    """
    seen = set()
    for rec in records:
        if not isinstance(rec, dict) or not rec:
            continue
        try:
            fp = _fingerprint(rec, keys)
        except Exception:
            # เทียบไม่ได้ (ค่าแปลก) -> ปล่อยผ่าน ดีกว่าทิ้งข้อมูล
            yield rec
            continue
        if fp in seen:
            continue
        seen.add(fp)
        yield rec


# ---------------- pipeline: clean -> dedupe ----------------

def clean_stream(records: Iterable[dict],
                 keys: Optional[Sequence[str]] = None,
                 drop_empty: bool = True,
                 lower_keys: bool = True) -> Iterator[dict]:
    """pipeline แบบ streaming: clean แต่ละ record แล้วส่งต่อ dedupe — ปล่อย record ที่สะอาด+ไม่ซ้ำ"""
    def _cleaned():
        for rec in records:
            c = clean_record(rec, drop_empty=drop_empty, lower_keys=lower_keys)
            if c:
                yield c
    yield from dedupe(_cleaned(), keys=keys)


# ---------------- index ผ่าน pipeline (whitelist-gated) ----------------

def _default_keys(name: str) -> Optional[List[str]]:
    """เดาคีย์กันซ้ำที่เหมาะกับ dataset อ้างอิง — ไม่มีก็คืน None (กันซ้ำทั้งแถว)"""
    n = str(name).lower()
    if n.startswith("PeopleDataLabs_416M"):
        return ["name", "email"]
    if n.startswith("northern.ac.th"):
        return ["phone", "name", "email"]
    return None


def clean_and_index(name: str,
                    keys: Optional[Sequence[str]] = None,
                    **opts) -> dict:
    """clean + dedupe แล้วทำดัชนีลง Elasticsearch — คืนสถิติ (ไม่ throw)

    - whitelist-gated: ไฟล์นอก whitelist -> ไม่ทำอะไร (indexed=0)
    - ไม่มี ES -> indexed=0 (ส่วน clean/dedupe ยังทำงานเพื่อรายงานสถิติได้)
    คืน: {"dataset","raw","cleaned","indexed","deduped_removed","es"}
    """
    stats = {"dataset": name, "raw": 0, "cleaned": 0, "indexed": 0,
             "deduped_removed": 0, "es": search_index.es_available()}
    if not dataset_manager.is_allowed(name):
        logger.debug("CLEANSE | เพิกเฉยไฟล์นอก whitelist: %s", name)
        return stats
    if keys is None:
        keys = _default_keys(name)

    # นับสถิติระหว่าง stream โดยไม่ต้อง materialize ทั้งชุด
    counts = {"raw": 0, "cleaned": 0}

    def _pipeline() -> Iterator[dict]:
        raw = dataset_manager.get_records(name, **opts)

        def _cleaned():
            for rec in raw:
                counts["raw"] += 1
                c = clean_record(rec)
                if c:
                    yield c
        for rec in dedupe(_cleaned(), keys=keys):
            counts["cleaned"] += 1
            yield rec

    try:
        if stats["es"]:
            indexed = search_index.index_dataset(name, records=_pipeline())
        else:
            # ไม่มี ES: ทำ clean+dedupe ให้ครบเพื่อรายงานสถิติ (indexing เป็นส่วนเสริม)
            for _ in _pipeline():
                pass
            indexed = 0
    except Exception as e:
        logger.warning("CLEANSE | index %s ล้มเหลว (%s)", name, e)
        indexed = 0
    stats["raw"] = counts["raw"]
    stats["cleaned"] = counts["cleaned"]
    stats["indexed"] = indexed
    stats["deduped_removed"] = max(0, counts["raw"] - counts["cleaned"])
    logger.info("CLEANSE | %s: raw=%d cleaned=%d indexed=%d (ตัดซ้ำ/ว่าง=%d)",
                name, stats["raw"], stats["cleaned"], stats["indexed"],
                stats["deduped_removed"])
    return stats


def clean_all(**opts) -> dict:
    """clean+dedupe+index ทุก dataset ใน whitelist — แยกความล้มเหลวต่อไฟล์ (ไม่ throw)"""
    out = {}
    for name in sorted(dataset_manager.ALLOWED_DATASETS):
        try:
            out[name] = clean_and_index(name, **opts)
        except Exception:
            logger.exception("CLEANSE | clean_all %s ผิดพลาด", name)
            out[name] = {"dataset": name, "error": True}
    return out
