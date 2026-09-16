# -*- coding: utf-8 -*-
"""reference_data/schema.py — Field Extraction + Data-Structure Mapping (Task 1)

สกัด "ฟิลด์" และทำแผนที่ "โครงสร้างข้อมูล" จาก dump สาธารณะขนาดใหญ่ (โดยเฉพาะ .sql)
อย่างรวดเร็ว โดยต่อยอดจาก parser เดิม (json/csv/sql) — ไม่รัน SQL, ไม่โหลดทั้งไฟล์เข้า
RAM (อ่านแบบ streaming ผ่าน parser) และ "สุ่มตัวอย่างแบบมีเพดาน" เพื่อให้เร็วกับไฟล์ใหญ่

ขอบเขตปลอดภัย (เหมือนเดิม): entry point ระดับ dataset (profile_dataset/sql_schema) ทำงาน
ได้เฉพาะไฟล์ใน whitelist ของ reference_data (airports, programming-languages) เท่านั้น —
ไม่ใช่เครื่องมือ profile ฐานข้อมูล/leak/PII ทั่วไป ตัว helper ระดับ record (profile_records,
infer_type) เป็นฟังก์ชันบริสุทธิ์ไม่ผูก dataset จึงนำไปเทส/ใช้ซ้ำได้อิสระ

คืนผลเป็น dict ที่ serialize เป็น JSON ได้ทันที เพื่อให้ชั้นบน (เช่นรายงาน/หน้า schema) ใช้ต่อ
"""

import logging
from typing import Dict, Iterable, List, Optional

from . import dataset_manager
from .parsers import sql_parser

logger = logging.getLogger("modbot.reference_data.schema")

# เพดานการสุ่มตัวอย่างต่อการ profile หนึ่งครั้ง — กันไฟล์ใหญ่ทำงานช้า/กินแรม
DEFAULT_SAMPLE = 5000
# จำนวนค่าตัวอย่างที่เก็บต่อฟิลด์ (ไว้ให้คนดูว่าหน้าตาข้อมูลเป็นอย่างไร)
_SAMPLES_PER_FIELD = 3


def infer_type(value) -> str:
    """เดาชนิดของค่าแบบเบา ๆ: null/bool/int/float/str (parser คืน str/None เป็นหลัก)"""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return "empty"
        low = s.lower()
        if low in ("true", "false"):
            return "bool"
        # ตัวเลขที่มาเป็น string (พบบ่อยจาก SQL/CSV)
        body = s[1:] if s[0] in "+-" else s
        if body.isdigit():
            return "int"
        if body.count(".") == 1 and body.replace(".", "", 1).isdigit():
            return "float"
        return "str"
    return type(value).__name__


def _blank_stat() -> dict:
    return {"count": 0, "non_null": 0, "types": {}, "samples": [],
            "min_len": None, "max_len": None}


def profile_records(records: Iterable[dict],
                    sample_limit: int = DEFAULT_SAMPLE) -> dict:
    """ทำ field-profile จาก iterator ของ record dict (สุ่มมีเพดานเพื่อความเร็ว)

    คืน:
        {
          "rows_seen": จำนวนแถวที่อ่าน,
          "sampled": จำนวนแถวที่นำมา profile จริง (<= sample_limit),
          "truncated": True ถ้าหยุดเพราะชนเพดาน,
          "fields": {ชื่อฟิลด์: {count, non_null, types{ชนิด:จำนวน}, samples[], min_len, max_len}},
          "field_order": [ลำดับฟิลด์ที่พบครั้งแรก],
        }
    ไม่ throw: record ที่ไม่ใช่ dict จะถูกข้าม
    """
    fields: Dict[str, dict] = {}
    order: List[str] = []
    rows_seen = 0
    sampled = 0
    truncated = False
    for rec in records:
        rows_seen += 1
        if not isinstance(rec, dict):
            continue
        sampled += 1
        for key, value in rec.items():
            st = fields.get(key)
            if st is None:
                st = fields[key] = _blank_stat()
                order.append(key)
            st["count"] += 1
            t = infer_type(value)
            st["types"][t] = st["types"].get(t, 0) + 1
            if value is not None and t not in ("null", "empty"):
                st["non_null"] += 1
                sval = value if isinstance(value, str) else str(value)
                ln = len(sval)
                st["min_len"] = ln if st["min_len"] is None else min(st["min_len"], ln)
                st["max_len"] = ln if st["max_len"] is None else max(st["max_len"], ln)
                if len(st["samples"]) < _SAMPLES_PER_FIELD and sval not in st["samples"]:
                    st["samples"].append(sval)
        if sampled >= sample_limit:
            truncated = True
            break
    return {"rows_seen": rows_seen, "sampled": sampled, "truncated": truncated,
            "fields": fields, "field_order": order}


def field_names(records: Iterable[dict], sample_limit: int = DEFAULT_SAMPLE) -> List[str]:
    """คืนรายชื่อฟิลด์ (ตามลำดับที่พบครั้งแรก) — ทางลัดของ profile_records()['field_order']"""
    return profile_records(records, sample_limit=sample_limit)["field_order"]


def dominant_types(profile: dict) -> Dict[str, str]:
    """สรุปชนิดเด่นของแต่ละฟิลด์จากผล profile (ฟิลด์ -> ชนิดที่พบมากสุด)"""
    out = {}
    for name, st in (profile.get("fields") or {}).items():
        types = st.get("types") or {}
        out[name] = max(types, key=types.get) if types else "null"
    return out


# ---------------- entry point ระดับ dataset (whitelist-gated) ----------------

def profile_dataset(name: str, sample_limit: int = DEFAULT_SAMPLE,
                    **opts) -> Optional[dict]:
    """profile dataset ใน whitelist (.json/.csv/.sql) — คืน None ถ้านอก whitelist/โหลดไม่ได้

    เลือก parser ตามนามสกุลอัตโนมัติ (ผ่าน dataset_manager.get_records) แล้ว profile แบบ
    streaming — เหมาะกับ dump ขนาดใหญ่เพราะไม่โหลดทั้งไฟล์และหยุดที่ sample_limit
    """
    if not dataset_manager.is_allowed(name):
        logger.debug("SCHEMA | เพิกเฉยไฟล์นอก whitelist: %s", name)
        return None
    try:
        records = dataset_manager.get_records(name, **opts)
        prof = profile_records(records, sample_limit=sample_limit)
    except Exception as e:
        logger.warning("SCHEMA | profile %s ล้มเหลว (%s)", name, e)
        return None
    prof["dataset"] = name
    return prof


def sql_schema(name: str) -> Optional[dict]:
    """แผนที่โครงสร้างของ .sql dump ใน whitelist: รวม CREATE TABLE (คอลัมน์ประกาศ) เข้ากับ
    ฟิลด์ที่ "พบจริง" ใน INSERT (สุ่มมีเพดาน) — ให้ภาพว่า dump มีตาราง/คอลัมน์อะไรบ้างเร็ว ๆ

    คืน None ถ้านอก whitelist / ไม่ใช่ .sql / เปิดไม่ได้
    """
    if not dataset_manager.is_allowed(name):
        return None
    if not str(name).lower().endswith(".sql"):
        return None
    path = dataset_manager.get_dataset_path(name)
    if not path:
        return None
    try:
        declared = sql_parser.list_tables(path)  # {ตาราง: [คอลัมน์ประกาศ]}
    except Exception as e:
        logger.warning("SCHEMA | list_tables %s ล้มเหลว (%s)", name, e)
        declared = {}
    # ฟิลด์ที่พบจริงต่อตาราง (จำกัดตัวอย่างเพื่อความเร็ว)
    observed: Dict[str, List[str]] = {}
    seen = 0
    try:
        for row in sql_parser.stream_records(path, with_table=True):
            table = row.get("table")
            data = row.get("data") or {}
            if table is None:
                continue
            bucket = observed.setdefault(table, [])
            for k in data.keys():
                if k not in bucket:
                    bucket.append(k)
            seen += 1
            if seen >= DEFAULT_SAMPLE:
                break
    except Exception as e:
        logger.warning("SCHEMA | อ่าน INSERT ของ %s ล้มเหลว (%s)", name, e)
    tables = {}
    for table in sorted(set(declared) | set(observed)):
        tables[table] = {
            "declared_columns": declared.get(table, []),
            "observed_fields": observed.get(table, []),
        }
    return {"dataset": name, "tables": tables, "rows_scanned": seen}
