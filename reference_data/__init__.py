# -*- coding: utf-8 -*-
"""reference_data — ชั้นเก็บ/แคช/โหลด dataset อ้างอิงจาก Google Drive

เฉพาะไฟล์อ้างอิงที่ไม่ใช่ข้อมูลส่วนบุคคล 2 ไฟล์ (whitelist แข็ง):
    airports.json, programming-languages.json

เปิด API หลักให้โค้ดเดิมเรียกใช้:
    get_dataset_path(name) -> path ในเครื่องของเวอร์ชันปัจจุบัน (Drive-cached หรือ local)
    get_json(name)         -> อ็อบเจกต์ JSON ที่ parse แล้ว (แคช RAM)
    sync_all()             -> ซิงก์ทุก dataset (ใช้ตอน startup)
    drive_enabled()        -> ตั้งค่า Drive ไว้ไหม

ออกแบบให้ "ปลอดภัยเมื่อไม่มี Drive": ถ้าไม่ได้ตั้งค่า/ไลบรารีไม่มี/Drive ล่ม จะถอยไป
ใช้ไฟล์ในเครื่อง (resource/) เหมือนพฤติกรรมเดิมของบอตทุกประการ
"""

# =====================================================================
# แผนที่ฟังก์ชัน "ค้นหาในไฟล์ฐานข้อมูลอ้างอิง" (ไว้อ้างอิงเร็ว ๆ ว่าอะไรอยู่ตรงไหน)
# ---------------------------------------------------------------------
# [จุดกำหนด whitelist — ไฟล์ฐานข้อมูลที่เราอนุญาตเท่านั้น]
#   dataset_manager.py : ALLOWED_DATASETS, _DATASET_STEMS, _DATASET_EXTS, is_allowed()
#       = แหล่งความจริงเดียวของ whitelist (airports, programming-languages
#         × .json/.csv/.sql) — ไฟล์นอกรายการนี้ถูกเพิกเฉยทุกทาง
#   ทุกโมดูลค้น/ทำดัชนีต้องผ่านประตูนี้ก่อนเสมอ:
#       search_index.py : _allowed_stems(), index_name() ใน index_dataset()
#       schema.py       : profile_dataset(), sql_schema()  (เช็ค is_allowed)
#       cleansing.py    : clean_and_index(), _default_keys() (เช็ค is_allowed)
#       fast_index.py   : for_dataset(), search()          (เช็ค is_allowed)
#
# [แยกฟิลด์ — คอลัมน์/คีย์ในไฟล์ -> record dict แบน]
#   parsers/sql_parser.py : _parse_create() (คอลัมน์จาก CREATE TABLE),
#       _parse_insert() (จับค่าเข้าคอลัมน์), _split_top_level(), list_tables(),
#       stream_records()
#   parsers/csv_parser.py : _sniff() + stream_records()  (หัวตาราง -> ฟิลด์)
#   parsers/json_parser.py: _iter_obj(), _as_record(), stream_records() (คีย์ JSON -> ฟิลด์)
#   schema.py            : profile_records(), field_names(), infer_type(),
#       dominant_types(), sql_schema()  (สกัดชื่อ/ชนิดฟิลด์ + แผนที่โครงสร้าง)
#
# [สกัดข้อความ — รวม/ทำความสะอาดข้อความให้พร้อมค้น]
#   search_index.py : doc_from_record() (สร้าง _all_text/_all_auto/_codes/_suggest),
#       _looks_like_code(), _strip_helpers()
#   fast_index.py   : _record_text(), _norm(), _deaccent(), trigrams()
#   cleansing.py    : clean_record(), _clean_scalar(), clean_stream(),
#       dedupe()/_fingerprint()  (normalize + กันซ้ำก่อนค้น/ทำดัชนี)
#   parsers/sql_parser.py : _parse_value() (SQL literal -> ข้อความ), _strip_comments()
#
# [ค้นหาข้อความ — ยิงคำค้นแล้วคืนระเบียนที่ตรง]
#   search_index.py (Elasticsearch) : build_query(), search(), suggest(),
#       did_you_mean(), search_smart()
#   fast_index.py (offline trigram) : FastIndex.search(), FastIndex._candidates(),
#       _precise_score(), search() ระดับโมดูล
# =====================================================================

from .dataset_manager import (
    ALLOWED_DATASETS,
    is_allowed,
    drive_enabled,
    get_dataset_path,
    get_json,
    get_records,
    parse_records,
    sync,
    sync_all,
)
# Task 1: สกัดฟิลด์ + แผนที่โครงสร้างจาก dump (whitelist-gated)
from .schema import profile_dataset, sql_schema, profile_records
# คัดแยกบทบาทฟิลด์อัตโนมัติ (auto field classification) — ไม่ต้องกำหนดฟิลด์ในโค้ด
from .schema import (classify_fields, classify_dataset,
                     detect_text_fields, detect_code_fields, detect_id_fields)
# Task 2: cleansing + dedupe + index (whitelist-gated)
from .cleansing import clean_record, dedupe, clean_and_index, clean_all
# ค้นในไฟล์เร็วแบบ offline: trigram inverted index + LRU cache (whitelist-gated)
from .fast_index import FastIndex, for_dataset as fast_for_dataset, search as fast_search

__all__ = [
    "ALLOWED_DATASETS", "is_allowed", "drive_enabled",
    "get_dataset_path", "get_json", "get_records", "parse_records",
    "sync", "sync_all",
    "profile_dataset", "sql_schema", "profile_records",
    "classify_fields", "classify_dataset",
    "detect_text_fields", "detect_code_fields", "detect_id_fields",
    "clean_record", "dedupe", "clean_and_index", "clean_all",
    "FastIndex", "fast_for_dataset", "fast_search",
]
