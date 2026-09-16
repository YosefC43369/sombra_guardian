# -*- coding: utf-8 -*-
"""reference_data/parsers — เลือก parser ตามชนิดไฟล์ (.json/.csv/.sql) ผ่านหน้าตาเดียวกัน

หน้าตาร่วมของทุก parser (module-level functions):
    stream_records(path, **opts) -> Iterator[dict]   # อ่านแบบ streaming, memory-safe
    parse(path, **opts)          -> List[dict]        # materialize (ไฟล์เล็ก)

ผู้เรียก (dataset_manager) ใช้ stream_records(name, path) โดยไม่ต้องรู้ว่าเป็นฟอร์แมตไหน
ทุก parser คืน "record dict แบน" ที่เทียบเท่ากันข้ามฟอร์แมต
"""

import os
from typing import Iterator, Optional

from . import json_parser, csv_parser, sql_parser

# extension -> parser module
_PARSERS = {
    ".json": json_parser,
    ".jsonl": json_parser,
    ".ndjson": json_parser,
    ".csv": csv_parser,
    ".sql": sql_parser,
}

SUPPORTED_EXTENSIONS = tuple(sorted(_PARSERS.keys()))


def ext_of(name: str) -> str:
    return os.path.splitext(str(name))[1].lower()


def get_parser(name: str):
    """คืน parser module ตามนามสกุลของ `name` — None ถ้าไม่รองรับ"""
    return _PARSERS.get(ext_of(name))


def is_supported(name: str) -> bool:
    return ext_of(name) in _PARSERS


def stream_records(name: str, path, **opts) -> Iterator[dict]:
    """dispatch ตามนามสกุลของ `name` แล้ว stream record dict — คืน iterator ว่างถ้าไม่รองรับ"""
    parser = get_parser(name)
    if parser is None:
        return iter(())
    return parser.stream_records(path, **opts)


def parse(name: str, path, **opts):
    parser = get_parser(name)
    if parser is None:
        return []
    return parser.parse(path, **opts)
