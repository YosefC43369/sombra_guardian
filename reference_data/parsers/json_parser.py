# -*- coding: utf-8 -*-
"""reference_data/parsers/json_parser.py — parser สำหรับ .json / .jsonl

คืน "record dict แบน" ต่อรายการ ให้รูปแบบเดียวกับ CSV/SQL parser:
  - ไฟล์เป็น array           -> yield แต่ละ element (dict)
  - ไฟล์เป็น {"key": [...]}   -> yield แต่ละ element ของ array นั้น (เช่น {"airports":[...]})
  - ไฟล์เป็น dict-คีย์-ด้วยรหัส -> yield แต่ละ value (ฉีดคีย์เป็น field "code")
  - .jsonl / .ndjson         -> yield ทีละบรรทัด

ปลอดภัยต่อไฟล์ใหญ่: ถ้าติดตั้ง ijson และไฟล์เป็น array ล้วน จะ stream ด้วย ijson
(ไม่โหลดทั้งไฟล์เข้า RAM) มิฉะนั้น fallback ไป json.load — JSON เสีย/ว่างจะ yield ว่าง
ไม่ throw
"""

import os
import json
import logging
from typing import Iterator

logger = logging.getLogger("modbot.reference_data.parsers.json")

# ไฟล์ใหญ่กว่านี้ (ไบต์) จะพยายาม stream ด้วย ijson ถ้ามี
_LARGE = int(os.getenv("REFERENCE_JSON_STREAM_BYTES", str(8 * 1024 * 1024)) or 0)


def _ijson():
    try:
        import ijson  # type: ignore
        return ijson
    except Exception:
        return None


def _first_char(path) -> str:
    try:
        with open(path, "rb") as f:
            while True:
                c = f.read(1)
                if not c:
                    return ""
                if not c.isspace():
                    return c.decode("latin1", "ignore")
    except OSError:
        return ""


def _as_record(x):
    return x if isinstance(x, dict) else {"value": x}


def _iter_obj(obj) -> Iterator[dict]:
    if obj is None:
        return
    if isinstance(obj, list):
        for x in obj:
            yield _as_record(x)
    elif isinstance(obj, dict):
        list_vals = [v for v in obj.values() if isinstance(v, list)]
        if len(obj) == 1 and len(list_vals) == 1:
            yield from _iter_obj(list_vals[0])            # {"airports":[...]}
        elif obj and all(isinstance(v, dict) for v in obj.values()):
            for key, val in obj.items():                  # dict-คีย์-ด้วยรหัส
                rec = dict(val)
                rec.setdefault("code", key)
                yield rec
        else:
            yield obj                                     # เรกคอร์ดเดียว


def _iter_jsonl(path) -> Iterator[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                yield _as_record(obj)
    except OSError:
        return


def stream_records(path, **opts) -> Iterator[dict]:
    """yield record dict ทีละรายการจากไฟล์ JSON/JSONL — memory-safe, ไม่ throw"""
    ext = os.path.splitext(str(path))[1].lower()
    if ext in (".jsonl", ".ndjson"):
        yield from _iter_jsonl(path)
        return

    # ไฟล์ใหญ่ + เป็น array ล้วน -> stream ด้วย ijson (ถ้ามี)
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if _LARGE and size >= _LARGE and _first_char(path) == "[":
        ij = _ijson()
        if ij is not None:
            try:
                with open(path, "rb") as f:
                    for item in ij.items(f, "item"):
                        yield _as_record(item)
                return
            except Exception as e:
                logger.debug("JSON | ijson stream ล้มเหลว (%s) — fallback json.load", e)

    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("JSON | อ่าน/parse ไม่สำเร็จ %s (%s)", path, e)
        return
    yield from _iter_obj(obj)


def parse(path, **opts):
    """materialize เป็น list (สำหรับไฟล์เล็ก) — ใช้ stream_records ข้างใน"""
    return list(stream_records(path, **opts))
