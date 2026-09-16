# -*- coding: utf-8 -*-
"""reference_data/parsers/csv_parser.py — parser สำหรับ .csv

คืน record dict แบนต่อแถว (คีย์ = ชื่อคอลัมน์จาก header) ให้รูปแบบเดียวกับ JSON/SQL

คุณสมบัติ:
  - อ่านแบบ streaming (csv.reader เป็น iterator) — ไม่โหลดทั้งไฟล์เข้า RAM
  - UTF-8 (รองรับ BOM ผ่าน utf-8-sig) + errors="replace" กันไฟล์ encoding เพี้ยน
  - เดา delimiter อัตโนมัติ (, ; \\t |) หรือกำหนดเองผ่าน arg/env REFERENCE_CSV_DELIMITER
  - เดา header ถ้ามี; ถ้าไม่มีจะตั้งชื่อคอลัมน์เป็น col0, col1, ... แล้วนับแถวแรกเป็นข้อมูล
  - รองรับ quoting/คอมมา/ขึ้นบรรทัดใหม่ในฟิลด์ที่ครอบเครื่องหมายคำพูด (csv มาตรฐาน)
  - แถวเสียแยกเป็นรายแถว ไม่ทำทั้งไฟล์พัง
"""

import os
import csv
import logging
from typing import Iterator, Optional

logger = logging.getLogger("modbot.reference_data.parsers.csv")

# กัน field ยักษ์ทำ csv ระเบิด (ไฟล์อ้างอิงปกติไม่ยาวขนาดนั้น)
try:
    csv.field_size_limit(16 * 1024 * 1024)
except Exception:
    pass


def _sniff(sample: str, delimiter: Optional[str]):
    """คืน (delimiter, has_header)"""
    if delimiter:
        return delimiter, True
    delim = ","
    has_header = True
    try:
        delim = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except Exception:
        pass
    try:
        has_header = csv.Sniffer().has_header(sample)
    except Exception:
        has_header = True
    return delim, has_header


def stream_records(path, delimiter: Optional[str] = None, **opts) -> Iterator[dict]:
    """yield record dict ทีละแถว — memory-safe, ไม่ throw"""
    delim = (delimiter or os.getenv("REFERENCE_CSV_DELIMITER", "").strip() or None)
    try:
        f = open(path, "r", encoding="utf-8-sig", newline="", errors="replace")
    except OSError as e:
        logger.warning("CSV | เปิดไฟล์ไม่ได้ %s (%s)", path, e)
        return
    with f:
        sample = f.read(65536)
        f.seek(0)
        if not sample.strip():
            return
        d, has_header = _sniff(sample, delim)
        reader = csv.reader(f, delimiter=d)
        header = None
        for row in reader:
            try:
                if not row or all(c == "" for c in row):
                    continue
                if header is None:
                    if has_header:
                        header = [c.strip() for c in row]
                        continue
                    header = [f"col{i}" for i in range(len(row))]
                    # ไม่มี header -> แถวแรกเป็นข้อมูล ตกลงมา yield ต่อ
                rec = {}
                for i, val in enumerate(row):
                    key = header[i] if i < len(header) else f"col{i}"
                    rec[key] = val
                yield rec
            except Exception as e:
                logger.debug("CSV | ข้ามแถวเสีย (%s)", e)
                continue


def parse(path, **opts):
    return list(stream_records(path, **opts))
