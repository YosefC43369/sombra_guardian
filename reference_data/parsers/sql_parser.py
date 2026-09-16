# -*- coding: utf-8 -*-
"""reference_data/parsers/sql_parser.py — parser สำหรับ .sql dump (อ่านเป็น "ข้อมูล" เท่านั้น)

⚠️ ความปลอดภัย: โมดูลนี้ "ไม่รัน SQL" ใด ๆ ทั้งสิ้น — เป็นตัวแยกข้อความ (text parser)
ล้วน ๆ ที่อ่านเฉพาะ CREATE TABLE (เพื่อรู้ชื่อคอลัมน์) และ INSERT ... VALUES (...)
(เพื่อดึงข้อมูลเป็นแถว) เท่านั้น คำสั่งอื่น (DROP/DELETE/UPDATE/ALTER/GRANT/CREATE USER
ฯลฯ) ถูก "เพิกเฉย" ไม่ถูกประมวลผลและไม่มีวันถูกรัน เพราะไม่มีการเชื่อมต่อฐานข้อมูลใด ๆ

คืน record dict แบน (คีย์ = ชื่อคอลัมน์) ให้รูปแบบเดียวกับ JSON/CSV parser
รองรับไฟล์ใหญ่: อ่านเป็นก้อน (chunk) แล้วตัดเป็น statement ทีละอัน (ไม่โหลดทั้งไฟล์
เข้า RAM) — statement เสียแยกเป็นราย statement ไม่ทำทั้งไฟล์พัง
"""

import re
import logging
from typing import Iterator, Dict, List, Optional, Tuple

logger = logging.getLogger("modbot.reference_data.parsers.sql")

_CHUNK = 1 << 20  # 1 MB

_CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?([A-Za-z0-9_$]+)[`\"']?\s*\((.*)\)",
    re.IGNORECASE | re.DOTALL)
_INSERT_RE = re.compile(
    r"INSERT\s+(?:IGNORE\s+)?INTO\s+[`\"']?([A-Za-z0-9_$]+)[`\"']?\s*(?:\(([^)]*)\)\s*)?VALUES\s*(.*)",
    re.IGNORECASE | re.DOTALL)

_CONSTRAINT_KW = {"PRIMARY", "UNIQUE", "KEY", "CONSTRAINT", "FOREIGN",
                  "INDEX", "FULLTEXT", "SPATIAL", "CHECK"}


def _split_top_level(s: str, sep: str) -> List[str]:
    """แยก string ด้วย `sep` เฉพาะที่ "ระดับบนสุด" — ไม่แยกภายในเครื่องหมายคำพูดหรือ ()"""
    out, buf = [], []
    depth = 0
    quote = None
    esc = False
    for ch in s:
        if esc:
            buf.append(ch); esc = False; continue
        if quote:
            buf.append(ch)
            if ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch; buf.append(ch); continue
        if ch == "(":
            depth += 1; buf.append(ch); continue
        if ch == ")":
            depth -= 1; buf.append(ch); continue
        if ch == sep and depth == 0:
            out.append("".join(buf)); buf = []; continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def _clean_ident(tok: str) -> str:
    return tok.strip().strip("`\"'").strip()


def _parse_value(tok: str):
    """แปลง literal ของ SQL เป็นค่า Python (string/None) — ไม่ประเมิน expression"""
    t = tok.strip()
    if not t or t.upper() == "NULL":
        return None
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"', "`"):
        inner = t[1:-1]
        inner = (inner.replace("\\'", "'").replace('\\"', '"')
                 .replace("''", "'").replace('\\\\', '\\')
                 .replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r"))
        return inner
    return t  # ตัวเลข/คีย์เวิร์ด — เก็บเป็น string ตามเดิม


def _iter_statements(path) -> Iterator[str]:
    """อ่านไฟล์เป็นก้อนแล้ว yield statement ทีละอัน (ตัดที่ ';' ระดับบนสุด)"""
    buf: List[str] = []
    depth = 0
    quote = None
    esc = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                for ch in chunk:
                    buf.append(ch)
                    if esc:
                        esc = False; continue
                    if quote:
                        if ch == "\\":
                            esc = True
                        elif ch == quote:
                            quote = None
                        continue
                    if ch in ("'", '"', "`"):
                        quote = ch; continue
                    if ch == "(":
                        depth += 1; continue
                    if ch == ")":
                        depth -= 1; continue
                    if ch == ";" and depth == 0:
                        yield "".join(buf); buf = []
    except OSError as e:
        logger.warning("SQL | อ่านไฟล์ไม่ได้ %s (%s)", path, e)
        return
    tail = "".join(buf).strip()
    if tail:
        yield tail


def _strip_comments(stmt: str) -> str:
    """ตัดคอมเมนต์แบบ -- และ /* */ ที่อยู่ "นอกเครื่องหมายคำพูด" ออก (กันพลาดในสตริง)"""
    out = []
    i, n = 0, len(stmt)
    quote = None
    while i < n:
        ch = stmt[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(stmt[i + 1]); i += 2; continue
            if ch == quote:
                quote = None
            i += 1; continue
        if ch in ("'", '"', "`"):
            quote = ch; out.append(ch); i += 1; continue
        if ch == "-" and i + 1 < n and stmt[i + 1] == "-":
            while i < n and stmt[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and stmt[i + 1] == "*":
            i += 2
            while i + 1 < n and not (stmt[i] == "*" and stmt[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch); i += 1
    return "".join(out)


def _parse_create(stmt: str, tables: Dict[str, List[str]]) -> None:
    m = _CREATE_RE.search(stmt)
    if not m:
        return
    table = _clean_ident(m.group(1)).lower()
    cols = []
    for part in _split_top_level(m.group(2), ","):
        p = part.strip()
        if not p:
            continue
        first = p.split()[0] if p.split() else ""
        if _clean_ident(first).upper() in _CONSTRAINT_KW:
            continue
        cols.append(_clean_ident(first))
    if cols:
        tables[table] = cols


def _parse_insert(stmt: str, tables: Dict[str, List[str]]) -> Iterator[Tuple[str, dict]]:
    m = _INSERT_RE.search(stmt)
    if not m:
        return
    table = _clean_ident(m.group(1))
    col_str = m.group(2)
    cols: Optional[List[str]] = None
    if col_str:
        cols = [_clean_ident(c) for c in _split_top_level(col_str, ",")]
    elif table.lower() in tables:
        cols = tables[table.lower()]
    for tup in _split_top_level(m.group(3), ","):
        t = tup.strip()
        if not (t.startswith("(") and t.endswith(")")):
            continue
        fields = _split_top_level(t[1:-1], ",")
        vals = [_parse_value(x) for x in fields]
        if cols and len(cols) == len(vals):
            rec = dict(zip(cols, vals))
        else:
            rec = {f"col{i}": v for i, v in enumerate(vals)}
        yield table, rec


def list_tables(path) -> Dict[str, List[str]]:
    """สแกนเฉพาะ CREATE TABLE เพื่อคืน {ชื่อตาราง: [คอลัมน์]} (ไม่ดึงข้อมูล)"""
    tables: Dict[str, List[str]] = {}
    for stmt in _iter_statements(path):
        s = _strip_comments(stmt).strip().rstrip(";").strip()
        if s[:12].upper().startswith("CREATE TABLE"):
            try:
                _parse_create(s, tables)
            except Exception:
                continue
    return tables


def stream_records(path, with_table: bool = False, **opts) -> Iterator[dict]:
    """yield record dict ทีละแถวจาก INSERT — memory-safe, ไม่รัน SQL, ไม่ throw

    with_table=True จะห่อเป็น {"table": ชื่อตาราง, "data": {...}} เผื่อผู้เรียกต้องการ
    ชื่อตาราง (ดีฟอลต์คืน dict แบนเพื่อให้เทียบเท่ากับ JSON/CSV)
    """
    tables: Dict[str, List[str]] = {}
    for stmt in _iter_statements(path):
        s = _strip_comments(stmt).strip().rstrip(";").strip()
        if not s:
            continue
        head = s[:12].upper()
        if head.startswith("CREATE TABLE"):
            try:
                _parse_create(s, tables)
            except Exception as e:
                logger.debug("SQL | CREATE TABLE parse ล้มเหลว (%s)", e)
        elif head.startswith("INSERT"):
            try:
                for table, rec in _parse_insert(s, tables):
                    yield {"table": table, "data": rec} if with_table else rec
            except Exception as e:
                logger.debug("SQL | INSERT parse ล้มเหลว (%s)", e)
        # คำสั่งอื่น ๆ (DROP/DELETE/UPDATE/ALTER/GRANT/…) -> เพิกเฉย ไม่ประมวลผล


def parse(path, **opts):
    return list(stream_records(path, **opts))
