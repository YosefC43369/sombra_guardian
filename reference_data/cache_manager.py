# -*- coding: utf-8 -*-
"""reference_data/cache_manager.py — RAM + disk cache สำหรับ dataset อ้างอิง

สองชั้น:
  - RAM cache: เก็บ "อ็อบเจกต์ JSON ที่ parse แล้ว" ของ dataset ที่ใช้ล่าสุด (LRU)
  - Disk cache: เก็บไฟล์ที่ดาวน์โหลดจาก Google Drive ไว้ในเครื่องชั่วคราว พร้อม
    metadata sidecar (file_id / modified_time / md5 / size / cached_at) เพื่อใช้
    ตัดสินว่า cache ยัง "ตรงกับ Drive" อยู่ไหม

เป็น stdlib ล้วน (ไม่พึ่ง google libs) จึงเทสต์ได้โดยไม่ต้องมี Drive จริง
"""

import os
import json
import time
import hashlib
import logging
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Optional

logger = logging.getLogger("modbot.reference_data.cache")

# โฟลเดอร์ cache (ชั่วคราวบน VPS) — override ด้วย env DRIVE_CACHE_DIR
CACHE_DIR = Path(os.getenv("DRIVE_CACHE_DIR", "").strip() or "./cache/reference")
# อายุ cache ก่อนจะ "แวะถาม Drive ว่ามีเวอร์ชันใหม่ไหม" (วินาที) — ไม่ใช่การลบไฟล์
CACHE_TTL = int(os.getenv("REFERENCE_CACHE_TTL", "3600") or "3600")
# จำนวน dataset สูงสุดที่เก็บใน RAM (ชุดข้อมูลอ้างอิงมีไม่กี่ไฟล์ ใช้ค่าน้อย)
RAM_MAX_ENTRIES = int(os.getenv("REFERENCE_RAM_MAX_ENTRIES", "8") or "8")

# RAM cache: name -> {"sig": <file signature>, "obj": <parsed json>}
_ram: "OrderedDict[str, dict]" = OrderedDict()


def cache_dir() -> Path:
    return CACHE_DIR


def _subdir(name: str) -> str:
    """โฟลเดอร์ย่อยของ cache ตามชนิดไฟล์ (json/csv/sql/other) — เก็บคงรูปแบบเดิมไว้"""
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    return ext if ext in ("json", "csv", "sql") else "other"


def cache_file(name: str) -> Path:
    return CACHE_DIR / _subdir(name) / name


def meta_file(name: str) -> Path:
    return CACHE_DIR / _subdir(name) / f"{name}.meta.json"


def _ensure_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_parent(path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


# ---------------- metadata sidecar ----------------

def load_meta(name: str) -> dict:
    """อ่าน metadata ของ cache — คืน {} ถ้าไม่มี/อ่านไม่ได้"""
    try:
        with open(meta_file(name), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_meta(name: str, meta: dict) -> None:
    """เขียน metadata แบบ atomic"""
    target = meta_file(name)
    _ensure_parent(target)
    fd, tmp = tempfile.mkstemp(prefix=".meta.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------- disk cache ----------------

def cache_exists(name: str) -> bool:
    """มีไฟล์ cache ครบ (ทั้งไฟล์ข้อมูลและ metadata) ไหม"""
    return cache_file(name).is_file() and meta_file(name).is_file()


def file_md5(path) -> str:
    """คำนวณ md5 ของไฟล์ (ตรงกับ md5Checksum ที่ Google Drive ให้มา) — '' ถ้าอ่านไม่ได้"""
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def verify_integrity(name: str, expected_md5: Optional[str] = None) -> bool:
    """ตรวจว่าไฟล์ cache ยังสมบูรณ์ (md5 ตรงกับที่บันทึกไว้/ที่ Drive แจ้ง)

    ถ้าไม่มี md5 ให้เทียบ (เช่น Drive ไม่ส่ง md5Checksum มา) ให้ผ่านเมื่อไฟล์อ่านได้
    """
    path = cache_file(name)
    if not path.is_file():
        return False
    expected = expected_md5 or load_meta(name).get("md5")
    if not expected:
        return path.stat().st_size > 0
    return file_md5(path) == expected


def is_current(name: str, remote_meta: dict) -> bool:
    """cache ตรงกับเวอร์ชันบน Drive ไหม — เทียบ md5 ก่อน ถ้าไม่มีค่อยเทียบ
    (file_id + modified_time)"""
    if not cache_exists(name):
        return False
    local = load_meta(name)
    r_md5 = remote_meta.get("md5")
    l_md5 = local.get("md5")
    if r_md5 and l_md5:
        return r_md5 == l_md5 and verify_integrity(name, r_md5)
    # ไม่มี md5 -> ใช้ file_id + modified_time เป็นตัวชี้เวอร์ชัน
    return (bool(local.get("file_id"))
            and local.get("file_id") == remote_meta.get("file_id")
            and local.get("modified_time") == remote_meta.get("modified_time")
            and cache_file(name).stat().st_size > 0)


def should_recheck_drive(name: str) -> bool:
    """ควรแวะถาม Drive ไหม (ผ่าน TTL แล้วหรือยังไม่เคย cache) — ลดจำนวน API call"""
    meta = load_meta(name)
    checked = meta.get("checked_at")
    if not checked:
        return True
    return (time.time() - float(checked)) >= CACHE_TTL


def touch_checked(name: str) -> None:
    """บันทึกเวลาที่เพิ่งถาม Drive ล่าสุด (ใช้กับ TTL)"""
    meta = load_meta(name)
    meta["checked_at"] = time.time()
    save_meta(name, meta)


def write_cache(name: str, src_path, remote_meta: dict) -> Path:
    """ย้ายไฟล์ที่ดาวน์โหลดมาเข้ากล่อง cache + บันทึก metadata (atomic)"""
    dest = cache_file(name)
    _ensure_parent(dest)
    os.replace(str(src_path), str(dest))
    meta = dict(remote_meta or {})
    meta.setdefault("md5", file_md5(dest))
    meta["filename"] = name
    meta["file_type"] = _subdir(name)
    meta["size"] = dest.stat().st_size
    meta["cached_at"] = time.time()
    meta["checked_at"] = time.time()
    save_meta(name, meta)
    ram_clear(name)  # ไฟล์เปลี่ยน -> ล้าง RAM cache ของ dataset นี้
    return dest


def clear_disk(name: str) -> None:
    """ลบไฟล์ cache + metadata ของ dataset นี้ (ใช้ตอน cache เสีย/ต้อง rebuild)"""
    for p in (cache_file(name), meta_file(name)):
        try:
            p.unlink()
        except OSError:
            pass
    ram_clear(name)


# ---------------- RAM cache ----------------

def _signature(path) -> Optional[tuple]:
    """ลายเซ็นไฟล์ (mtime, size) ใช้ตรวจว่า RAM cache ยังตรงกับไฟล์บนดิสก์ไหม"""
    try:
        st = os.stat(path)
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


def ram_get(name: str, path):
    """คืนอ็อบเจกต์ JSON จาก RAM ถ้ายังตรงกับไฟล์ปัจจุบัน มิฉะนั้น None"""
    entry = _ram.get(name)
    if not entry:
        return None
    if entry.get("sig") != _signature(path):
        _ram.pop(name, None)
        return None
    _ram.move_to_end(name)
    return entry.get("obj")


def ram_put(name: str, path, obj) -> None:
    _ram[name] = {"sig": _signature(path), "obj": obj}
    _ram.move_to_end(name)
    while len(_ram) > max(1, RAM_MAX_ENTRIES):
        _ram.popitem(last=False)


def ram_clear(name: str) -> None:
    _ram.pop(name, None)


def clear_all_ram() -> None:
    _ram.clear()
