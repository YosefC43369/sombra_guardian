# -*- coding: utf-8 -*-
"""reference_data/dataset_manager.py — ตัวประสานงานโหลด dataset อ้างอิงจาก Google Drive

รับผิดชอบเฉพาะไฟล์อ้างอิงที่ "ไม่ใช่ข้อมูลส่วนบุคคล" 2 ไฟล์เท่านั้น (whitelist แข็ง):
    airports.json, programming-languages.json

flow:
    ขอ path ของ dataset -> ถ้าตั้งค่า Drive: เทียบ cache กับ metadata บน Drive
      -> ตรงกัน = ใช้ cache / ไม่ตรง = ดาวน์โหลดใหม่ + ตรวจ integrity + อัปเดต cache
    -> ถ้า Drive ใช้ไม่ได้/ไม่ได้ตั้งค่า: ใช้ไฟล์ในเครื่อง (resource/) เหมือนเดิม

หลักการ:
  - Google Drive = source of truth; cache/RAM = ข้อมูลอนุพันธ์ (สร้างใหม่ได้เสมอ)
  - ไฟล์นอก whitelist = เพิกเฉย ไม่ index/ดาวน์โหลด
  - ไม่ crash บอตไม่ว่ากรณีใด: ทุกทางลงเอยด้วย path/JSON ที่ใช้ได้ หรือ None + log
  - ไม่ทำให้ dataset หนึ่งพังเพราะอีก dataset หนึ่งพัง (แยก try/except ต่อไฟล์)
"""

import os
import json
import logging
import tempfile
from pathlib import Path
from typing import Optional

from . import cache_manager as cache
from . import drive_client as drive
from . import parsers

logger = logging.getLogger("modbot.reference_data")

# whitelist แข็ง — เฉพาะ dataset อ้างอิงที่ไม่ใช่ PII 2 ชุด ในฟอร์แมต .json/.csv/.sql
# (ไม่ใช่ระบบค้นฐานข้อมูล/leak/PII — ไฟล์อื่นในโฟลเดอร์ Drive ถูกเพิกเฉยเสมอ)
_DATASET_STEMS = ("123rf.com member", "data_tour", "database", "haamor_db", "geniusu_users", "information_schema",
                  "mysql", "northern.ac.th", "Parkmobile.us_2021-03-21.9M", "PeopleDataLabs_416M", "performance_schema",
                  "phpmyadmin", "query_zego", "tb_customer", "tour_system")
_DATASET_EXTS = (".json", ".csv", ".sql")
ALLOWED_DATASETS = {f"{stem}{ext}" for stem in _DATASET_STEMS for ext in _DATASET_EXTS}

# ไฟล์สำรองในเครื่อง (พฤติกรรมเดิมของบอต) — ใช้เมื่อไม่ได้ตั้งค่า Drive หรือ Drive ล่ม
_RESOURCE_DIR = Path(__file__).resolve().parent.parent / "resource"
LOCAL_FALLBACK = {name: _RESOURCE_DIR / name for name in ALLOWED_DATASETS}


def is_allowed(name: str) -> bool:
    return name in ALLOWED_DATASETS


def drive_enabled() -> bool:
    """ตั้งค่า Google Drive ไว้ใช้งานไหม (มีโฟลเดอร์+credential+ไลบรารี)"""
    return drive.is_configured()


def _local_fallback_path(name: str) -> Optional[str]:
    p = LOCAL_FALLBACK.get(name)
    if p and p.is_file():
        return str(p)
    return None


def _refresh_from_drive(name: str) -> Optional[str]:
    """ตรวจ/ดึงเวอร์ชันล่าสุดจาก Drive ถ้าจำเป็น — คืน path ของ cache ที่พร้อมใช้ หรือ None

    - ถ้ายังไม่ถึง TTL และมี cache อยู่แล้ว: ใช้ cache เลย (ลด API call)
    - ถ้าถึง TTL: ถาม metadata; ตรงกับ cache = ใช้ cache / ไม่ตรง = ดาวน์โหลดใหม่
    """
    have_cache = cache.cache_exists(name)
    if have_cache and not cache.should_recheck_drive(name):
        return str(cache.cache_file(name))

    remote = drive.find_file(name, allowed=ALLOWED_DATASETS)
    if not remote or not remote.get("file_id"):
        # หาไฟล์บน Drive ไม่เจอ/ต่อไม่ได้ -> ใช้ cache เดิมถ้ามี
        if have_cache:
            logger.info("REFDATA | %s: ถาม Drive ไม่ได้ ใช้ cache เดิม", name)
            return str(cache.cache_file(name))
        return None

    if have_cache and cache.is_current(name, remote):
        cache.touch_checked(name)          # อัปเดตเวลา TTL แต่ไม่ดาวน์โหลดซ้ำ
        logger.info("REFDATA | %s: cache ตรงกับ Drive (ไม่ดาวน์โหลด)", name)
        return str(cache.cache_file(name))

    # เวอร์ชันเปลี่ยน/ยังไม่มี cache -> ดาวน์โหลดใหม่ลงไฟล์ชั่วคราวก่อน
    logger.info("REFDATA | %s: พบเวอร์ชันใหม่บน Drive — กำลังดาวน์โหลด", name)
    cache._ensure_dir()
    fd, tmp = tempfile.mkstemp(prefix=f".dl.{name}.", dir=str(cache.cache_dir()))
    os.close(fd)
    if not drive.download(remote["file_id"], tmp):
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if have_cache:
            logger.warning("REFDATA | %s: ดาวน์โหลดไม่สำเร็จ ใช้ cache เดิม", name)
            return str(cache.cache_file(name))
        return None

    # ตรวจ integrity เทียบ md5 ที่ Drive แจ้ง (ถ้ามี) ก่อนรับเข้า cache
    expected = remote.get("md5")
    if expected and cache.file_md5(tmp) != expected:
        logger.warning("REFDATA | %s: md5 ไม่ตรงหลังดาวน์โหลด — ทิ้งไฟล์", name)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if have_cache:
            return str(cache.cache_file(name))
        return None

    dest = cache.write_cache(name, tmp, remote)
    logger.info("REFDATA | %s: อัปเดต cache เรียบร้อย (%d bytes)", name, dest.stat().st_size)
    return str(dest)


def get_dataset_path(name: str) -> Optional[str]:
    """คืน path ในเครื่องของ dataset ที่ "เป็นเวอร์ชันปัจจุบัน" — พร้อมให้โค้ดเดิมเปิดอ่าน

    ไม่เคยโยน exception: ทุก error path จะ log แล้วถอยไปใช้ cache เดิม/ไฟล์ในเครื่อง
    ไฟล์นอก whitelist -> คืน None (เพิกเฉย)
    """
    if not is_allowed(name):
        logger.debug("REFDATA | เพิกเฉยไฟล์นอก whitelist: %s", name)
        return None

    if not drive_enabled():
        return _local_fallback_path(name)   # พฤติกรรมเดิม 100%

    try:
        path = _refresh_from_drive(name)
    except Exception:
        logger.exception("REFDATA | %s: ผิดพลาดระหว่างซิงก์ Drive", name)
        path = None

    if path and os.path.isfile(path):
        return path
    # Drive/แคชใช้ไม่ได้ -> ไฟล์ในเครื่องเป็นทางออกสุดท้าย
    fallback = _local_fallback_path(name)
    if fallback:
        logger.info("REFDATA | %s: ถอยไปใช้ไฟล์ในเครื่อง", name)
    return fallback


def get_json(name: str):
    """คืนอ็อบเจกต์ JSON ของ dataset (แคชใน RAM) — คืน None ถ้าโหลด/parse ไม่ได้

    ปลอดภัยต่อไฟล์เสีย: JSON พังของไฟล์หนึ่งจะไม่กระทบไฟล์อื่นหรือทำบอตล่ม
    """
    if not is_allowed(name):
        return None
    path = get_dataset_path(name)
    if not path:
        return None
    cached = cache.ram_get(name, path)
    if cached is not None:
        return cached
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("REFDATA | %s: อ่าน/parse JSON ไม่สำเร็จ (%s)", name, e)
        # cache น่าจะเสีย -> ลบทิ้งเพื่อให้รอบหน้าดึงใหม่จาก Drive (source of truth)
        if drive_enabled() and cache.cache_exists(name):
            cache.clear_disk(name)
        return None
    cache.ram_put(name, path, obj)
    return obj


def get_records(name: str, **opts):
    """คืน iterator ของ "record dict แบน" จาก dataset (รองรับ .json/.csv/.sql)

    เลือก parser ตามนามสกุลไฟล์อัตโนมัติ แล้ว stream ทีละเรกคอร์ด (memory-safe —
    เหมาะกับไฟล์ใหญ่) โดยผู้เรียกไม่ต้องรู้ว่าเป็นฟอร์แมตไหน ทุกฟอร์แมตคืนโครงเดียวกัน

    ไม่ throw: ไฟล์นอก whitelist / โหลดไม่ได้ / ฟอร์แมตไม่รองรับ -> iterator ว่าง
    ไฟล์เสียของชุดหนึ่งจะไม่กระทบชุดอื่น (parser จัดการ error ภายในเป็นราย record)
    """
    if not is_allowed(name):
        return iter(())
    path = get_dataset_path(name)
    if not path:
        return iter(())
    return parsers.stream_records(name, path, **opts)


def parse_records(name: str, **opts):
    """materialize get_records เป็น list (สำหรับไฟล์เล็ก/เทส) — ระวังไฟล์ใหญ่"""
    return list(get_records(name, **opts))


def sync(name: str) -> bool:
    """ซิงก์ dataset เดียวจาก Drive (ใช้ตอน startup/manual) — คืน True ถ้าได้ path ที่ใช้ได้"""
    if not is_allowed(name):
        return False
    return bool(get_dataset_path(name))


def sync_all() -> dict:
    """ซิงก์ทุก dataset ใน whitelist — แยกความล้มเหลวต่อไฟล์ ไม่ให้ไฟล์หนึ่งทำอีกไฟล์พัง

    คืน {name: bool} ว่าแต่ละไฟล์พร้อมใช้ไหม (ไม่ throw)
    """
    result = {}
    for name in sorted(ALLOWED_DATASETS):
        try:
            result[name] = sync(name)
        except Exception:
            logger.exception("REFDATA | sync %s ผิดพลาด", name)
            result[name] = False
    logger.info("REFDATA | ซิงก์เสร็จ: %s (drive=%s)", result, drive_enabled())
    return result
