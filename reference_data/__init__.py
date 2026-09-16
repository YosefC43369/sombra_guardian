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

from .dataset_manager import (
    ALLOWED_DATASETS,
    is_allowed,
    drive_enabled,
    get_dataset_path,
    get_json,
    sync,
    sync_all,
)

__all__ = [
    "ALLOWED_DATASETS", "is_allowed", "drive_enabled",
    "get_dataset_path", "get_json", "sync", "sync_all",
]
