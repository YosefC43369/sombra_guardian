# -*- coding: utf-8 -*-
"""reference_data/drive_client.py — ชั้นเชื่อมต่อ Google Drive (อ่านอย่างเดียว)

รับผิดชอบเฉพาะ: ยืนยันตัวตนด้วย Service Account, หาไฟล์ในโฟลเดอร์ที่กำหนด, และ
ดาวน์โหลดไฟล์ตาม file_id เท่านั้น — ไม่แตะ dataset อื่น ไม่เขียน/ลบบน Drive

ออกแบบให้ "เป็นทางเลือก": ถ้าไม่ได้ตั้งค่า (ไม่มี DRIVE_FOLDER_ID / credential) หรือ
ไม่ได้ติดตั้งไลบรารี google -> is_configured() = False และผู้เรียก (dataset_manager)
จะ fallback ไปใช้ไฟล์ในเครื่องแทน ทำให้บอตทำงานได้เหมือนเดิมทุกประการ

ความปลอดภัย:
  - ขอบเขต read-only (drive.readonly) เท่านั้น
  - credential มาจาก env (GOOGLE_SERVICE_ACCOUNT_JSON = เนื้อ JSON, หรือ
    GOOGLE_APPLICATION_CREDENTIALS = พาธไฟล์) — ไม่ hardcode ในซอร์ส
  - ไม่ log private key / token / เนื้อ credential เด็ดขาด
"""

import os
import io
import json
import time
import logging
import tempfile
from typing import Optional, List

logger = logging.getLogger("modbot.reference_data.drive")

DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID", "").strip()
_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
# ฟิลด์ metadata ที่ขอจาก Drive (ไม่ดึงเนื้อไฟล์ตอน list)
_FILE_FIELDS = "id, name, mimeType, size, modifiedTime, md5Checksum, version"

_MAX_RETRIES = int(os.getenv("DRIVE_MAX_RETRIES", "4") or "4")

_service = None
_service_tried = False


def _load_google():
    """import ไลบรารี google แบบไม่ล้มถ้าไม่มี — คืน (service_account, build, MediaIoBaseDownload) หรือ None"""
    try:
        from google.oauth2 import service_account  # type: ignore
        from googleapiclient.discovery import build  # type: ignore
        from googleapiclient.http import MediaIoBaseDownload  # type: ignore
        return service_account, build, MediaIoBaseDownload
    except Exception:
        return None


def _credentials(service_account):
    """สร้าง credentials จาก env — คืน None ถ้าไม่มี/พัง (ไม่ log เนื้อ credential)"""
    inline = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()
    path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    try:
        if inline:
            info = json.loads(inline)
            return service_account.Credentials.from_service_account_info(info, scopes=_SCOPES)
        if path and os.path.isfile(path):
            return service_account.Credentials.from_service_account_file(path, scopes=_SCOPES)
    except Exception as e:
        # ห้ามใส่ตัวแปรที่อาจมี credential ลง log — บอกแค่ชนิดข้อผิดพลาด
        logger.warning("DRIVE | สร้าง credentials ไม่สำเร็จ (%s)", type(e).__name__)
    return None


def credentials_present() -> bool:
    inline = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()
    path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    return bool(inline) or bool(path and os.path.isfile(path))


def is_configured() -> bool:
    """ตั้งค่าครบพอจะลองต่อ Drive ไหม (มีโฟลเดอร์ + credential + ไลบรารี)"""
    return bool(DRIVE_FOLDER_ID) and credentials_present() and _load_google() is not None


def get_service():
    """สร้าง/แคช Drive service (v3) — คืน None ถ้าปิดใช้/ต่อไม่ได้ (แคชผลรวมถึง None)"""
    global _service, _service_tried
    if _service_tried:
        return _service
    _service_tried = True
    if not DRIVE_FOLDER_ID:
        return None
    libs = _load_google()
    if libs is None:
        logger.info("DRIVE | ไม่ได้ติดตั้งไลบรารี google-api-python-client — ใช้ไฟล์ในเครื่องแทน")
        return None
    service_account, build, _ = libs
    creds = _credentials(service_account)
    if creds is None:
        logger.info("DRIVE | ไม่มี credential ที่ใช้ได้ — ใช้ไฟล์ในเครื่องแทน")
        return None
    try:
        _service = build("drive", "v3", credentials=creds, cache_discovery=False)
        logger.info("DRIVE | เชื่อมต่อ Google Drive (read-only) folder=%s สำเร็จ", DRIVE_FOLDER_ID)
    except Exception as e:
        logger.warning("DRIVE | สร้าง service ไม่สำเร็จ (%s) — ใช้ไฟล์ในเครื่องแทน", type(e).__name__)
        _service = None
    return _service


def _retry(fn, what: str):
    """เรียก API พร้อม retry แบบ exponential backoff (2^n วินาที) — คืน None เมื่อหมดโอกาส"""
    delay = 2.0
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            return fn()
        except Exception as e:
            if attempt >= _MAX_RETRIES:
                logger.warning("DRIVE | %s ล้มเหลวหลังลอง %d ครั้ง (%s)", what, attempt, type(e).__name__)
                return None
            logger.info("DRIVE | %s ล้มเหลว (ครั้งที่ %d) รออีก %.0fs (%s)",
                        what, attempt, delay, type(e).__name__)
            time.sleep(delay)
            delay *= 2
    return None


def _to_meta(f: dict) -> dict:
    return {
        "file_id": f.get("id"),
        "name": f.get("name"),
        "mime_type": f.get("mimeType"),
        "size": int(f.get("size") or 0),
        "modified_time": f.get("modifiedTime"),
        "md5": f.get("md5Checksum"),
        "version": f.get("version"),
    }


def find_file(name: str, allowed: Optional[set] = None) -> Optional[dict]:
    """หา metadata ของไฟล์ชื่อ `name` ในโฟลเดอร์ที่กำหนด — คืน None ถ้าไม่พบ/ต่อไม่ได้

    ใช้เฉพาะ metadata ของ Drive (ไม่ดาวน์โหลดเนื้อไฟล์) และปฏิเสธชื่อที่ไม่อยู่ใน allowed
    """
    if allowed is not None and name not in allowed:
        return None
    service = get_service()
    if service is None:
        return None
    safe = name.replace("'", r"\'")
    query = (f"name = '{safe}' and '{DRIVE_FOLDER_ID}' in parents and trashed = false")

    def _do():
        return service.files().list(
            q=query, fields=f"files({_FILE_FIELDS})", pageSize=10,
            supportsAllDrives=True, includeItemsFromAllDrives=True,
        ).execute()

    resp = _retry(_do, f"find_file({name})")
    if not resp:
        return None
    files = resp.get("files", [])
    # เลือกไฟล์ที่ชื่อ "ตรงเป๊ะ" (Drive query เป็น exact แต่ป้องกันไว้อีกชั้น)
    for f in files:
        if f.get("name") == name:
            return _to_meta(f)
    return None


def download(file_id: str, dest_path) -> bool:
    """ดาวน์โหลดไฟล์ตาม file_id ไปยัง dest_path (stream) — คืน True เมื่อสำเร็จ"""
    libs = _load_google()
    service = get_service()
    if libs is None or service is None or not file_id:
        return False
    _, _, MediaIoBaseDownload = libs

    def _do():
        request = service.files().get_media(fileId=file_id)
        with open(dest_path, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request, chunksize=4 * 1024 * 1024)
            done = False
            while not done:
                _, done = downloader.next_chunk()
        return True

    ok = _retry(_do, f"download({file_id})")
    if not ok:
        try:
            os.unlink(dest_path)
        except OSError:
            pass
        return False
    return True
