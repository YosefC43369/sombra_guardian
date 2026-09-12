"""
envutil.py — ตัวอ่าน environment variable ที่ทน "ค่าว่าง" ได้

ทำไมต้องมี: os.getenv(name, default) คืน "" เมื่อคีย์ถูกตั้งไว้แต่ปล่อยค่าว่าง
(เช่น `REPO_TEST_TIMEOUT_SECONDS=` ใน .env) ไม่ได้คืน default ตามที่หลายคนเข้าใจ
ผลคือ int("") / float("") ระเบิดตั้งแต่ตอน import ทำให้ทั้งโมดูลโหลดไม่ได้และ
บอทสตาร์ทไม่ขึ้น ตัวอ่านที่นี่ถือว่า "ค่าว่าง = ไม่ได้ตั้ง" ซึ่งเป็นพฤติกรรม
ที่ถูกต้องกับไฟล์ .env ที่ commit ไว้จริง (มีคีย์ค่าว่างหลายตัว)

nethealth.py มีชุดเดียวกันอยู่แล้วสำหรับ search/scrape — ไฟล์นี้แยกออกมาให้
โมดูลอื่น (quota, news, repository_sandbox, app, blockchain) ใช้ร่วมได้โดยไม่ต้อง
ผูกกับ nethealth ซึ่งเป็นคนละความรับผิดชอบ
"""

import os
import logging

logger = logging.getLogger("modbot.env")


def raw(name, default=""):
    """ค่าดิบของ env — คืน default เมื่อไม่ได้ตั้งหรือตั้งเป็นค่าว่าง/ช่องว่าง"""
    value = os.getenv(name)
    if value is None or not str(value).strip():
        return str(default)
    return str(value).strip()


def env_int(name, default):
    try:
        return int(raw(name, default))
    except (TypeError, ValueError):
        logger.warning("ENV | %s ไม่ใช่จำนวนเต็ม ใช้ค่า default %s", name, default)
        return int(default)


def env_float(name, default):
    try:
        return float(raw(name, default))
    except (TypeError, ValueError):
        logger.warning("ENV | %s ไม่ใช่ตัวเลข ใช้ค่า default %s", name, default)
        return float(default)


def env_bool(name, default):
    return raw(name, default).lower() in ("true", "1", "yes", "on")


def env_list(name, default=""):
    """คืนลิสต์เสมอ; 'ตั้งไว้แต่ว่าง' จะได้ default ไม่ใช่ลิสต์ว่าง"""
    return [part.strip() for part in raw(name, default).split(",") if part.strip()]
