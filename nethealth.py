"""
nethealth.py — สถานะสุขภาพของเส้นทางเครือข่าย + ตัวอ่าน env ที่ใช้ร่วมกัน
ระหว่าง search.py และ scrape.py

เหตุผลที่ต้องมีโมดูลนี้:

1. tor2web gateway กับ onion search engine "ตายถาวร" บ่อยกว่า "ตายชั่วคราว"
   ถ้าไล่ยิงใหม่ทุกครั้ง งบเวลาของคำสั่งจะหมดไปกับเส้นทางที่ตายแล้ว แทนที่จะ
   ได้ข่าวกรองกลับมา ตัว circuit breaker ที่นี่จำว่าเส้นทางไหนล้มซ้ำๆ แล้ว
   ข้ามไปชั่วคราว (cooldown) ก่อนจะให้โอกาสลองใหม่แบบ half-open

2. search.py กับ scrape.py เคย probe Tor แยกกันคนละชุด และมีตัวอ่าน env
   ซ้ำกันคนละก๊อป ทำให้ .env ที่ตั้งค่าว่างไว้ทำงานไม่เหมือนกันสองที่

3. os.getenv(name, default) คืน "" เมื่อคีย์ถูกตั้งไว้แต่ปล่อยค่าว่าง — ไม่ได้
   คืน default ตามที่คนส่วนใหญ่เข้าใจ ตัวอ่าน env ที่นี่จึงถือว่า "ค่าว่าง =
   ไม่ได้ตั้ง" ซึ่งเป็นพฤติกรรมที่ถูกต้องกับไฟล์ .env ที่ commit ไว้จริงๆ
"""

import os
import time
import socket
import logging
import threading

logger = logging.getLogger("modbot.nethealth")


# ---------------- Env readers (ค่าว่าง = ใช้ default) ----------------

def _raw(name, default):
    value = os.getenv(name)
    if value is None or not str(value).strip():
        return str(default)
    return str(value).strip()


def env_int(name, default):
    try:
        return int(_raw(name, default))
    except (TypeError, ValueError):
        logger.warning("CONFIG | %s is not an int, using default %s", name, default)
        return int(default)


def env_float(name, default):
    try:
        return float(_raw(name, default))
    except (TypeError, ValueError):
        logger.warning("CONFIG | %s is not a float, using default %s", name, default)
        return float(default)


def env_bool(name, default):
    return _raw(name, default).lower() in ("true", "1", "yes", "on")


def env_list(name, default):
    """คืนลิสต์เสมอ และ 'ตั้งไว้แต่ว่าง' จะได้ default ไม่ใช่ลิสต์ว่าง

    .env ที่ commit ไว้ตั้ง TOR_GATEWAY_SUFFIXES= ว่างเอาไว้ โค้ดเดิมจึงได้
    ลิสต์ว่าง = ไม่มี gateway สำรองเลย ถ้าเครื่องไม่ได้รัน Tor ก็ค้นไม่เจอ
    อะไรทั้งสิ้นโดยไม่มีข้อความบอกว่าเพราะอะไร
    """
    return [part.strip() for part in _raw(name, default).split(",") if part.strip()]


# ---------------- Tor / gateway config (แหล่งความจริงเดียว) ----------------

DEFAULT_TOR_GATEWAY_SUFFIXES = ".ly,.ps,.cab,.direct"

TOR_SOCKS_HOST = _raw("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = env_int("TOR_SOCKS_PORT", 9050)
TOR_GATEWAY_SUFFIXES = env_list("TOR_GATEWAY_SUFFIXES", DEFAULT_TOR_GATEWAY_SUFFIXES)
TOR_PROBE_TTL_SECONDS = env_float("TOR_PROBE_TTL_SECONDS", 60)

_tor_lock = threading.Lock()
_tor_state = {"checked_at": 0.0, "reachable": False}


def tor_reachable(timeout=2.0, force=False) -> bool:
    """probe เดียวใช้ร่วมกันทั้ง search และ scrape — cache ไว้ตาม TTL
    เพราะถูกเรียกจากหลาย worker thread พร้อมกันในทุกคำสั่ง"""
    if not force:
        with _tor_lock:
            if (time.monotonic() - _tor_state["checked_at"]) < TOR_PROBE_TTL_SECONDS:
                return _tor_state["reachable"]
    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=timeout):
            reachable = True
    except OSError:
        reachable = False
    with _tor_lock:
        _tor_state["checked_at"] = time.monotonic()
        _tor_state["reachable"] = reachable
    return reachable


# ---------------- Circuit breaker ----------------

# 2 ครั้งพอ: เป้าหมายหนึ่งมักถูกแปลงเป็น 2-3 query ยิงพร้อมกัน engine ที่ตาย
# จึงล้มครบเกณฑ์ภายในการสืบสวนครั้งเดียว ไม่ต้องรอสะสมข้ามหลายครั้ง
ENGINE_FAILURE_THRESHOLD = env_int("NET_ENGINE_FAILURE_THRESHOLD", 2)
ROUTE_FAILURE_THRESHOLD = env_int("NET_ROUTE_FAILURE_THRESHOLD", 8)
CIRCUIT_OPEN_SECONDS = env_float("NET_CIRCUIT_OPEN_SECONDS", 300)

_circuit_lock = threading.Lock()
_circuit_state = {}


def blocked(key: str) -> bool:
    """เส้นทางนี้อยู่ในช่วง cooldown อยู่ไหม (ล้มครบเกณฑ์แล้ว)"""
    with _circuit_lock:
        entry = _circuit_state.get(key)
        if not entry:
            return False
        open_until = entry["open_until"]
        if open_until <= 0.0:
            # ยังไม่เคยเปิดวงจร — ห้ามแตะตัวนับ ไม่งั้นการ "ถาม" จะล้างประวัติ
            # ความล้มเหลวทิ้งทุกครั้ง และวงจรจะไม่มีวันเปิดเลย
            return False
        if open_until > time.monotonic():
            return True
        # หมด cooldown -> half-open: ล้างประวัติแล้วให้โอกาสลองใหม่
        entry["failures"] = 0
        entry["open_until"] = 0.0
        return False


def record(key: str, ok: bool, threshold: int) -> None:
    with _circuit_lock:
        entry = _circuit_state.setdefault(key, {"failures": 0, "open_until": 0.0})
        if ok:
            entry["failures"] = 0
            entry["open_until"] = 0.0
            return
        entry["failures"] += 1
        if entry["failures"] >= threshold and entry["open_until"] <= time.monotonic():
            entry["open_until"] = time.monotonic() + CIRCUIT_OPEN_SECONDS
            logger.info(
                "CIRCUIT OPEN | %s ล้ม %d ครั้งติด พักไว้ %ds",
                key, entry["failures"], int(CIRCUIT_OPEN_SECONDS),
            )


def health() -> dict:
    """สรุปสถานะเส้นทางไว้ log และแสดงใน /search"""
    now = time.monotonic()
    with _circuit_lock:
        return {
            key: {
                "failures": entry["failures"],
                "cooldown_s": max(0, int(entry["open_until"] - now)),
            }
            for key, entry in _circuit_state.items()
        }


def open_routes() -> list:
    """รายชื่อเส้นทางที่กำลังถูกพักอยู่ตอนนี้"""
    now = time.monotonic()
    with _circuit_lock:
        return sorted(k for k, v in _circuit_state.items() if v["open_until"] > now)


def reset() -> None:
    with _circuit_lock:
        _circuit_state.clear()
    with _tor_lock:
        _tor_state["checked_at"] = 0.0
