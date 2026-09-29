# -*- coding: utf-8 -*-
"""
quota_keys.py — ระบบ "คีย์โควตา AI" สำหรับคำสั่ง /ask_ai (ต่อยอดจาก quota.py)

แนวคิด
------
quota.py คุมโควตา "ต่อวัน" ต่อผู้ใช้ (นับจำนวนครั้ง) — เหมาะกับสมาชิกที่เป็น Admin
โมดูลนี้เพิ่มอีกชั้นสำหรับ "สมาชิกทั่วไป": ต้องมี *คีย์ส่วนตัว* ก่อนใช้ /ask_ai
โดยคีย์แต่ละใบ:

  1. เป็นสตริง Hex ยาว (สุ่มด้วย secrets — เหมือนความยาว SHA-256)
  2. อายุ 3 วัน "นับจากครั้งแรกที่ใช้" (ไม่ใช่นับจากวันสร้าง) — ก่อนถูกใช้ครั้งแรก
     คีย์ยังไม่เริ่มจับเวลา จึงแจกล่วงหน้าได้
  3. ผูกกับผู้ใช้คนแรกที่เอาไปใช้ (bound_user_id) — คนอื่นเอาไปใช้ไม่ได้
  4. หมดอายุแล้วใช้ไม่ได้ และถูกลบอัตโนมัติ (purge) เพื่อไม่ให้ตารางบวม

ความปลอดภัยของการเก็บ (สอดคล้อง osint_db.py / integrity_ledger.py)
-----------------------------------------------------------------
เก็บเฉพาะ SHA-256 ของคีย์ (key_hash) ลงฐานข้อมูล ไม่เคยเก็บคีย์ดิบ — ถ้า bot.db
รั่ว คีย์ที่ยังไม่ถูกใช้ก็ปลอมไม่ได้ คีย์ดิบจะถูกแสดง "ครั้งเดียว" ตอน generate
แล้วส่งให้ Admin ทาง DM เท่านั้น (จัดการที่ชั้น app.py)

ข้อจำกัดการออกแบบ (ตรงกับ quota.py):
- ใช้ไลบรารีมาตรฐานล้วน (sqlite3, secrets, hashlib, time)
- ไม่มี network / thread / background loop
- CREATE TABLE IF NOT EXISTS เท่านั้น ไม่ยุ่งกับตารางของโมดูลอื่น
"""

import time
import hashlib
import logging
import secrets
import sqlite3
from typing import Dict, List, Optional, Tuple

from envutil import env_int

logger = logging.getLogger("modbot.quota_keys")

DB_PATH = "bot.db"

# อายุคีย์ (วัน) นับจากการใช้ครั้งแรก — override ได้ด้วย env โดยไม่แตะโค้ด
KEY_TTL_DAYS = env_int("AI_KEY_TTL_DAYS", 3)
# ความยาวคีย์ดิบเป็นไบต์ (32 ไบต์ = 64 ตัวอักษร hex — เท่ากับความยาว SHA-256)
KEY_BYTES = 32
# เพดานจำนวนคีย์ที่สร้างได้ต่อครั้ง (กันสั่งพลาดสร้างเป็นแสน)
MAX_GENERATE_PER_CALL = env_int("AI_KEY_MAX_PER_CALL", 200)


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> int:
    return int(time.time())


def _ttl_seconds() -> int:
    days = KEY_TTL_DAYS if KEY_TTL_DAYS > 0 else 3
    return days * 86400


def hash_key(raw_key: str) -> str:
    """SHA-256 ของคีย์ดิบ (normalize: strip + lower) — ใช้เป็น primary key ในตาราง
    ต้องเป็นฟังก์ชันเดียวที่ทั้ง generate และ redeem ใช้ ค่าจึงตรงกันเสมอ"""
    norm = (raw_key or "").strip().lower()
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def quota_keys_db_init() -> None:
    """สร้างตารางคีย์ถ้ายังไม่มี — ปลอดภัยต่อการเรียกซ้ำทุกครั้งที่บอตบูต"""
    conn = _conn()
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS ai_quota_keys (
            key_hash       TEXT PRIMARY KEY,
            label          TEXT NOT NULL DEFAULT '',
            created_at     INTEGER NOT NULL,
            created_by     INTEGER NOT NULL,
            first_used_at  INTEGER,
            expires_at     INTEGER,
            bound_user_id  INTEGER,
            bound_username TEXT NOT NULL DEFAULT '',
            uses           INTEGER NOT NULL DEFAULT 0,
            revoked        INTEGER NOT NULL DEFAULT 0
        )""")
        # ดัชนีช่วยการ list/purge ตามเวลาและเจ้าของ
        conn.execute("CREATE INDEX IF NOT EXISTS idx_qk_expires ON ai_quota_keys(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_qk_bound ON ai_quota_keys(bound_user_id)")
        conn.commit()
    finally:
        conn.close()
    logger.info("QUOTA KEYS DATABASE: OK")


def _next_label_index(conn: sqlite3.Connection) -> int:
    """ลำดับถัดไปสำหรับ label 'Key #NNN' — อิงจำนวนแถวที่เคยสร้าง (rowid สูงสุด
    ใช้ไม่ได้เพราะ PK เป็น text) จึงนับจาก label ที่มีรูปแบบ Key #NNN"""
    rows = conn.execute(
        "SELECT label FROM ai_quota_keys WHERE label LIKE 'Key #%'"
    ).fetchall()
    top = 0
    for r in rows:
        try:
            top = max(top, int(str(r["label"]).split("#", 1)[1]))
        except (ValueError, IndexError):
            continue
    return top + 1


def generate_keys(count: int, created_by: int) -> List[Dict[str, str]]:
    """สร้างคีย์ใหม่ ``count`` ใบ คืนรายการ {"label","key"} โดย ``key`` เป็นคีย์ดิบ
    (แสดงครั้งเดียว) ส่วนในฐานข้อมูลเก็บแค่ hash

    ป้องกันคีย์ชนกัน (แทบเป็นไปไม่ได้ที่ 256-bit จะชน) ด้วยการ INSERT OR IGNORE
    แล้วสุ่มใหม่ถ้าโดน ignore
    """
    n = max(1, min(int(count or 0), MAX_GENERATE_PER_CALL))
    now = _now()
    created: List[Dict[str, str]] = []
    conn = _conn()
    try:
        idx = _next_label_index(conn)
        for _ in range(n):
            for _attempt in range(5):
                raw = secrets.token_hex(KEY_BYTES)
                kh = hash_key(raw)
                label = f"Key #{idx:03d}"
                cur = conn.execute(
                    "INSERT OR IGNORE INTO ai_quota_keys "
                    "(key_hash, label, created_at, created_by) VALUES (?,?,?,?)",
                    (kh, label, now, int(created_by)),
                )
                if cur.rowcount:
                    created.append({"label": label, "key": raw})
                    idx += 1
                    break
        conn.commit()
    finally:
        conn.close()
    logger.info("QUOTA KEYS | สร้างคีย์ใหม่ %d ใบ โดย user=%s", len(created), created_by)
    return created


def purge_expired(now: Optional[int] = None) -> int:
    """ลบคีย์ที่หมดอายุแล้วออกจากตาราง คืนจำนวนที่ลบ

    "หมดอายุ" = เคยถูกใช้ (expires_at ตั้งแล้ว) และเวลาปัจจุบันเลย expires_at
    คีย์ที่ยังไม่เคยถูกใช้ (expires_at IS NULL) จะไม่ถูกลบ — มันยังไม่เริ่มจับเวลา
    """
    ts = now if now is not None else _now()
    conn = _conn()
    try:
        cur = conn.execute(
            "DELETE FROM ai_quota_keys WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (ts,),
        )
        conn.commit()
        removed = cur.rowcount or 0
    finally:
        conn.close()
    if removed:
        logger.info("QUOTA KEYS | ลบคีย์หมดอายุ %d ใบ", removed)
    return removed


def redeem_key(raw_key: str, user_id: int, username: str = "",
               now: Optional[int] = None) -> Tuple[bool, str, Optional[dict]]:
    """ตรวจและ "ใช้" คีย์หนึ่งครั้งสำหรับ ``user_id``

    คืน (ok, reason, info):
      - ok=True   -> ใช้ได้ info มี {"label","expires_at","remaining_seconds","uses"}
      - ok=False  -> reason เป็นรหัสสั้น ๆ: not_found | revoked | bound_other |
                     expired

    พฤติกรรม:
      - ครั้งแรกที่ใช้: ผูกกับ user_id นี้ ตั้ง first_used_at และ expires_at
        (= now + TTL) แล้วเริ่มจับเวลา
      - ครั้งถัดไป: ต้องเป็น user เดิม และยังไม่หมดอายุ
    ทุกการใช้ที่สำเร็จจะ +1 ที่คอลัมน์ uses (audit)
    """
    ts = now if now is not None else _now()
    kh = hash_key(raw_key)
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM ai_quota_keys WHERE key_hash=?", (kh,)
        ).fetchone()
        if row is None:
            return False, "not_found", None
        if row["revoked"]:
            return False, "revoked", None

        bound = row["bound_user_id"]
        expires_at = row["expires_at"]

        # คีย์ที่เคยผูกกับคนอื่น — ปฏิเสธ
        if bound is not None and int(bound) != int(user_id):
            return False, "bound_other", None

        # คีย์ที่หมดอายุแล้ว — ปฏิเสธ (และปล่อยให้ purge เก็บกวาดภายหลัง)
        if expires_at is not None and ts >= int(expires_at):
            return False, "expired", None

        if bound is None:
            # ครั้งแรก: ผูกผู้ใช้ + เริ่มจับเวลา
            expires_at = ts + _ttl_seconds()
            conn.execute(
                "UPDATE ai_quota_keys SET bound_user_id=?, bound_username=?, "
                "first_used_at=?, expires_at=?, uses=uses+1 WHERE key_hash=?",
                (int(user_id), str(username or "")[:64], ts, expires_at, kh),
            )
        else:
            conn.execute(
                "UPDATE ai_quota_keys SET uses=uses+1, bound_username=? WHERE key_hash=?",
                (str(username or row["bound_username"] or "")[:64], kh),
            )
        conn.commit()
        info = {
            "label": row["label"],
            "expires_at": int(expires_at),
            "remaining_seconds": max(0, int(expires_at) - ts),
            "uses": int(row["uses"]) + 1,
        }
        return True, "ok", info
    finally:
        conn.close()


def active_key_for_user(user_id: int, now: Optional[int] = None) -> Optional[dict]:
    """คืนคีย์ที่ยัง "ใช้ได้" ของผู้ใช้ (ผูกแล้ว ยังไม่หมดอายุ ไม่ถูกเพิกถอน) ถ้ามี
    ใช้ตอน /ask_ai เพื่อดูว่าผู้ใช้มีคีย์อยู่แล้วหรือยังต้องกรอกใหม่"""
    ts = now if now is not None else _now()
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM ai_quota_keys WHERE bound_user_id=? AND revoked=0 "
            "AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY expires_at DESC LIMIT 1",
            (int(user_id), ts),
        ).fetchone()
        if row is None:
            return None
        return {
            "label": row["label"],
            "expires_at": int(row["expires_at"]) if row["expires_at"] else None,
            "remaining_seconds": (max(0, int(row["expires_at"]) - ts)
                                  if row["expires_at"] else None),
            "uses": int(row["uses"]),
        }
    finally:
        conn.close()


def revoke_key(label_or_hash: str) -> bool:
    """เพิกถอนคีย์ตาม label ('Key #001') หรือ key_hash — คืน True ถ้ามีแถวโดนแก้"""
    conn = _conn()
    try:
        cur = conn.execute(
            "UPDATE ai_quota_keys SET revoked=1 WHERE label=? OR key_hash=?",
            (str(label_or_hash), str(label_or_hash)),
        )
        conn.commit()
        return bool(cur.rowcount)
    finally:
        conn.close()


def list_keys(now: Optional[int] = None, include_expired: bool = False) -> List[dict]:
    """ตารางสรุปสถานะคีย์ทั้งหมด (สำหรับ Admin) — ไม่คืนคีย์ดิบและไม่คืน hash เต็ม

    แต่ละรายการ: {label, status, bound_user_id, bound_username, expires_at,
    remaining_seconds, uses} โดย status ∈ unused | active | expired | revoked
    """
    ts = now if now is not None else _now()
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT * FROM ai_quota_keys ORDER BY created_at ASC, label ASC"
        ).fetchall()
    finally:
        conn.close()

    out: List[dict] = []
    for r in rows:
        expires_at = int(r["expires_at"]) if r["expires_at"] is not None else None
        if r["revoked"]:
            status = "revoked"
        elif r["bound_user_id"] is None:
            status = "unused"
        elif expires_at is not None and ts >= expires_at:
            status = "expired"
        else:
            status = "active"
        if status == "expired" and not include_expired:
            continue
        out.append({
            "label": r["label"],
            "status": status,
            "bound_user_id": r["bound_user_id"],
            "bound_username": r["bound_username"] or "",
            "expires_at": expires_at,
            "remaining_seconds": (max(0, expires_at - ts)
                                  if (expires_at and status == "active") else None),
            "uses": int(r["uses"]),
        })
    return out


def format_key_table(rows: List[dict]) -> str:
    """สร้างตารางสรุปคีย์เป็นข้อความ (แสดง label สมมติ ไม่โชว์คีย์จริง)"""
    if not rows:
        return "🔑 ยังไม่มีคีย์โควตา AI ในระบบ — ใช้ /generate_keys เพื่อสร้าง"
    icon = {"unused": "⚪", "active": "🟢", "expired": "🔴", "revoked": "⛔"}
    lines = ["🔑 สถานะคีย์โควตา AI", ""]
    for r in rows:
        who = ""
        if r["bound_user_id"]:
            uname = f"@{r['bound_username']}" if r["bound_username"] else str(r["bound_user_id"])
            who = f" — {uname}"
        left = ""
        if r["remaining_seconds"] is not None:
            hrs = r["remaining_seconds"] // 3600
            left = f" (เหลือ ~{hrs} ชม.)"
        lines.append(
            f"{icon.get(r['status'], '•')} {r['label']}: {r['status']}{who}{left} "
            f"[ใช้ {r['uses']} ครั้ง]"
        )
    return "\n".join(lines)
