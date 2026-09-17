# -*- coding: utf-8 -*-
"""reputation.py — Community Reputation Engine (ระบบชื่อเสียง/คะแนนน้ำใจของกลุ่ม)

เทคโนโลยีใหม่ที่แยกขาดจากคำสั่งอื่นของบอต: เอนจินให้ "คะแนนน้ำใจ" (karma/reputation)
ระหว่างสมาชิกในกลุ่ม เพื่อส่งเสริมพฤติกรรมดี ๆ (ช่วยเหลือ/ตอบคำถาม/แบ่งปัน) โดยออกแบบให้
"วัดชื่อเสียงที่เป็นปัจจุบัน" และ "ทนต่อการปั่นคะแนน" ด้วยกลไกหลายชั้น:

  1. Time-decay (half-life)   คะแนนเก่าค่อย ๆ จางหายตามครึ่งชีวิต -> สะท้อน "ชื่อเสียงช่วงนี้"
                              ไม่ใช่ยอดสะสมตลอดกาล (คนที่เคยแอ็กทีฟแล้วหายไปคะแนนจะลดเอง)
  2. Trust-weighted voting    น้ำหนักโหวตของผู้ให้ขึ้นกับ "ระดับของผู้ให้เอง" (EigenTrust-lite)
                              -> คนน่าเชื่อถือโหวตมีน้ำหนักกว่า บัญชีใหม่/บัญชีปั่นมีน้ำหนักน้อย
  3. Anti-abuse               กันโหวตตัวเอง/บอต, cooldown ต่อคู่ผู้ให้-ผู้รับ, โควตารายวันของผู้ให้,
                              ต้องมีคะแนนขั้นต่ำจึงให้ได้, เพดานต่อครั้ง, ถอนคืนได้ในเวลาสั้น ๆ
  4. Tiers & badges           แปลงคะแนนเป็นระดับ (หน้าใหม่ -> ตำนาน) พร้อมเหรียญตรา
  5. Analytics                กระดานผู้นำ, อันดับ/เปอร์เซ็นไทล์, เทรนด์ 7 วัน (โมเมนตัม),
                              ความหลากหลายของผู้ให้ (กันปั่นจากคนเดียว), sparkline กิจกรรม

สถาปัตยกรรม
-----------
- พึ่งพาเฉพาะไลบรารีมาตรฐาน (เทสต์ได้ง่าย ไม่ต้องมี dependency ภายนอก)
- เก็บเป็นไฟล์ JSON เดียว แยก namespace ตาม chat_id — เขียนแบบ atomic กันไฟล์เสีย
- ทุกฟังก์ชันคำนวณเป็น pure logic: รับ now (datetime) เข้ามาได้เพื่อให้เทสต์กำหนดเวลาเองได้
- โมดูลนี้เป็น "แกนคำนวณ+จัดเก็บ" ล้วน ๆ; การตรวจสิทธิ์/ผูกกับ Telegram อยู่ที่ app.py
- ไม่ใช่การเก็บข้อมูลส่วนบุคคล: เก็บเฉพาะ user id (แบบเดียวกับระบบเตือน/incident เดิมของบอต)
  ชื่อที่แสดงเป็น cache ไว้โชว์เฉย ๆ และอัปเดตทับได้เสมอ
"""

import os
import io
import json
import math
import logging
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("modbot.reputation")

# ---------------------------------------------------------------------------
# การตั้งค่า (override ได้ด้วย env; ค่าเริ่มต้นต่อกลุ่มปรับได้ผ่าน /repconfig)
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("REPUTATION_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource", "reputation.json")

# เพดานเชิงระบบ (กันไฟล์บวม / กันใช้เกินควร)
MAX_EVENTS_PER_USER = int(os.getenv("REP_MAX_EVENTS", "500") or "500")
MAX_HISTORY_PER_GIVER = int(os.getenv("REP_MAX_HISTORY", "200") or "200")
EPS = 1e-9

# ค่าเริ่มต้นของ "นโยบายคะแนน" ต่อกลุ่ม — แก้ได้ด้วย /repconfig
DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,           # เปิด/ปิดระบบทั้งกลุ่ม
    "allow_negative": False,   # อนุญาตให้หักคะแนน (ลบ) ไหม
    "daily_budget": 5,         # ผู้ให้แจกได้กี่แต้มต่อวัน (รวมทุกคน)
    "cooldown_sec": 21600,     # เว้นระยะต่อ "คู่ผู้ให้-ผู้รับ" (วินาที) ดีฟอลต์ 6 ชม.
    "halflife_days": 30.0,     # ครึ่งชีวิตการเสื่อมของคะแนน (วัน)
    "min_giver_score": 0.0,    # ผู้ให้ต้องมีคะแนน >= ค่านี้จึงให้ได้
    "max_amount": 3,           # ให้ได้สูงสุดต่อครั้ง (ค่าสัมบูรณ์)
    "weighted": True,          # ถ่วงน้ำหนักตามระดับผู้ให้ไหม
    "undo_window_sec": 300,    # ถอนคืนการให้ล่าสุดได้ภายในกี่วินาที
}

# คีย์ config ที่เป็น "จำนวนเต็ม" / "ทศนิยม" / "บูลีน" (ใช้ตอน parse ค่าใน /repconfig)
_CFG_INT = {"daily_budget", "cooldown_sec", "max_amount", "undo_window_sec"}
_CFG_FLOAT = {"halflife_days", "min_giver_score"}
_CFG_BOOL = {"enabled", "allow_negative", "weighted"}

# ระดับ (tier): (คะแนนขั้นต่ำ, key, ชื่อไทย, เหรียญ) — เรียงจากต่ำไปสูง
TIERS: List[Tuple[float, str, str, str]] = [
    (0.0,   "newcomer", "หน้าใหม่",     "🌱"),
    (10.0,  "member",   "สมาชิก",       "🙂"),
    (30.0,  "trusted",  "น่าเชื่อถือ",   "⭐"),
    (75.0,  "veteran",  "รุ่นเก๋า",       "🎖️"),
    (150.0, "guardian", "ผู้พิทักษ์",     "🛡️"),
    (300.0, "legend",   "ตำนาน",        "👑"),
]

_DIVIDER = "━━━━━━━━━━━━━━━━━━"

# แคช DB ใน RAM ตาม mtime
_cache: Dict[str, Any] = {"path": None, "mtime": None, "db": None}


# ---------------------------------------------------------------------------
# เวลา
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now(now: Optional[datetime]) -> datetime:
    """คืนเวลา now (ถ้าไม่ส่งมา = เวลาปัจจุบัน UTC) — บังคับให้มี tzinfo เสมอ"""
    if now is None:
        return _utcnow()
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now


def _iso(dt: datetime) -> str:
    return _now(dt).astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse(iso: str) -> Optional[datetime]:
    """แปลง iso -> datetime (มี tz) — None ถ้าพัง"""
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _day_key(dt: datetime) -> str:
    """วันตาม UTC (ใช้รีเซ็ตโควตารายวัน) — YYYY-MM-DD"""
    return _now(dt).astimezone(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# storage (JSON, atomic, per-chat namespace)
# ---------------------------------------------------------------------------

def _db_path(path: Optional[str]) -> str:
    return path or DB_PATH


def _load(path: Optional[str] = None) -> dict:
    """โหลด DB ทั้งไฟล์ (แคชตาม mtime) — คืน {} ถ้าไม่มี/อ่านไม่ได้ (ไม่ throw)"""
    target = _db_path(path)
    try:
        mtime = os.path.getmtime(target)
    except OSError:
        return {}
    if (_cache["path"] == target and _cache["mtime"] == mtime
            and _cache["db"] is not None):
        return _cache["db"]
    try:
        with io.open(target, "r", encoding="utf-8") as f:
            db = json.load(f)
        if not isinstance(db, dict):
            db = {}
    except (OSError, ValueError) as e:
        logger.warning("REP | อ่านไฟล์ไม่ได้ %s (%s)", target, e)
        return {}
    _cache.update(path=target, mtime=mtime, db=db)
    return db


def _atomic_write(db: dict, path: Optional[str] = None) -> None:
    """เขียน DB แบบ atomic (temp + os.replace) แล้ว invalidate แคช"""
    target = _db_path(path)
    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".reputation.", suffix=".tmp", dir=parent)
    try:
        with io.open(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _cache.update(path=None, mtime=None, db=None)


def _blank_chat() -> dict:
    """โครงข้อมูลเริ่มต้นของกลุ่มหนึ่ง"""
    return {"config": dict(DEFAULT_CONFIG), "users": {}, "givers": {}}


def _get_chat(db: dict, chat_id) -> dict:
    return db.get(str(chat_id)) or _blank_chat()


def _blank_user(name: Optional[str] = None) -> dict:
    return {"name": name, "events": [], "received_count": 0, "last_recv": None}


def _blank_giver(name: Optional[str] = None) -> dict:
    return {"name": name, "day": None, "spent": 0, "cooldowns": {},
            "given_total": 0, "history": [], "last_give": None,
            "give_days": [], "streak": 0}


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def get_config(chat_id, path: Optional[str] = None) -> dict:
    """คืน config ปัจจุบันของกลุ่ม (เติมค่าดีฟอลต์ให้คีย์ที่ขาด)"""
    cfg = dict(DEFAULT_CONFIG)
    stored = (_get_chat(_load(path), chat_id).get("config") or {})
    for k, v in stored.items():
        if k in cfg:
            cfg[k] = v
    return cfg


def _coerce_cfg(key: str, value: str):
    """แปลงค่า string จากคำสั่งเป็นชนิดที่ถูกต้องของ config key — คืน (ok, value|error)"""
    if key not in DEFAULT_CONFIG:
        return False, "unknown_key"
    raw = str(value).strip()
    try:
        if key in _CFG_BOOL:
            low = raw.lower()
            if low in ("1", "true", "yes", "on", "เปิด"):
                return True, True
            if low in ("0", "false", "no", "off", "ปิด"):
                return True, False
            return False, "bad_bool"
        if key in _CFG_INT:
            iv = int(raw)
            if iv < 0:
                return False, "negative"
            return True, iv
        if key in _CFG_FLOAT:
            fv = float(raw)
            if fv < 0:
                return False, "negative"
            return True, fv
    except ValueError:
        return False, "bad_value"
    return False, "unknown_key"


def set_config(chat_id, key: str, value: str, path: Optional[str] = None) -> dict:
    """ตั้งค่า config หนึ่งคีย์ — คืน {"ok":bool,"error":str|None,"key":..,"value":..}"""
    ok, coerced = _coerce_cfg(key, value)
    if not ok:
        return {"ok": False, "error": coerced, "key": key}
    db = dict(_load(path))
    chat = dict(_get_chat(db, chat_id))
    cfg = dict(chat.get("config") or DEFAULT_CONFIG)
    cfg[key] = coerced
    chat["config"] = cfg
    db[str(chat_id)] = chat
    _atomic_write(db, path)
    return {"ok": True, "error": None, "key": key, "value": coerced}


def reset_config(chat_id, path: Optional[str] = None) -> None:
    """คืน config กลับเป็นค่าดีฟอลต์ทั้งหมด"""
    db = dict(_load(path))
    chat = dict(_get_chat(db, chat_id))
    chat["config"] = dict(DEFAULT_CONFIG)
    db[str(chat_id)] = chat
    _atomic_write(db, path)


# ---------------------------------------------------------------------------
# tiers & weights
# ---------------------------------------------------------------------------

def tier_for(score: float) -> Tuple[int, str, str, str]:
    """คืน (index, key, ชื่อไทย, เหรียญ) ของระดับตามคะแนน"""
    idx = 0
    for i, (threshold, key, name, badge) in enumerate(TIERS):
        if score + EPS >= threshold:
            idx = i
        else:
            break
    _, key, name, badge = TIERS[idx]
    return idx, key, name, badge


def next_tier(score: float) -> Optional[Tuple[float, str, str, str]]:
    """คืน (คะแนนขั้นต่ำ, key, ชื่อ, เหรียญ) ของระดับถัดไป — None ถ้าสูงสุดแล้ว"""
    idx, _, _, _ = tier_for(score)
    if idx + 1 < len(TIERS):
        return TIERS[idx + 1]
    return None


def giver_weight(giver_score: float, weighted: bool) -> float:
    """น้ำหนักโหวตของผู้ให้ตามระดับ (EigenTrust-lite): ระดับสูง -> น้ำหนักมากขึ้นเล็กน้อย

    ปิด weighted -> คืน 1.0 เสมอ; เปิด -> 0.8..1.5 ตามระดับ (กันบัญชีใหม่ปั่นคะแนน)
    """
    if not weighted:
        return 1.0
    idx, _, _, _ = tier_for(max(0.0, giver_score))
    # ระดับ 0..5 -> น้ำหนัก 0.8, 1.0, 1.1, 1.2, 1.35, 1.5
    ladder = [0.8, 1.0, 1.1, 1.2, 1.35, 1.5]
    return ladder[min(idx, len(ladder) - 1)]


# ---------------------------------------------------------------------------
# decay math (หัวใจของ "ชื่อเสียงที่เป็นปัจจุบัน")
# ---------------------------------------------------------------------------

def _decay_factor(dt_seconds: float, halflife_days: float) -> float:
    """ตัวคูณการเสื่อม 0..1 ตามเวลาที่ผ่านไป (ครึ่งชีวิต halflife_days วัน)"""
    if halflife_days <= 0:
        return 1.0
    if dt_seconds <= 0:
        return 1.0
    h = halflife_days * 86400.0
    return math.pow(0.5, dt_seconds / h)


def _score_from_events(events: List[dict], now: datetime, halflife_days: float) -> float:
    """คำนวณคะแนน ณ เวลา now จาก event ทั้งหมด (แต่ละ event เสื่อมตามอายุของมัน)"""
    if not events:
        return 0.0
    total = 0.0
    for e in events:
        t = _parse(e.get("t"))
        if t is None:
            continue
        dt = (now - t).total_seconds()
        amt = float(e.get("amt", 0)) * float(e.get("w", 1.0))
        total += amt * _decay_factor(dt, halflife_days)
    return total


def _round(x: float) -> float:
    """ปัดคะแนนให้อ่านง่าย (ทศนิยม 1 ตำแหน่ง, ตัด -0.0)"""
    r = round(x + 0.0, 1)
    return 0.0 if r == 0 else r


def current_score(chat_id, user_id, now: Optional[datetime] = None,
                  path: Optional[str] = None) -> float:
    """คะแนนปัจจุบัน (หลัง decay) ของผู้ใช้คนหนึ่ง"""
    now = _now(now)
    cfg = get_config(chat_id, path)
    urec = _get_chat(_load(path), chat_id).get("users", {}).get(str(user_id))
    if not urec:
        return 0.0
    return _round(_score_from_events(urec.get("events", []), now, cfg["halflife_days"]))


# ---------------------------------------------------------------------------
# anti-abuse
# ---------------------------------------------------------------------------

def _reset_daily_if_needed(giver: dict, now: datetime) -> None:
    """รีเซ็ตโควตารายวันของผู้ให้ถ้าเปลี่ยนวันแล้ว (แก้ dict ในที่)"""
    today = _day_key(now)
    if giver.get("day") != today:
        giver["day"] = today
        giver["spent"] = 0


def can_give(chat_id, giver_id, receiver_id, amount: int,
             giver_is_self: bool = False, receiver_is_bot: bool = False,
             now: Optional[datetime] = None, path: Optional[str] = None) -> dict:
    """ตรวจว่าผู้ให้ให้คะแนนได้ไหม — คืน {"ok":bool,"error":str|None,"budget_left":int}

    error ที่เป็นไปได้: disabled, self, bot, bad_amount, negative_not_allowed,
                       min_giver, cooldown, budget
    """
    now = _now(now)
    cfg = get_config(chat_id, path)
    if not cfg["enabled"]:
        return {"ok": False, "error": "disabled", "budget_left": 0}
    if giver_is_self or str(giver_id) == str(receiver_id):
        return {"ok": False, "error": "self", "budget_left": 0}
    if receiver_is_bot:
        return {"ok": False, "error": "bot", "budget_left": 0}
    if amount == 0:
        return {"ok": False, "error": "bad_amount", "budget_left": 0}
    if abs(amount) > int(cfg["max_amount"]):
        return {"ok": False, "error": "bad_amount", "budget_left": 0}
    if amount < 0 and not cfg["allow_negative"]:
        return {"ok": False, "error": "negative_not_allowed", "budget_left": 0}

    chat = _get_chat(_load(path), chat_id)
    givers = chat.get("givers", {})
    giver = dict(givers.get(str(giver_id)) or _blank_giver())

    # คะแนนขั้นต่ำของผู้ให้
    if cfg["min_giver_score"] > 0:
        gscore = _round(_score_from_events(
            chat.get("users", {}).get(str(giver_id), {}).get("events", []),
            now, cfg["halflife_days"]))
        if gscore < cfg["min_giver_score"]:
            return {"ok": False, "error": "min_giver", "budget_left": 0}

    # cooldown ต่อคู่
    cd = (giver.get("cooldowns") or {}).get(str(receiver_id))
    cd_dt = _parse(cd)
    if cd_dt is not None:
        elapsed = (now - cd_dt).total_seconds()
        if elapsed < cfg["cooldown_sec"]:
            return {"ok": False, "error": "cooldown", "budget_left": _budget_left(giver, cfg, now),
                    "retry_after": int(cfg["cooldown_sec"] - elapsed)}

    # โควตารายวัน
    _reset_daily_if_needed(giver, now)
    left = int(cfg["daily_budget"]) - int(giver.get("spent", 0))
    if left < abs(amount):
        return {"ok": False, "error": "budget", "budget_left": max(0, left)}

    return {"ok": True, "error": None, "budget_left": left}


def _budget_left(giver: dict, cfg: dict, now: datetime) -> int:
    g = dict(giver)
    _reset_daily_if_needed(g, now)
    return max(0, int(cfg["daily_budget"]) - int(g.get("spent", 0)))


# ---------------------------------------------------------------------------
# core: give / undo
# ---------------------------------------------------------------------------

def give(chat_id, giver_id, receiver_id, amount: int = 1, reason: str = "",
         giver_name: Optional[str] = None, receiver_name: Optional[str] = None,
         giver_is_self: bool = False, receiver_is_bot: bool = False,
         now: Optional[datetime] = None, path: Optional[str] = None) -> dict:
    """ให้ (หรือหัก) คะแนนน้ำใจ — ผ่านการตรวจ anti-abuse ก่อนเสมอ

    คืน dict ผลลัพธ์:
        {"ok":bool, "error":str|None, "amount":int, "weight":float,
         "new_score":float, "tier":(idx,key,name,badge), "budget_left":int,
         "leveled_up":bool}
    """
    now = _now(now)
    amount = int(amount)
    check = can_give(chat_id, giver_id, receiver_id, amount,
                     giver_is_self=giver_is_self, receiver_is_bot=receiver_is_bot,
                     now=now, path=path)
    if not check["ok"]:
        return {"ok": False, "error": check["error"], "amount": amount,
                "budget_left": check.get("budget_left", 0),
                "retry_after": check.get("retry_after")}

    cfg = get_config(chat_id, path)
    db = dict(_load(path))
    chat = dict(_get_chat(db, chat_id))
    users = dict(chat.get("users", {}))
    givers = dict(chat.get("givers", {}))

    # คะแนนของผู้ให้ (สำหรับคำนวณน้ำหนัก)
    giver_urec = users.get(str(giver_id), {})
    gscore = _score_from_events(giver_urec.get("events", []), now, cfg["halflife_days"])
    weight = giver_weight(gscore, cfg["weighted"])

    # ---- ก่อนให้: คะแนนผู้รับเดิม (ไว้ตรวจ level-up) ----
    urec = dict(users.get(str(receiver_id)) or _blank_user(receiver_name))
    if receiver_name:
        urec["name"] = receiver_name
    old_score = _score_from_events(urec.get("events", []), now, cfg["halflife_days"])
    old_tier, _, _, _ = tier_for(_round(old_score))

    # ---- บันทึก event ให้ผู้รับ ----
    events = list(urec.get("events", []))
    events.append({"t": _iso(now), "from": str(giver_id), "amt": amount,
                   "w": round(weight, 3), "reason": (reason or "").strip()[:200]})
    events = _prune_events(events, now, cfg["halflife_days"])
    urec["events"] = events
    urec["received_count"] = int(urec.get("received_count", 0)) + 1
    urec["last_recv"] = _iso(now)
    users[str(receiver_id)] = urec

    # ---- อัปเดตสถานะผู้ให้ (โควตา/cooldown/history/streak) ----
    giver = dict(givers.get(str(giver_id)) or _blank_giver(giver_name))
    if giver_name:
        giver["name"] = giver_name
    _reset_daily_if_needed(giver, now)
    giver["spent"] = int(giver.get("spent", 0)) + abs(amount)
    cooldowns = dict(giver.get("cooldowns") or {})
    cooldowns[str(receiver_id)] = _iso(now)
    giver["cooldowns"] = _prune_cooldowns(cooldowns, now, cfg["cooldown_sec"])
    giver["given_total"] = int(giver.get("given_total", 0)) + 1
    hist = list(giver.get("history", []))
    hist.append({"t": _iso(now), "to": str(receiver_id), "amt": amount, "w": round(weight, 3)})
    giver["history"] = hist[-MAX_HISTORY_PER_GIVER:]
    giver["last_give"] = _iso(now)
    giver["streak"] = _update_streak(giver, now)
    givers[str(giver_id)] = giver

    chat["users"] = users
    chat["givers"] = givers
    db[str(chat_id)] = chat
    _atomic_write(db, path)

    new_score = _round(_score_from_events(events, now, cfg["halflife_days"]))
    new_tier = tier_for(new_score)
    return {"ok": True, "error": None, "amount": amount, "weight": round(weight, 3),
            "new_score": new_score, "tier": new_tier,
            "budget_left": max(0, int(cfg["daily_budget"]) - int(giver["spent"])),
            "leveled_up": new_tier[0] > old_tier}


def undo_last(chat_id, giver_id, now: Optional[datetime] = None,
              path: Optional[str] = None) -> dict:
    """ถอนการให้ล่าสุดของผู้ให้ (ภายในหน้าต่างเวลา undo_window_sec)

    คืน {"ok":bool,"error":str|None,"to":receiver_id,"amount":int}
    error: nothing (ไม่มีให้ถอน), expired (เลยเวลา)
    """
    now = _now(now)
    cfg = get_config(chat_id, path)
    db = dict(_load(path))
    chat = dict(_get_chat(db, chat_id))
    givers = dict(chat.get("givers", {}))
    giver = dict(givers.get(str(giver_id)) or {})
    hist = list(giver.get("history", []))
    if not hist:
        return {"ok": False, "error": "nothing"}
    last = hist[-1]
    t = _parse(last.get("t"))
    if t is None or (now - t).total_seconds() > cfg["undo_window_sec"]:
        return {"ok": False, "error": "expired"}

    receiver_id = last["to"]
    users = dict(chat.get("users", {}))
    urec = dict(users.get(str(receiver_id)) or {})
    events = list(urec.get("events", []))
    # ลบ event ล่าสุดที่ตรงกับ from=giver, t=last t (จับตัวเดียว)
    removed = False
    for i in range(len(events) - 1, -1, -1):
        e = events[i]
        if (str(e.get("from")) == str(giver_id) and e.get("t") == last.get("t")
                and int(e.get("amt", 0)) == int(last.get("amt", 0))):
            events.pop(i)
            removed = True
            break
    if not removed:
        return {"ok": False, "error": "nothing"}
    urec["events"] = events
    urec["received_count"] = max(0, int(urec.get("received_count", 0)) - 1)
    users[str(receiver_id)] = urec

    # คืนโควตา + ลบ history ล่าสุด + ล้าง cooldown ของคู่นี้
    hist.pop()
    giver["history"] = hist
    _reset_daily_if_needed(giver, now)
    giver["spent"] = max(0, int(giver.get("spent", 0)) - abs(int(last.get("amt", 0))))
    giver["given_total"] = max(0, int(giver.get("given_total", 0)) - 1)
    cds = dict(giver.get("cooldowns") or {})
    cds.pop(str(receiver_id), None)
    giver["cooldowns"] = cds
    givers[str(giver_id)] = giver

    chat["users"] = users
    chat["givers"] = givers
    db[str(chat_id)] = chat
    _atomic_write(db, path)
    return {"ok": True, "error": None, "to": receiver_id, "amount": int(last.get("amt", 0))}


def _prune_events(events: List[dict], now: datetime, halflife_days: float) -> List[dict]:
    """ตัด event ที่เก่ามากจน "เสื่อมจนแทบไม่มีผล" ออก (กันไฟล์บวม) + เพดานจำนวน

    ตัดตัวที่ decay < ~0.1% (เกิน ~10 ครึ่งชีวิต) แล้วคงไว้ไม่เกิน MAX_EVENTS_PER_USER ตัวใหม่สุด
    """
    if halflife_days > 0:
        cutoff = now - timedelta(days=halflife_days * 10)
        kept = [e for e in events if (_parse(e.get("t")) or now) >= cutoff]
    else:
        kept = list(events)
    if len(kept) > MAX_EVENTS_PER_USER:
        kept = kept[-MAX_EVENTS_PER_USER:]
    return kept


def _prune_cooldowns(cooldowns: Dict[str, str], now: datetime, cooldown_sec: float) -> dict:
    """ตัด cooldown ที่หมดอายุแล้วออก (กัน dict บวม)"""
    out = {}
    for rid, iso in cooldowns.items():
        t = _parse(iso)
        if t is not None and (now - t).total_seconds() < cooldown_sec:
            out[rid] = iso
    return out


def _update_streak(giver: dict, now: datetime) -> int:
    """อัปเดต streak การให้รายวัน (ให้ต่อเนื่องกี่วัน) — เก็บวันล่าสุด ๆ ใน give_days"""
    today = _day_key(now)
    days = list(giver.get("give_days", []))
    if today not in days:
        days.append(today)
    days = sorted(set(days))[-40:]     # เก็บ 40 วันหลังสุดพอ
    giver["give_days"] = days
    # นับ streak ย้อนจากวันนี้
    streak = 0
    cur = now
    dayset = set(days)
    while _day_key(cur) in dayset:
        streak += 1
        cur = cur - timedelta(days=1)
    return streak


# ---------------------------------------------------------------------------
# query: profile / leaderboard / rank / stats / trend
# ---------------------------------------------------------------------------

def _all_scores(chat: dict, now: datetime, halflife_days: float) -> Dict[str, float]:
    """คะแนนปัจจุบันของทุกคนในกลุ่ม (uid -> score)"""
    out = {}
    for uid, urec in (chat.get("users") or {}).items():
        out[uid] = _round(_score_from_events(urec.get("events", []), now, halflife_days))
    return out


def leaderboard(chat_id, limit: int = 10, now: Optional[datetime] = None,
                path: Optional[str] = None) -> List[dict]:
    """กระดานผู้นำ: [{"user_id","name","score","tier"}] เรียงจากมากไปน้อย (คะแนน>0)"""
    now = _now(now)
    cfg = get_config(chat_id, path)
    chat = _get_chat(_load(path), chat_id)
    scores = _all_scores(chat, now, cfg["halflife_days"])
    ranked = sorted(((s, uid) for uid, s in scores.items() if s > 0),
                    key=lambda x: (-x[0], x[1]))
    out = []
    for s, uid in ranked[: max(1, int(limit))]:
        urec = chat["users"].get(uid, {})
        out.append({"user_id": uid, "name": urec.get("name"),
                    "score": s, "tier": tier_for(s)})
    return out


def rank_of(chat_id, user_id, now: Optional[datetime] = None,
            path: Optional[str] = None) -> Optional[dict]:
    """อันดับของผู้ใช้: {"rank","total","percentile","score"} — None ถ้าไม่มีคะแนน"""
    now = _now(now)
    cfg = get_config(chat_id, path)
    chat = _get_chat(_load(path), chat_id)
    scores = _all_scores(chat, now, cfg["halflife_days"])
    positive = {u: s for u, s in scores.items() if s > 0}
    my = scores.get(str(user_id), 0.0)
    if my <= 0:
        return None
    higher = sum(1 for s in positive.values() if s > my + EPS)
    total = len(positive)
    rank = higher + 1
    lower_or_eq = sum(1 for s in positive.values() if s <= my + EPS)
    percentile = int(round(100.0 * lower_or_eq / total)) if total else 0
    return {"rank": rank, "total": total, "percentile": percentile, "score": my}


def _score_asof(events: List[dict], asof: datetime, halflife_days: float) -> float:
    """คะแนน ณ เวลา asof (นับเฉพาะ event ที่เกิดก่อน asof) — ใช้คำนวณเทรนด์"""
    past = [e for e in events if (_parse(e.get("t")) or asof) <= asof]
    return _score_from_events(past, asof, halflife_days)


def trend_7d(chat_id, user_id, now: Optional[datetime] = None,
             path: Optional[str] = None) -> dict:
    """โมเมนตัม 7 วัน: {"now","past","delta","dir"} (dir: up/down/flat)"""
    now = _now(now)
    cfg = get_config(chat_id, path)
    urec = _get_chat(_load(path), chat_id).get("users", {}).get(str(user_id))
    if not urec:
        return {"now": 0.0, "past": 0.0, "delta": 0.0, "dir": "flat"}
    events = urec.get("events", [])
    cur = _score_from_events(events, now, cfg["halflife_days"])
    past = _score_asof(events, now - timedelta(days=7), cfg["halflife_days"])
    delta = _round(cur - past)
    direction = "up" if delta > 0.05 else ("down" if delta < -0.05 else "flat")
    return {"now": _round(cur), "past": _round(past), "delta": delta, "dir": direction}


def giver_diversity(chat_id, user_id, path: Optional[str] = None) -> dict:
    """ความหลากหลายของผู้ให้: {"distinct","total","ratio"} — ต่ำ = อาจถูกปั่นจากคนเดียว"""
    urec = _get_chat(_load(path), chat_id).get("users", {}).get(str(user_id))
    if not urec:
        return {"distinct": 0, "total": 0, "ratio": 0.0}
    events = urec.get("events", [])
    givers = [str(e.get("from")) for e in events if e.get("from")]
    total = len(givers)
    distinct = len(set(givers))
    ratio = round(distinct / total, 2) if total else 0.0
    return {"distinct": distinct, "total": total, "ratio": ratio}


def recent_events(chat_id, user_id, limit: int = 3, path: Optional[str] = None) -> List[dict]:
    """event รับคะแนนล่าสุด (ใหม่ -> เก่า) พร้อมเหตุผล"""
    urec = _get_chat(_load(path), chat_id).get("users", {}).get(str(user_id))
    if not urec:
        return []
    ev = list(urec.get("events", []))
    ev.sort(key=lambda e: e.get("t") or "", reverse=True)
    return ev[: max(1, int(limit))]


def get_profile(chat_id, user_id, name: Optional[str] = None,
                now: Optional[datetime] = None, path: Optional[str] = None) -> dict:
    """โปรไฟล์ชื่อเสียงแบบครบของผู้ใช้ (รวมทุก metric ไว้ในที่เดียว)"""
    now = _now(now)
    chat = _get_chat(_load(path), chat_id)
    urec = chat.get("users", {}).get(str(user_id)) or {}
    giver = chat.get("givers", {}).get(str(user_id)) or {}
    score = current_score(chat_id, user_id, now=now, path=path)
    idx, key, tname, badge = tier_for(score)
    nxt = next_tier(score)
    rank = rank_of(chat_id, user_id, now=now, path=path)
    trend = trend_7d(chat_id, user_id, now=now, path=path)
    div = giver_diversity(chat_id, user_id, path=path)
    return {
        "user_id": str(user_id),
        "name": name or urec.get("name") or giver.get("name"),
        "score": score,
        "tier": {"index": idx, "key": key, "name": tname, "badge": badge},
        "next_tier": ({"min": nxt[0], "name": nxt[2], "badge": nxt[3],
                       "need": _round(max(0.0, nxt[0] - score))} if nxt else None),
        "received_count": int(urec.get("received_count", 0)),
        "given_total": int(giver.get("given_total", 0)),
        "give_streak": int(giver.get("streak", 0)),
        "rank": rank,
        "trend": trend,
        "diversity": div,
        "recent": recent_events(chat_id, user_id, 3, path=path),
    }


def chat_stats(chat_id, now: Optional[datetime] = None, path: Optional[str] = None) -> dict:
    """สถิติรวมของกลุ่ม: จำนวนคนมีคะแนน, คะแนนรวม, ผู้ให้ที่แอ็กทีฟ, ผู้ให้วันนี้"""
    now = _now(now)
    cfg = get_config(chat_id, path)
    chat = _get_chat(_load(path), chat_id)
    scores = _all_scores(chat, now, cfg["halflife_days"])
    positive = {u: s for u, s in scores.items() if s > 0}
    total_karma = _round(sum(positive.values()))
    givers = chat.get("givers", {})
    today = _day_key(now)
    active_today = sum(1 for g in givers.values() if g.get("day") == today and int(g.get("spent", 0)) > 0)
    return {
        "ranked_users": len(positive),
        "total_karma": total_karma,
        "givers_total": len(givers),
        "givers_active_today": active_today,
        "enabled": cfg["enabled"],
    }


# ---------------------------------------------------------------------------
# formatting (Telegram)
# ---------------------------------------------------------------------------

def _bar(cur: float, lo: float, hi: float, width: int = 12) -> str:
    """แถบความคืบหน้าไปยังระดับถัดไป (อักขระบล็อก)"""
    if hi <= lo:
        return "█" * width
    frac = max(0.0, min(1.0, (cur - lo) / (hi - lo)))
    filled = int(round(frac * width))
    return "█" * filled + "░" * (width - filled)


def _sparkline_week(events: List[dict], now: datetime) -> str:
    """sparkline กิจกรรมรับคะแนน 7 วันล่าสุด (บล็อกความสูงตามยอดต่อวัน)"""
    blocks = "▁▂▃▄▅▆▇█"
    now = _now(now)
    counts = [0] * 7
    for e in events:
        t = _parse(e.get("t"))
        if t is None:
            continue
        d = (now.date() - t.date()).days
        if 0 <= d < 7:
            counts[6 - d] += max(0, int(e.get("amt", 0)))
    hi = max(counts) if counts else 0
    if hi <= 0:
        return "▁" * 7
    return "".join(blocks[min(len(blocks) - 1, int(round((c / hi) * (len(blocks) - 1))))]
                   for c in counts)


def _mention(name: Optional[str], user_id) -> str:
    if name:
        return name if str(name).startswith("@") else str(name)
    return f"ผู้ใช้ {user_id}"


def _trend_icon(direction: str) -> str:
    return {"up": "📈", "down": "📉", "flat": "➖"}.get(direction, "➖")


def format_profile(profile: dict) -> str:
    """การ์ดโปรไฟล์ชื่อเสียงของผู้ใช้ (สำหรับ /karma)"""
    p = profile
    tier = p["tier"]
    lines = [f"{tier['badge']} โปรไฟล์ชื่อเสียง · {_mention(p['name'], p['user_id'])}",
             _DIVIDER,
             f"คะแนนน้ำใจ: {p['score']}  ·  ระดับ: {tier['name']}"]
    # ความคืบหน้าไประดับถัดไป
    nxt = p.get("next_tier")
    if nxt:
        idx = tier["index"]
        lo = 0.0
        # หา threshold ของระดับปัจจุบันจาก TIERS
        try:
            lo = TIERS[idx][0]
        except Exception:
            lo = 0.0
        bar = _bar(p["score"], lo, nxt["min"])
        lines.append(f"{bar}  อีก {nxt['need']} → {nxt['badge']} {nxt['name']}")
    else:
        lines.append("🏆 ถึงระดับสูงสุดแล้ว")
    # อันดับ
    if p.get("rank"):
        r = p["rank"]
        lines.append(f"อันดับ: #{r['rank']}/{r['total']}  (เปอร์เซ็นไทล์ {r['percentile']})")
    # เทรนด์
    tr = p.get("trend") or {}
    lines.append(f"{_trend_icon(tr.get('dir','flat'))} เทรนด์ 7 วัน: {tr.get('delta',0):+g}")
    # กิจกรรม + ความน่าเชื่อถือของคะแนน
    div = p.get("diversity") or {}
    lines.append(f"ได้รับ {p['received_count']} ครั้ง · ให้คนอื่น {p['given_total']} ครั้ง"
                 + (f" · 🔥 ให้ต่อเนื่อง {p['give_streak']} วัน" if p.get("give_streak") else ""))
    if div.get("total"):
        lines.append(f"👥 ผู้ให้ที่ต่างกัน {div['distinct']}/{div['total']} คน (หลากหลาย {int(div['ratio']*100)}%)")
    # sparkline
    recent = p.get("recent") or []
    if recent:
        lines.append("🗓️ กิจกรรม 7 วัน: " + _sparkline_week(_all_recent_for_spark(profile), _utcnow()))
    lines.append(_DIVIDER)
    lines.append("ให้คะแนน: reply แล้วพิมพ์ /rep [เหตุผล]")
    return "\n".join(lines)


def _all_recent_for_spark(profile: dict) -> List[dict]:
    """ดึง event สำหรับ sparkline (ใช้ recent ที่แนบมาในโปรไฟล์)"""
    return profile.get("recent") or []


def format_leaderboard(rows: List[dict], title: str = "กระดานผู้นำน้ำใจ") -> str:
    """กระดานผู้นำ (สำหรับ /toprep)"""
    if not rows:
        return (f"🏅 {title} · ยังว่าง\n{_DIVIDER}\n"
                "ยังไม่มีใครได้รับคะแนน — เริ่มด้วยการ reply แล้วพิมพ์ /rep")
    medals = ["🥇", "🥈", "🥉"]
    lines = [f"🏅 {title}", _DIVIDER]
    for i, row in enumerate(rows):
        rankmark = medals[i] if i < 3 else f"{i+1}."
        tier = row["tier"]
        lines.append(f"{rankmark} {_mention(row['name'], row['user_id'])} — "
                     f"{row['score']} {tier[3]}")
    lines.append(_DIVIDER)
    lines.append("ดูโปรไฟล์: /karma (reply ผู้ใช้)")
    return "\n".join(lines)


def format_give_result(res: dict, giver_name: Optional[str],
                       receiver_name: Optional[str]) -> str:
    """ข้อความตอบเมื่อให้คะแนนสำเร็จ/ไม่สำเร็จ"""
    if res.get("ok"):
        tier = res["tier"]
        head = "➕ ให้คะแนนน้ำใจ" if res["amount"] > 0 else "➖ หักคะแนน"
        sign = f"{res['amount']:+d}"
        wtxt = f" (น้ำหนัก ×{res['weight']:g})" if abs(res["weight"] - 1.0) > 1e-6 else ""
        out = (f"{head} {sign}{wtxt} ให้ {_mention(receiver_name, '')}\n"
               f"{_DIVIDER}\n"
               f"คะแนนรวมตอนนี้: {res['new_score']} · {tier[3]} {tier[2]}\n"
               f"โควตาวันนี้เหลือ: {res['budget_left']}")
        if res.get("leveled_up"):
            out += f"\n🎉 เลื่อนระดับเป็น {tier[3]} {tier[2]}!"
        return out
    # error
    err = res.get("error")
    msgs = {
        "disabled": "⚠️ ระบบชื่อเสียงปิดอยู่ในกลุ่มนี้ (Admin เปิดด้วย /repconfig enabled on)",
        "self": "🙃 ให้คะแนนตัวเองไม่ได้นะ",
        "bot": "🤖 ให้คะแนนบอตไม่ได้",
        "bad_amount": "❌ จำนวนไม่ถูกต้อง (เกินเพดานต่อครั้ง หรือเป็น 0)",
        "negative_not_allowed": "❌ กลุ่มนี้ไม่อนุญาตให้หักคะแนน",
        "min_giver": "🔒 คุณต้องมีคะแนนขั้นต่ำก่อนจึงจะให้คนอื่นได้",
        "cooldown": "⏳ เพิ่งให้คนนี้ไปเมื่อกี้ รอสักครู่ค่อยให้ใหม่"
                    + (f" (อีก ~{res['retry_after']//60} นาที)" if res.get("retry_after") else ""),
        "budget": f"🪙 โควตาวันนี้หมดแล้ว (เหลือ {res.get('budget_left',0)})",
    }
    return msgs.get(err, "❌ ให้คะแนนไม่สำเร็จ")


def format_config(chat_id, cfg: dict) -> str:
    """แสดง config ปัจจุบัน (สำหรับ /repconfig)"""
    lines = ["⚙️ ตั้งค่าระบบชื่อเสียง", _DIVIDER,
             f"enabled = {'เปิด' if cfg['enabled'] else 'ปิด'}",
             f"allow_negative = {'ได้' if cfg['allow_negative'] else 'ไม่ได้'}",
             f"weighted = {'ถ่วงน้ำหนักตามระดับ' if cfg['weighted'] else 'เท่ากันหมด'}",
             f"daily_budget = {cfg['daily_budget']} แต้ม/วัน",
             f"max_amount = {cfg['max_amount']} แต้ม/ครั้ง",
             f"cooldown_sec = {cfg['cooldown_sec']} วิ ({cfg['cooldown_sec']//3600} ชม.)",
             f"halflife_days = {cfg['halflife_days']} วัน",
             f"min_giver_score = {cfg['min_giver_score']}",
             f"undo_window_sec = {cfg['undo_window_sec']} วิ",
             _DIVIDER,
             "แก้ไข: /repconfig <key> <value>  ·  รีเซ็ต: /repconfig reset"]
    return "\n".join(lines)


def format_tiers() -> str:
    """แสดงบันไดระดับทั้งหมด (สำหรับ /repconfig tiers หรือช่วยอธิบาย)"""
    lines = ["🪜 ระดับชื่อเสียง", _DIVIDER]
    for threshold, key, name, badge in TIERS:
        lines.append(f"{badge} {name} — ตั้งแต่ {int(threshold)} คะแนน")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# weekly digest (สรุปน้ำใจประจำสัปดาห์)
# ---------------------------------------------------------------------------

def week_gains(chat_id, top: int = 5, now: Optional[datetime] = None,
               path: Optional[str] = None) -> List[dict]:
    """ผู้ที่ "คะแนนโตขึ้นมากที่สุด" ในรอบ 7 วัน (score_now - score_7วันก่อน)

    ต่างจาก leaderboard (ยอดสะสม) ตรงที่วัด "โมเมนตัมของสัปดาห์" — คนที่เพิ่งได้รับน้ำใจเยอะ
    คืน [{"user_id","name","gain","score"}] เรียง gain มากไปน้อย (เฉพาะ gain > 0)
    """
    now = _now(now)
    cfg = get_config(chat_id, path)
    chat = _get_chat(_load(path), chat_id)
    asof = now - timedelta(days=7)
    rows = []
    for uid, urec in (chat.get("users") or {}).items():
        events = urec.get("events", [])
        cur = _score_from_events(events, now, cfg["halflife_days"])
        past = _score_asof(events, asof, cfg["halflife_days"])
        gain = _round(cur - past)
        if gain > 0:
            rows.append({"user_id": uid, "name": urec.get("name"),
                         "gain": gain, "score": _round(cur)})
    rows.sort(key=lambda r: (-r["gain"], -r["score"]))
    return rows[: max(1, int(top))]


def week_top_givers(chat_id, top: int = 3, now: Optional[datetime] = None,
                    path: Optional[str] = None) -> List[dict]:
    """ผู้ให้ที่ใจดีที่สุดในรอบ 7 วัน (นับจำนวนครั้ง/แต้มที่ให้ใน history)"""
    now = _now(now)
    chat = _get_chat(_load(path), chat_id)
    asof = now - timedelta(days=7)
    rows = []
    for gid, g in (chat.get("givers") or {}).items():
        given = 0
        pts = 0
        for h in g.get("history", []):
            t = _parse(h.get("t"))
            if t is not None and t >= asof:
                given += 1
                pts += abs(int(h.get("amt", 0)))
        if given > 0:
            rows.append({"user_id": gid, "name": g.get("name"),
                         "count": given, "points": pts})
    rows.sort(key=lambda r: (-r["points"], -r["count"]))
    return rows[: max(1, int(top))]


def format_digest(chat_id, now: Optional[datetime] = None, path: Optional[str] = None) -> str:
    """สรุปน้ำใจประจำสัปดาห์ (สำหรับ /repdigest หรือส่งอัตโนมัติรายสัปดาห์)"""
    now = _now(now)
    gains = week_gains(chat_id, 5, now=now, path=path)
    givers = week_top_givers(chat_id, 3, now=now, path=path)
    stats = chat_stats(chat_id, now=now, path=path)
    lines = ["📊 สรุปน้ำใจประจำสัปดาห์", _DIVIDER]
    if gains:
        lines.append("🌟 มาแรงประจำสัปดาห์ (คะแนนโตขึ้น)")
        medals = ["🥇", "🥈", "🥉"]
        for i, r in enumerate(gains):
            mark = medals[i] if i < 3 else f"{i+1}."
            lines.append(f"{mark} {_mention(r['name'], r['user_id'])} +{r['gain']} (รวม {r['score']})")
    else:
        lines.append("ยังไม่มีใครได้รับน้ำใจในสัปดาห์นี้")
    if givers:
        lines.append("")
        lines.append("💝 ผู้ให้ใจดีประจำสัปดาห์")
        for i, r in enumerate(givers):
            lines.append(f"{i+1}. {_mention(r['name'], r['user_id'])} — ให้ {r['count']} ครั้ง ({r['points']} แต้ม)")
    lines.append(_DIVIDER)
    lines.append(f"👥 คนมีคะแนน {stats['ranked_users']} · น้ำใจรวม {stats['total_karma']} · "
                 f"ผู้ให้วันนี้ {stats['givers_active_today']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# maintenance
# ---------------------------------------------------------------------------

def prune_chat(chat_id, now: Optional[datetime] = None, path: Optional[str] = None) -> dict:
    """เก็บกวาดข้อมูลเก่าของกลุ่ม: ตัด event ที่เสื่อมจนหมดผล, cooldown หมดอายุ, user ที่ว่างเปล่า

    คืนสถิติ {"users_before","users_after","events_pruned"}
    """
    now = _now(now)
    cfg = get_config(chat_id, path)
    db = dict(_load(path))
    chat = dict(_get_chat(db, chat_id))
    users = dict(chat.get("users", {}))
    before = len(users)
    pruned = 0
    new_users = {}
    for uid, urec in users.items():
        urec = dict(urec)
        ev = urec.get("events", [])
        kept = _prune_events(ev, now, cfg["halflife_days"])
        pruned += max(0, len(ev) - len(kept))
        urec["events"] = kept
        # เก็บ user ที่ยังมี event หรือยังมีคะแนน หรือเคยรับ
        if kept or int(urec.get("received_count", 0)) > 0:
            new_users[uid] = urec
    chat["users"] = new_users
    # เก็บกวาด cooldown ของผู้ให้
    givers = dict(chat.get("givers", {}))
    for gid, g in list(givers.items()):
        g = dict(g)
        g["cooldowns"] = _prune_cooldowns(g.get("cooldowns") or {}, now, cfg["cooldown_sec"])
        givers[gid] = g
    chat["givers"] = givers
    db[str(chat_id)] = chat
    _atomic_write(db, path)
    return {"users_before": before, "users_after": len(new_users), "events_pruned": pruned}
