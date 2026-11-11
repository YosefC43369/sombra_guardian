# -*- coding: utf-8 -*-
"""broadcast/core.py — ตรรกะล้วนของตัวกระจายลิงก์ (ไม่แตะ telegram/ดิสก์)

  * owner_ids / is_owner      ใครคุมการกระจายได้ (จาก env BROADCAST_OWNER_IDS)
  * is_due / seconds_until_due ถึงรอบกระจายหรือยัง
  * render                    ประกอบข้อความที่จะยิง จากลิงก์เดียว
  * parse_target              แปลง '@user' / '-100123' / 'https://t.me/..' เป็น chat ref
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from . import store

# ใช้ตัวช่วยช่วงเวลา/ตรวจลิงก์ของ autolink ซ้ำ (อยู่ repo เดียวกัน ไม่ dup)
try:
    from autolink import engine as _al  # parse_duration / format_duration / normalize_link
except Exception:  # pragma: no cover
    _al = None

try:
    import urlkit  # type: ignore
    _HAS_URLKIT = True
except Exception:  # pragma: no cover
    urlkit = None  # type: ignore
    _HAS_URLKIT = False


# ---------------------------------------------------------------------------
# ช่วงเวลา (ยืมจาก autolink ถ้ามี ไม่งั้น fallback ในตัว)
# ---------------------------------------------------------------------------

def parse_duration(text: str) -> int:
    if _al is not None:
        return _al.parse_duration(text)
    m = re.match(r"(?i)^\s*(\d+)\s*([smhd]?)\s*$", str(text or ""))
    if not m:
        raise ValueError(f"รูปแบบช่วงเวลาไม่ถูกต้อง: {text!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[(m.group(2) or "m").lower()]


def format_duration(seconds: int) -> str:
    if _al is not None:
        return _al.format_duration(seconds)
    seconds = int(max(0, seconds))
    if seconds == 0:
        return "0s"
    out = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size:
            q, seconds = divmod(seconds, size)
            out.append(f"{q}{unit}")
    return " ".join(out)


def normalize_link(raw: str) -> str:
    """คืน URL ที่เติม scheme แล้ว + ตรวจว่าใช้งานได้ (raise ValueError ถ้าไม่ใช่ลิงก์)"""
    if _al is not None:
        return _al.normalize_link(raw)["url"]
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("ลิงก์ว่าง")
    url = raw if re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", raw) else "https://" + raw
    host = url.split("://", 1)[-1].split("/", 1)[0]
    if not host or " " in host or "." not in host:
        raise ValueError(f"ไม่ใช่ลิงก์ที่ใช้งานได้: {raw!r}")
    return url


# ---------------------------------------------------------------------------
# สิทธิ์เจ้าของบอต
# ---------------------------------------------------------------------------

def owner_ids() -> Set[int]:
    """อ่านรายชื่อ user id ที่คุมการกระจายได้ จาก env BROADCAST_OWNER_IDS
    รองรับคั่นด้วย comma หรือช่องว่าง เช่น "111,222 333" """
    raw = os.getenv("BROADCAST_OWNER_IDS", "") or ""
    ids: Set[int] = set()
    for tok in re.split(r"[\s,]+", raw.strip()):
        if not tok:
            continue
        try:
            ids.add(int(tok))
        except ValueError:
            continue
    return ids


def is_owner(user_id: int) -> bool:
    ids = owner_ids()
    return bool(ids) and int(user_id) in ids


def owner_configured() -> bool:
    return bool(owner_ids())


# ---------------------------------------------------------------------------
# ถึงรอบยัง
# ---------------------------------------------------------------------------

def is_due(cfg: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    now = now or store.utcnow()
    if not cfg.get("enabled"):
        return False
    if not (cfg.get("link") or "").strip():
        return False
    last = store.parse_iso(cfg.get("last_run_iso"))
    if last is None:
        return True
    return (now - last).total_seconds() >= int(cfg.get("interval_sec", 0))


def seconds_until_due(cfg: Dict[str, Any], now: Optional[datetime] = None) -> int:
    now = now or store.utcnow()
    if not cfg.get("enabled") or not (cfg.get("link") or "").strip():
        return -1
    last = store.parse_iso(cfg.get("last_run_iso"))
    if last is None:
        return 0
    remain = int(cfg.get("interval_sec", 0)) - (now - last).total_seconds()
    return max(0, int(round(remain)))


# ---------------------------------------------------------------------------
# ประกอบข้อความ
# ---------------------------------------------------------------------------

def render(cfg: Dict[str, Any]) -> str:
    """ข้อความที่จะยิง จาก 'ลิงก์เดียว' ใน config

    ลำดับความสำคัญ:
      1) ถ้ามี template -> ใช้ template (ตัวแปร {url} {label})
      2) ถ้ามี message  -> "message\\nurl" (ยกเว้น message มี {url} อยู่แล้ว)
      3) ไม่งั้น        -> url เปล่า
    """
    url = (cfg.get("link") or "").strip()
    label = ""
    if _HAS_URLKIT and url:
        try:
            label = urlkit.etld1(url) or ""
        except Exception:
            label = ""

    tmpl = (cfg.get("template") or "").strip()
    if tmpl:
        try:
            return tmpl.format(url=url, label=label or url)
        except (KeyError, IndexError, ValueError):
            pass

    message = (cfg.get("message") or "").strip()
    if message:
        if "{url}" in message:
            try:
                return message.format(url=url, label=label or url)
            except (KeyError, IndexError, ValueError):
                return f"{message}\n{url}"
        return f"{message}\n{url}"
    return url


# ---------------------------------------------------------------------------
# แปลงปลายทางที่ผู้ใช้พิมพ์
# ---------------------------------------------------------------------------

_NUMERIC_RE = re.compile(r"^-?\d+$")
_TME_RE = re.compile(r"(?i)^https?://t\.me/([A-Za-z0-9_]+)")


def parse_target(token: str) -> Dict[str, Any]:
    """แปลงสตริงปลายทางเป็น {ref, kind}

    รองรับ:
      "-1001234567890"            -> chat id ตัวเลข (ส่งได้ตรง)
      "123456789"                 -> user id ตัวเลข (ต้องเคยเริ่มแชตกับบอต)
      "@channelusername"          -> username (ต้องเป็น public หรือบอตอยู่ในนั้น)
      "https://t.me/username"     -> ดึง username ออกมา
    คืน {"ref": <int|str>, "kind": "id"|"username"}
    raise ValueError ถ้าแปลงไม่ได้
    """
    tok = (token or "").strip()
    if not tok:
        raise ValueError("ปลายทางว่าง")
    m = _TME_RE.match(tok)
    if m:
        return {"ref": "@" + m.group(1), "kind": "username"}
    if tok.startswith("@") and len(tok) > 1:
        return {"ref": tok, "kind": "username"}
    if _NUMERIC_RE.match(tok):
        return {"ref": int(tok), "kind": "id"}
    # ชื่อเปล่า ๆ ก็ถือเป็น username
    if re.match(r"^[A-Za-z0-9_]{4,}$", tok):
        return {"ref": "@" + tok, "kind": "username"}
    raise ValueError(f"ปลายทางไม่ถูกต้อง: {token!r} (ใช้ chat id, @username หรือ ลิงก์ t.me)")
