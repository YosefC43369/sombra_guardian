# -*- coding: utf-8 -*-
"""autolink/engine.py — ตรรกะกำหนดเวลา/เลือกลิงก์ (pure logic เทสต์ได้)

แยกจาก Telegram และจากดิสก์โดยสิ้นเชิง:
  * parse_duration / format_duration  แปลงสตริงช่วงเวลา <-> วินาที
  * is_due                            แคมเปญถึงเวลายิงหรือยัง
  * seconds_until_due                 อีกกี่วินาทีจะถึงรอบ (ใช้โชว์สถานะ)
  * choose                            เลือกลิงก์ถัดไป + cursor ใหม่ ตามโหมด
  * render                            ประกอบข้อความที่จะส่งจาก template
  * normalize_link                    ทำความสะอาด/ตรวจ URL (อาศัย urlkit)
"""

from __future__ import annotations

import re
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import store

# urlkit อยู่ที่ราก repo — ใช้ตรวจ/ย่อโดเมนลิงก์ ถ้าไม่มีก็ยังทำงานได้
try:
    import urlkit  # type: ignore
    _HAS_URLKIT = True
except Exception:  # pragma: no cover - เผื่อรันแยกบริบท
    urlkit = None  # type: ignore
    _HAS_URLKIT = False


# ---------------------------------------------------------------------------
# ช่วงเวลา
# ---------------------------------------------------------------------------

_DUR_RE = re.compile(r"(?i)^\s*(\d+)\s*([smhd]?)\s*$")
_UNIT_SEC = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """แปลง '45s' / '30m' / '2h' / '1d' / '90' เป็นวินาที

    เลขเปล่า (ไม่มีหน่วย) ตีความเป็น "นาที" ตามสัญชาตญาณผู้ใช้กลุ่มแชต
    raise ValueError ถ้ารูปแบบผิด
    """
    if not text:
        raise ValueError("ต้องระบุช่วงเวลา เช่น 30m, 2h, 1d")
    m = _DUR_RE.match(str(text))
    if not m:
        raise ValueError(f"รูปแบบช่วงเวลาไม่ถูกต้อง: {text!r} (ใช้ได้ เช่น 45s 30m 2h 1d)")
    value = int(m.group(1))
    unit = (m.group(2) or "m").lower()  # ดีฟอลต์ = นาที
    return value * _UNIT_SEC[unit]


def format_duration(seconds: int) -> str:
    """แปลงวินาทีกลับเป็นสตริงอ่านง่าย เช่น 5400 -> '1h 30m'"""
    seconds = int(max(0, seconds))
    if seconds == 0:
        return "0s"
    parts: List[str] = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size:
            qty, seconds = divmod(seconds, size)
            parts.append(f"{qty}{unit}")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# ถึงเวลายัง
# ---------------------------------------------------------------------------

def is_due(campaign: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    """แคมเปญพร้อมยิงไหม: เปิดอยู่ มีลิงก์ และครบรอบช่วงเวลาแล้ว"""
    now = now or store.utcnow()
    if not campaign.get("enabled", True):
        return False
    if not campaign.get("links"):
        return False
    last = store.parse_iso(campaign.get("last_run_iso"))
    if last is None:
        return True  # ยังไม่เคยยิง -> ยิงได้เลยรอบแรก
    interval = int(campaign.get("interval_sec", 0))
    return (now - last).total_seconds() >= interval


def seconds_until_due(campaign: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """อีกกี่วินาทีจะถึงรอบถัดไป (0 = ถึงแล้ว / -1 = ปิดหรือไม่มีลิงก์)"""
    now = now or store.utcnow()
    if not campaign.get("enabled", True) or not campaign.get("links"):
        return -1
    last = store.parse_iso(campaign.get("last_run_iso"))
    if last is None:
        return 0
    interval = int(campaign.get("interval_sec", 0))
    remain = interval - (now - last).total_seconds()
    return max(0, int(round(remain)))


def due_campaigns(db: Dict[str, Any], now: Optional[datetime] = None
                  ) -> List[Tuple[str, Dict[str, Any]]]:
    """สแกนทั้ง DB คืน [(chat_id_str, campaign), ...] ที่ถึงเวลายิง"""
    now = now or store.utcnow()
    out: List[Tuple[str, Dict[str, Any]]] = []
    for chat_id, camp in store.iter_all(db):
        if is_due(camp, now):
            out.append((chat_id, camp))
    return out


# ---------------------------------------------------------------------------
# เลือกลิงก์ถัดไป
# ---------------------------------------------------------------------------

def choose(campaign: Dict[str, Any], rng: Optional[random.Random] = None
           ) -> Tuple[Dict[str, str], int]:
    """เลือกลิงก์ที่จะส่งรอบนี้ ตามโหมด คืน (link, cursor_ถัดไป)

    - sequential : วนตามลำดับ 0,1,2,...,0,1,...
    - single     : ยิงลิงก์แรกซ้ำตลอด
    - random     : สุ่ม (cursor ถัดไปชี้ที่ตัวที่สุ่มได้ ไว้โชว์สถานะ)
    ไม่แก้ campaign ในที่นี้ (pure) — ให้ผู้เรียกเอา cursor ไปบันทึกเอง
    """
    links = campaign.get("links") or []
    if not links:
        raise ValueError("แคมเปญไม่มีลิงก์")
    n = len(links)
    mode = campaign.get("mode", "sequential")
    cur = int(campaign.get("cursor", 0)) % n

    if mode == "single":
        return links[0], 0
    if mode == "random":
        r = rng or random
        idx = r.randrange(n)
        return links[idx], idx
    # sequential (ดีฟอลต์)
    link = links[cur]
    nxt = (cur + 1) % n
    return link, nxt


# ---------------------------------------------------------------------------
# ประกอบข้อความ
# ---------------------------------------------------------------------------

def render(campaign: Dict[str, Any], link: Dict[str, str],
           index: int) -> str:
    """ประกอบข้อความที่จะส่ง จาก template ของแคมเปญ

    ตัวแปรที่ใช้ใน template ได้:
      {url}   ลิงก์เต็ม
      {label} ป้ายกำกับ (ถ้าไม่ตั้ง จะ fallback เป็นโดเมน eTLD+1)
      {n}     ลำดับลิงก์ (เริ่มที่ 1)
      {total} จำนวนลิงก์ทั้งหมดในแคมเปญ
      {title} ชื่อแคมเปญ
    ถ้าไม่มี template -> ส่งเป็น "label — url" หรือ url เปล่า ๆ
    """
    url = (link.get("url") or "").strip()
    label = (link.get("label") or "").strip()
    if not label and _HAS_URLKIT:
        try:
            label = urlkit.etld1(url) or ""
        except Exception:
            label = ""
    total = len(campaign.get("links") or [])
    title = campaign.get("title", "")

    tmpl = (campaign.get("template") or "").strip()
    if tmpl:
        mapping = {
            "url": url,
            "label": label or url,
            "n": index + 1,
            "total": total,
            "title": title,
        }
        try:
            return tmpl.format(**mapping)
        except (KeyError, IndexError, ValueError):
            # template พัง -> ไม่ยอมเงียบ ส่งแบบดีฟอลต์แทน
            pass

    if label and label != url:
        return f"{label} — {url}"
    return url


# ---------------------------------------------------------------------------
# ตรวจ/ทำความสะอาดลิงก์
# ---------------------------------------------------------------------------

def normalize_link(raw: str, label: str = "") -> Dict[str, str]:
    """แปลงสตริงเป็น record ลิงก์ {url, label} — เติม scheme ถ้าไม่มี

    raise ValueError ถ้าไม่ใช่ URL ที่มี host ใช้งานได้
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("ลิงก์ว่าง")

    url = raw
    if not re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", url):
        url = "https://" + url  # เติม scheme ให้เป็นลิงก์กดได้

    host = ""
    is_ip = False
    if _HAS_URLKIT:
        try:
            ex = urlkit.extract(url)
            host, is_ip = ex.host, ex.is_ip
        except Exception:
            host = ""
    else:
        host = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]

    # host ต้องไม่มีช่องว่าง และต้องมีจุด (โดเมนจริง) หรือเป็น IP เท่านั้น
    host_ok = bool(host) and not any(ch.isspace() for ch in host) and (
        is_ip or "." in host)
    if not host_ok:
        raise ValueError(f"ไม่ใช่ลิงก์ที่ใช้งานได้: {raw!r}")

    return {"url": url, "label": (label or "").strip()}
