# -*- coding: utf-8 -*-
"""group_security_intelligence/service.py — ชั้นประสานงาน (async) + audit + แจ้งเตือน + loop

ตัวกลางที่ร้อยทุกส่วนเข้าด้วยกัน และเป็นที่เดียวที่คุยกับ Telegram/โมดูลอื่น:
  * audit()                บันทึก audit trail — index เร็วใน store + ต่อ integrity_ledger
                           (Merkle tamper-evident) ที่มีอยู่แล้วของโปรเจกต์ (reuse)
  * notify()               แจ้งเตือนเข้า group แบบ throttle/dedupe ตาม policy
  * process_events()       รับ event จาก monitor -> audit + correlate + แจ้งเตือน
  * scan_message()         ตรวจ secret + social engineering จากข้อความ (เรียกจาก handle_message)
  * observe_admin_transition()  รับการเปลี่ยนแอดมินจาก on_chat_member_update
  * poll_chat() / background_loop()  snapshot แอดมิน/คอนฟิกเป็นรอบ (Bot API ไม่ push ทุกอย่าง)
  * backup/recovery        สำเนา+กู้คืนเฉพาะคุณสมบัติที่ Bot API รองรับจริง

ทุกการคุยกับ Telegram ห่อ try/except + รองรับ RetryAfter; ไม่มี path ไหนทำให้ลูปหลักล้ม
"""

from __future__ import annotations

import os
import uuid
import asyncio
import logging
from typing import Any, Dict, List, Optional

from . import store, detectors, monitor, correlate

logger = logging.getLogger("modbot.gsi.service")

TICK_SECONDS = int(os.getenv("GSI_TICK", "120") or "120")

# --- external deps แบบ guarded (รันจริงมีครบ; เทสต์/รันแยกไม่ต้องมี) ---
try:
    import integrity_ledger as _ledger  # tamper-evident audit (reuse)
except Exception:  # pragma: no cover
    _ledger = None

try:
    from telegram.error import TelegramError, RetryAfter, Forbidden, BadRequest
except Exception:  # pragma: no cover
    class TelegramError(Exception):
        pass

    class RetryAfter(TelegramError):
        retry_after = 0

    class Forbidden(TelegramError):
        pass

    class BadRequest(TelegramError):
        pass

_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _sev_ge(a: str, b: str) -> bool:
    return _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0)


# ---------------------------------------------------------------------------
# AUDIT TRAIL (reuse integrity_ledger สำหรับ tamper-evidence)
# ---------------------------------------------------------------------------

def audit(chat_id, category: str, severity: str, detail: str,
          actor_id: Optional[int] = None, before=None, after=None,
          action: Optional[str] = None, incident_id: Optional[str] = None,
          kind: Optional[str] = None, path: Optional[str] = None) -> Dict[str, Any]:
    """เขียน audit record หนึ่งรายการ

    - เก็บ index แบบ query เร็วใน store (redact มาก่อนแล้วจากผู้เรียก)
    - ส่งเข้า integrity_ledger.record_event เพื่อความ tamper-evident จริง (best-effort)
    คืน record ที่บันทึก
    """
    rec = {
        "id": uuid.uuid4().hex[:16],
        "ts": store.iso(),
        "chat_id": int(chat_id),
        "category": category,
        "kind": kind or category,
        "severity": severity,
        "actor_id": actor_id,
        "detail": detail,
        "before": before,
        "after": after,
        "action": action,
        "incident_id": incident_id,
    }

    def _mut(node):
        store._append_capped(node["audit_index"], rec, store.MAX_AUDIT_INDEX)
        return rec

    store.mutate_chat(chat_id, _mut, path)

    # tamper-evident anchor (ไม่ให้ความล้มเหลวของ ledger ทำให้ audit หลักพัง)
    if _ledger is not None:
        try:
            _ledger.record_event(
                int(chat_id), "GSI_" + category.upper(),
                payload={"id": rec["id"], "severity": severity,
                         "kind": rec["kind"], "detail": detail,
                         "actor_id": actor_id, "action": action,
                         "incident_id": incident_id},
                actor=str(actor_id) if actor_id else None,
                idempotency_key="gsi:" + rec["id"],
            )
        except Exception:
            logger.exception("GSI audit ledger anchor failed | chat=%s", chat_id)
    return rec


def verify_audit(chat_id) -> Dict[str, Any]:
    """ตรวจความครบถ้วนของ audit ผ่าน integrity_ledger (ถ้ามี)"""
    if _ledger is None:
        return {"available": False, "reason": "integrity_ledger ไม่พร้อมใช้งาน"}
    try:
        count = _ledger.entry_count(int(chat_id))
        root = _ledger.current_root(int(chat_id))
        return {"available": True, "entries": count, "merkle_root": root}
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ---------------------------------------------------------------------------
# NOTIFICATION (throttle + dedupe + ระดับขั้นต่ำ)
# ---------------------------------------------------------------------------

def _should_notify(node: Dict[str, Any], key: str, severity: str) -> bool:
    pol = node["policy"]
    if not pol.get("notify", True):
        return False
    if not _sev_ge(severity, pol.get("notify_min_severity", "MEDIUM")):
        return False
    throttle = int(pol.get("notify_throttle_sec", 300))
    st = node["notif_state"]
    last = store.parse_iso(st.get(key))
    now = store.utcnow()
    if last is not None and (now - last).total_seconds() < throttle:
        return False
    st[key] = store.iso(now)
    return True


async def notify(bot, chat_id, text: str, severity: str, key: str,
                 path: Optional[str] = None) -> bool:
    """แจ้งเตือนเข้า group (ตาม convention ของ sg_platform) แบบ throttle/dedupe

    key = ตัวระบุชนิดการแจ้งเตือน ใช้กันซ้ำ/throttle
    คืน True ถ้าส่งจริง
    """
    allow = store.mutate_chat(chat_id, lambda n: _should_notify(n, key, severity), path)
    if not allow:
        return False
    try:
        await bot.send_message(chat_id=int(chat_id),
                               text=f"🛡 [ความปลอดภัยกลุ่ม] {text}",
                               disable_web_page_preview=True)
        return True
    except RetryAfter as e:
        await asyncio.sleep(min(int(getattr(e, "retry_after", 1)) + 1, 60))
        try:
            await bot.send_message(chat_id=int(chat_id),
                                   text=f"🛡 [ความปลอดภัยกลุ่ม] {text}",
                                   disable_web_page_preview=True)
            return True
        except Exception:
            return False
    except (Forbidden, BadRequest, TelegramError):
        return False
    except Exception:
        logger.exception("GSI notify failed | chat=%s", chat_id)
        return False


# ---------------------------------------------------------------------------
# ประมวลผล event จาก monitor -> audit + correlate + แจ้งเตือน
# ---------------------------------------------------------------------------

async def process_events(bot, chat_id, events: List[Dict[str, Any]],
                         source: str, path: Optional[str] = None) -> None:
    """รับ list event (จาก diff ของ monitor) แล้ว audit + ป้อน correlation + แจ้งเตือน"""
    if not events:
        return
    for e in events:
        audit(chat_id, source, e.get("severity", "LOW"), e.get("detail", ""),
              actor_id=e.get("actor_id"), before=e.get("before"),
              after=e.get("after"), kind=e.get("kind"), path=path)
        if _sev_ge(e.get("severity", "LOW"), "HIGH"):
            await notify(bot, chat_id, e.get("detail", "ตรวจพบการเปลี่ยนแปลงสำคัญ"),
                         e.get("severity", "HIGH"), key=f"evt:{e.get('kind')}", path=path)

    await run_correlation(bot, chat_id, path=path)


async def run_correlation(bot, chat_id, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """รัน correlation บน audit ล่าสุดในหน้าต่างเวลา สร้าง incident ถ้าเข้าเกณฑ์"""
    node = store.get_chat(store.load(path), chat_id)
    pol = node["policy"]
    window = int(pol.get("correlation_window_sec", 900))
    min_ev = int(pol.get("correlation_min_events", 2))

    now = store.utcnow()
    cutoff = now.timestamp() - window
    # เอาเฉพาะเหตุการณ์เชิงโครงสร้าง (ไม่รวม secret/se ที่เป็นราย message) ในหน้าต่าง
    corr_src = [a for a in node["audit_index"]
                if a.get("category") in ("admin", "config", "invite", "social_eng")
                and (store.parse_iso(a.get("ts")) or now).timestamp() >= cutoff]
    incidents = correlate.correlate(corr_src, window_sec=window,
                                    min_events=min_ev, now=now)
    if not incidents:
        return None

    # เอา incident ล่าสุด/หนักสุด ที่ยังไม่เคยบันทึก (กันสร้างซ้ำด้วย fingerprint)
    inc = max(incidents, key=lambda i: i["score"])
    fp = _incident_fingerprint(inc)

    def _mut(n):
        for existing in n["incidents"]:
            if existing.get("fingerprint") == fp:
                return None  # บันทึกแล้ว
        rec = {
            "id": uuid.uuid4().hex[:12],
            "fingerprint": fp,
            "created_iso": store.iso(),
            "level": inc["level"],
            "score": inc["score"],
            "kinds": inc["kinds"],
            "actors": inc["actors"],
            "explanation": inc["explanation"],
            "event_count": len(inc["events"]),
            "start_iso": inc["start_iso"],
            "end_iso": inc["end_iso"],
            "status": "OPEN",
        }
        store._append_capped(n["incidents"], rec, store.MAX_INCIDENTS)
        return rec

    rec = store.mutate_chat(chat_id, _mut, path)
    if rec is None:
        return None

    audit(chat_id, "incident", rec["level"],
          f"สร้าง incident #{rec['id']} ({rec['level']}): {rec['explanation']}",
          incident_id=rec["id"], kind="incident_created", path=path)
    if _sev_ge(rec["level"], node["policy"].get("notify_min_severity", "MEDIUM")):
        await notify(bot, chat_id,
                     f"พบเหตุการณ์ที่อาจเชื่อมโยงกัน (incident #{rec['id']}, ระดับ {rec['level']})\n"
                     f"{rec['explanation']}",
                     rec["level"], key=f"incident:{rec['level']}", path=path)
    return rec


def _incident_fingerprint(inc: Dict[str, Any]) -> str:
    import hashlib
    basis = inc["start_iso"] + "|" + "|".join(sorted(inc["kinds"].keys()))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# ตรวจข้อความ: secret + social engineering
# ---------------------------------------------------------------------------

async def scan_message(bot, chat_id, user_id, text: str,
                       username: Optional[str] = None,
                       message_id: Optional[int] = None,
                       delete_cb=None, path: Optional[str] = None) -> None:
    """ตรวจข้อความหนึ่ง — เรียกจาก handle_message (ควร schedule เป็น task ไม่บล็อก)

    delete_cb: coroutine ลบข้อความ (ถ้า policy ให้ลบ secret) — ส่งจาก app.py
    """
    try:
        node = store.get_chat(store.load(path), chat_id)
        pol = node["policy"]
        if not pol.get("enabled", True):
            return

        if pol.get("secret_scan", True):
            await _scan_secrets(bot, chat_id, user_id, username, text,
                                message_id, delete_cb, pol, path)
        if pol.get("social_eng_scan", True):
            await _scan_social_eng(bot, chat_id, user_id, username, text, pol, path)
    except Exception:
        logger.exception("GSI scan_message error | chat=%s", chat_id)


async def _scan_secrets(bot, chat_id, user_id, username, text, message_id,
                        delete_cb, pol, path):
    findings = detectors.scan_secrets(text)
    if not findings:
        return
    worst = detectors.highest_severity(findings)
    types = ", ".join(sorted({f["type"] for f in findings}))
    redacted = ", ".join(f"{f['type']}={f['redacted']}" for f in findings[:5])

    def _mut(node):
        for f in findings:
            store._append_capped(node["secret_findings"], {
                "ts": store.iso(), "user_id": user_id, "username": username,
                "type": f["type"], "severity": f["severity"],
                "redacted": f["redacted"], "fingerprint": f["fingerprint"],
                "message_id": message_id,
            }, store.MAX_FINDINGS)

    store.mutate_chat(chat_id, _mut, path)
    audit(chat_id, "secret", worst,
          f"พบข้อมูลลับในข้อความจาก {_u(username, user_id)}: {types}",
          actor_id=user_id, kind="secret_detected",
          after={"types": types, "redacted": redacted}, path=path)

    # ลบข้อความถ้าตั้งนโยบายและมี callback (ไม่เคยเก็บ/ส่งต่อค่าจริง)
    if pol.get("delete_detected_secrets") and delete_cb and message_id:
        try:
            await delete_cb()
            audit(chat_id, "secret", worst, "ลบข้อความที่มีข้อมูลลับอัตโนมัติ",
                  actor_id=user_id, action="message_deleted", kind="secret_deleted", path=path)
        except Exception:
            logger.info("GSI could not delete secret message | chat=%s", chat_id)

    await notify(bot, chat_id,
                 f"⚠️ ตรวจพบข้อมูลลับที่อาจหลุด ({types}) จาก {_u(username, user_id)}\n"
                 f"ค่าแสดงแบบปิดบัง: {redacted}\n"
                 f"แนะนำ: เพิกถอน/หมุนคีย์ที่หลุดทันที และลบข้อความ",
                 worst, key="secret_leak", path=path)


async def _scan_social_eng(bot, chat_id, user_id, username, text, pol, path):
    result = detectors.analyze_social_eng(text)
    if not result:
        return

    # AI เสริม (ถ้าเปิด + มีไคลเอนต์เดิม) — ไม่สร้างคอนฟิก AI ใหม่, redact ก่อนส่ง
    if pol.get("social_eng_use_ai") and result["risk_score"] >= 40:
        try:
            boosted = await _ai_second_opinion(text, result)
            if boosted:
                result = boosted
        except Exception:
            logger.info("GSI AI SE analysis skipped (error)")

    sev = _se_level(result["risk_score"])

    def _mut(node):
        store._append_capped(node["se_findings"], {
            "ts": store.iso(), "user_id": user_id, "username": username,
            "category": result["category"], "risk_score": result["risk_score"],
            "confidence": result["confidence"], "indicators": result["indicators"],
            "explanation": result["explanation"],
            "recommended_action": result["recommended_action"],
        }, store.MAX_FINDINGS)

    store.mutate_chat(chat_id, _mut, path)
    audit(chat_id, "social_eng", sev,
          f"ข้อความน่าสงสัย (social engineering) จาก {_u(username, user_id)}: "
          f"{result['explanation']} [score={result['risk_score']}]",
          actor_id=user_id, kind="social_eng_detected",
          after={"category": result["category"], "score": result["risk_score"]},
          path=path)

    if result["risk_score"] >= 45:
        await notify(bot, chat_id,
                     f"⚠️ ข้อความอาจเป็นการหลอกลวง ({result['category']}, "
                     f"score {result['risk_score']}/100) จาก {_u(username, user_id)}\n"
                     f"{result['explanation']}\nแนะนำ: {result['recommended_action']}",
                     sev, key="social_eng", path=path)


async def _ai_second_opinion(text: str, base: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """ใช้ AI ไคลเอนต์เดิม (gemini.ask_gemini) ช่วยยืนยัน — reuse ไม่สร้างใหม่

    ส่งเฉพาะข้อความที่เกี่ยวข้อง ไม่ส่งข้อมูลระบุตัวตนสมาชิก
    """
    try:
        import gemini
    except Exception:
        return None
    prompt = (
        "วิเคราะห์ว่าข้อความต่อไปนี้ในแชตกลุ่มเข้าข่าย social engineering/หลอกลวงไหม "
        "ตอบสั้น ๆ ว่า risk: <0-100> และเหตุผลหนึ่งบรรทัด เท่านั้น\n\nข้อความ:\n" + text[:1000]
    )
    ok, reply = await gemini.ask_gemini(prompt)
    if not ok or not reply:
        return None
    import re
    m = re.search(r"risk\s*[:=]?\s*(\d{1,3})", reply, re.I)
    if m:
        ai_score = max(0, min(100, int(m.group(1))))
        merged = dict(base)
        merged["risk_score"] = int(round((base["risk_score"] + ai_score) / 2))
        merged["confidence"] = min(1.0, base["confidence"] + 0.1)
        merged["explanation"] += f" | AI: {reply.strip()[:160]}"
        return merged
    return base


def _se_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# แอดมิน event-driven (จาก on_chat_member_update)
# ---------------------------------------------------------------------------

async def observe_admin_transition(bot, chat_id, old_member: Optional[Dict[str, Any]],
                                   new_member: Dict[str, Any],
                                   actor_id: Optional[int] = None,
                                   path: Optional[str] = None) -> None:
    """รับการเปลี่ยนสถานะแอดมินรายคนแบบทันที — เรียกจาก app.on_chat_member_update"""
    try:
        events = monitor.diff_admin_transition(old_member, new_member, actor_id)
        if events:
            await process_events(bot, chat_id, events, "admin", path=path)
    except Exception:
        logger.exception("GSI observe_admin_transition error | chat=%s", chat_id)


# ---------------------------------------------------------------------------
# SNAPSHOT POLL (admin + config) — Bot API ไม่ push ทุกอย่าง
# ---------------------------------------------------------------------------

async def _fetch_admin_snapshot(bot, chat_id) -> Optional[List[Dict[str, Any]]]:
    try:
        admins = await bot.get_chat_administrators(int(chat_id))
    except (Forbidden, BadRequest, TelegramError):
        return None
    except Exception:
        logger.exception("GSI get_chat_administrators failed | chat=%s", chat_id)
        return None
    out = []
    for cm in admins:
        u = cm.user
        row = {"user_id": u.id, "status": str(cm.status),
               "username": u.username, "display": u.full_name}
        for p in monitor.ADMIN_PERMS:
            row[p] = bool(getattr(cm, p, False))
        out.append(row)
    return out


async def _fetch_config_snapshot(bot, chat_id) -> Optional[Dict[str, Any]]:
    try:
        chat = await bot.get_chat(int(chat_id))
    except (Forbidden, BadRequest, TelegramError):
        return None
    except Exception:
        logger.exception("GSI get_chat failed | chat=%s", chat_id)
        return None
    perms = {}
    cp = getattr(chat, "permissions", None)
    if cp is not None:
        for attr in ("can_send_messages", "can_send_polls", "can_send_other_messages",
                     "can_add_web_page_previews", "can_change_info", "can_invite_users",
                     "can_pin_messages", "can_manage_topics", "can_send_audios",
                     "can_send_documents", "can_send_photos", "can_send_videos"):
            perms[attr] = bool(getattr(cp, attr, False))
    photo = getattr(chat, "photo", None)
    return {
        "title": getattr(chat, "title", None),
        "description": getattr(chat, "description", None),
        "username": getattr(chat, "username", None),
        "has_photo": photo is not None,
        "photo_id": getattr(photo, "big_file_unique_id", None) if photo else None,
        "permissions": perms,
        "slow_mode_delay": getattr(chat, "slow_mode_delay", None),
        "linked_chat_id": getattr(chat, "linked_chat_id", None),
        "join_by_request": getattr(chat, "join_by_request", None),
        "has_protected_content": getattr(chat, "has_protected_content", None),
        "message_auto_delete_time": getattr(chat, "message_auto_delete_time", None),
    }


async def poll_chat(bot, chat_id, path: Optional[str] = None,
                    force_baseline: bool = False) -> Dict[str, Any]:
    """snapshot แอดมิน+คอนฟิกหนึ่งรอบ, diff กับของเดิม, audit+แจ้งเตือน

    คืนสรุป {admin_events, config_events, integrity_status}
    ครั้งแรก (ยังไม่มี baseline) จะตั้ง baseline เงียบ ๆ ไม่แจ้งเตือน
    """
    summary = {"admin_events": 0, "config_events": 0, "integrity_status": monitor.INTEGRITY_NORMAL}
    node = store.get_chat(store.load(path), chat_id)
    if not node["policy"].get("enabled", True):
        return summary

    # แอดมิน
    admins = await _fetch_admin_snapshot(bot, chat_id)
    if admins is not None:
        new_snap = monitor.snapshot_admins(admins, store.iso())
        old_snap = node.get("admins")
        events = monitor.diff_admins(old_snap, new_snap) if not force_baseline else []
        store.mutate_chat(chat_id, lambda n: n.__setitem__("admins", new_snap), path)
        if events:
            summary["admin_events"] = len(events)
            await process_events(bot, chat_id, events, "admin", path=path)

    # คอนฟิก
    props = await _fetch_config_snapshot(bot, chat_id)
    if props is not None:
        new_cfg = monitor.snapshot_config(props, store.iso())
        old_cfg = node.get("config")
        events, status = (([], monitor.INTEGRITY_NORMAL)
                          if force_baseline else monitor.diff_config(old_cfg, new_cfg))
        store.mutate_chat(chat_id, lambda n: n.__setitem__("config", new_cfg), path)
        store.mutate_chat(chat_id, lambda n: n["invites"].__setitem__("last_status", status), path)
        summary["integrity_status"] = status
        if events:
            summary["config_events"] = len(events)
            await process_events(bot, chat_id, events, "config", path=path)
            if status in (monitor.INTEGRITY_SUSPICIOUS, monitor.INTEGRITY_REQUIRES_REVIEW):
                await notify(bot, chat_id,
                             f"สถานะความครบถ้วนของคอนฟิกกลุ่ม: {status} "
                             f"({summary['config_events']} การเปลี่ยนแปลง)",
                             "HIGH" if status == monitor.INTEGRITY_REQUIRES_REVIEW else "MEDIUM",
                             key="integrity_status", path=path)
    return summary


async def ensure_baseline(bot, chat_id, path: Optional[str] = None) -> Dict[str, Any]:
    """สร้าง baseline snapshot (เรียกตอนเปิดใช้งานครั้งแรกในกลุ่ม)"""
    return await poll_chat(bot, chat_id, path=path, force_baseline=True)


async def background_loop(bot) -> None:
    """ลูป poll snapshot เป็นรอบ — เรียกจาก post_init"""
    await asyncio.sleep(12)
    logger.info("GSI LOOP STARTED | tick=%ss", TICK_SECONDS)
    while True:
        try:
            db = store.load()
            now = store.utcnow()
            for chat_id, node in list(db.get("chats", {}).items()):
                pol = dict(store.DEFAULT_POLICY)
                pol.update(node.get("policy", {}))
                if not pol.get("enabled", True):
                    continue
                interval = int(pol.get("snapshot_interval_sec", 3600))
                last = store.parse_iso((node.get("config") or {}).get("taken_iso"))
                if last is not None and (now - last).total_seconds() < interval:
                    continue
                try:
                    await poll_chat(bot, chat_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("GSI poll_chat error | chat=%s", chat_id)
                # prune retention เป็นครั้งคราว
                store.mutate_chat(chat_id, lambda n: store.prune_retention(n, now))
        except asyncio.CancelledError:
            logger.info("GSI LOOP CANCELLED — stopping")
            raise
        except Exception:
            logger.exception("GSI BACKGROUND LOOP ERROR")
        await asyncio.sleep(TICK_SECONDS)


# ---------------------------------------------------------------------------
# INVITE registry (event-driven + manual)
# ---------------------------------------------------------------------------

def register_invite(chat_id, link: str, name: Optional[str] = None,
                    creator_id: Optional[int] = None, is_primary: bool = False,
                    trusted: bool = True, path: Optional[str] = None) -> None:
    """เพิ่มลิงก์เชิญเข้าทะเบียนเชื่อถือ (เก็บลิงก์เต็มในไฟล์ข้อมูลที่ไม่เปิดเผย เท่านั้น)"""
    def _mut(node):
        node["invites"]["registry"][link] = {
            "link": link, "name": name, "creator_id": creator_id,
            "is_primary": is_primary, "trusted": trusted,
            "is_revoked": False, "added_iso": store.iso(),
        }
    store.mutate_chat(chat_id, _mut, path)


async def observe_invite_from_join(bot, chat_id, link: str, name: Optional[str],
                                   creator_id: Optional[int],
                                   path: Optional[str] = None) -> None:
    """ลิงก์เชิญที่ติดมากับการ join (จาก on_chat_member_update) — เทียบทะเบียน"""
    try:
        node = store.get_chat(store.load(path), chat_id)
        registry = node["invites"]["registry"]
        current = [{"link": link, "name": name, "creator_id": creator_id,
                    "is_revoked": False, "is_primary": False,
                    "trusted": link in registry}]
        events = monitor.diff_invites(registry, current)
        # บันทึกลิงก์ที่เพิ่งเห็นเข้า history (แบบ safe)
        def _mut(n):
            store._append_capped(n["invites"]["history"],
                                 {"ts": store.iso(), **monitor._safe_invite(current[0])},
                                 store.MAX_INVITE_HISTORY)
            # ลิงก์ที่เห็นครั้งแรกและไม่อยู่ทะเบียน -> เพิ่มแบบ "ยังไม่เชื่อถือ"
            if link not in n["invites"]["registry"]:
                n["invites"]["registry"][link] = {
                    "link": link, "name": name, "creator_id": creator_id,
                    "is_primary": False, "trusted": False,
                    "is_revoked": False, "added_iso": store.iso(),
                }
        store.mutate_chat(chat_id, _mut, path)
        if events:
            await process_events(bot, chat_id, events, "invite", path=path)
    except Exception:
        logger.exception("GSI observe_invite error | chat=%s", chat_id)


# ---------------------------------------------------------------------------
# BACKUP & RECOVERY (เฉพาะคุณสมบัติที่ Bot API รองรับจริง)
# ---------------------------------------------------------------------------

# คุณสมบัติที่ "กู้คืนได้จริง" ผ่าน Bot API (ต้องมีสิทธิ์ can_change_info)
RESTORABLE = ("title", "description", "permissions")


async def create_backup(bot, chat_id, actor_id: Optional[int] = None,
                        path: Optional[str] = None) -> Dict[str, Any]:
    """สร้าง backup การตั้งค่าที่บอตเข้าถึงได้ — คืน record backup"""
    admins = await _fetch_admin_snapshot(bot, chat_id)
    props = await _fetch_config_snapshot(bot, chat_id)
    node = store.get_chat(store.load(path), chat_id)

    def _mut(n):
        bid = store.next_seq(n)
        rec = {
            "id": bid,
            "version": 1,
            "created_iso": store.iso(),
            "created_by": actor_id,
            "admins": monitor.snapshot_admins(admins or [], store.iso()),
            "config": monitor.snapshot_config(props or {}, store.iso()),
            "policy": dict(n["policy"]),
            "invite_registry_meta": [
                monitor._safe_invite(v) for v in n["invites"]["registry"].values()
            ],
        }
        store._append_capped(n["backups"], rec, store.MAX_BACKUPS)
        return rec

    rec = store.mutate_chat(chat_id, _mut, path)
    audit(chat_id, "backup", "INFO", f"สร้าง backup #{rec['id']}",
          actor_id=actor_id, action="backup_created", kind="backup_created", path=path)
    return rec


def list_backups(chat_id, path: Optional[str] = None) -> List[Dict[str, Any]]:
    return store.get_chat(store.load(path), chat_id)["backups"]


def get_backup(chat_id, backup_id: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for b in list_backups(chat_id, path):
        if b["id"] == backup_id:
            return b
    return None


async def recovery_diff(bot, chat_id, backup_id: int,
                        path: Optional[str] = None) -> Dict[str, Any]:
    """เทียบคอนฟิกปัจจุบันกับ backup — คืนแผนกู้คืน (ยังไม่ลงมือ)"""
    backup = get_backup(chat_id, backup_id, path)
    if not backup:
        return {"ok": False, "reason": f"ไม่พบ backup #{backup_id}"}
    props = await _fetch_config_snapshot(bot, chat_id)
    if props is None:
        return {"ok": False, "reason": "อ่านคอนฟิกปัจจุบันไม่ได้"}
    cur = monitor.snapshot_config(props, store.iso())["props"]
    old = backup["config"]["props"]
    changes = []
    for key in RESTORABLE:
        if cur.get(key) != old.get(key):
            changes.append({"key": key, "current": cur.get(key),
                            "backup": old.get(key), "restorable": True})
    # รายการที่ต่างแต่กู้ไม่ได้ (ให้ผู้ใช้รู้ข้อจำกัด)
    unrestorable = []
    for key in ("username", "linked_chat_id", "join_by_request", "has_photo"):
        if cur.get(key) != old.get(key):
            unrestorable.append({"key": key, "current": cur.get(key), "backup": old.get(key)})
    return {"ok": True, "backup_id": backup_id, "changes": changes,
            "unrestorable": unrestorable}


async def apply_recovery(bot, chat_id, backup_id: int, keys: List[str],
                         actor_id: int, path: Optional[str] = None) -> Dict[str, Any]:
    """กู้คืนคุณสมบัติที่เลือก (เฉพาะ RESTORABLE) ผ่าน Bot API — ต้องยืนยันมาก่อนแล้ว

    บันทึกทุกการกู้คืนลง audit trail
    """
    backup = get_backup(chat_id, backup_id, path)
    if not backup:
        return {"ok": False, "reason": f"ไม่พบ backup #{backup_id}"}
    old = backup["config"]["props"]
    done, failed = [], []
    for key in keys:
        if key not in RESTORABLE:
            failed.append({"key": key, "reason": "คุณสมบัตินี้กู้คืนผ่าน Bot API ไม่ได้"})
            continue
        try:
            if key == "title" and old.get("title"):
                await bot.set_chat_title(int(chat_id), old["title"])
            elif key == "description":
                await bot.set_chat_description(int(chat_id), old.get("description") or "")
            elif key == "permissions" and old.get("permissions"):
                await _restore_permissions(bot, chat_id, old["permissions"])
            else:
                failed.append({"key": key, "reason": "ไม่มีค่าใน backup"})
                continue
            done.append(key)
            audit(chat_id, "recovery", "MEDIUM",
                  f"กู้คืน {key} จาก backup #{backup_id}",
                  actor_id=actor_id, action="recovery_applied",
                  kind="recovery_applied", before={"key": key}, path=path)
        except (Forbidden, BadRequest) as e:
            failed.append({"key": key, "reason": f"สิทธิ์ไม่พอ/คำสั่งถูกปฏิเสธ: {e}"})
        except Exception as e:
            logger.exception("GSI recovery apply error | chat=%s key=%s", chat_id, key)
            failed.append({"key": key, "reason": str(e)})
    return {"ok": True, "restored": done, "failed": failed}


_CHAT_PERM_KEYS = (
    "can_send_messages", "can_send_polls", "can_send_other_messages",
    "can_add_web_page_previews", "can_change_info", "can_invite_users",
    "can_pin_messages", "can_manage_topics", "can_send_audios",
    "can_send_documents", "can_send_photos", "can_send_videos",
    "can_send_video_notes", "can_send_voice_notes",
)


async def _restore_permissions(bot, chat_id, perms: Dict[str, Any]) -> None:
    from telegram import ChatPermissions
    kwargs = {k: bool(v) for k, v in perms.items() if k in _CHAT_PERM_KEYS}
    await bot.set_chat_permissions(int(chat_id), ChatPermissions(**kwargs))


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------

def _u(username: Optional[str], user_id) -> str:
    return f"@{username}" if username else f"user {user_id}"
