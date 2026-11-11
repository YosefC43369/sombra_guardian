# -*- coding: utf-8 -*-
"""group_security_intelligence/monitor.py — snapshot & diff ของแอดมิน/คอนฟิก/ลิงก์เชิญ

pure logic ทั้งหมด: ทำงานบน dict ล้วน (ชั้น service เป็นคนแปลง object ของ telegram
เป็น dict ก่อน) จึงเทสต์ได้ง่ายและไม่ผูกกับ Bot API

ครอบคลุม:
  snapshot_admins / diff_admins       — โครงแอดมิน + สิทธิ์ (เลื่อนขั้น/ลดขั้น/สิทธิ์เปลี่ยน)
  snapshot_config / diff_config       — การตั้งค่ากลุ่ม + สถานะ integrity
  diff_invites                        — ทะเบียนลิงก์เชิญ (ลิงก์ใหม่/ถูกเพิกถอน)

ทุก diff คืน list ของ "event" รูปแบบเดียวกัน: {kind, severity, actor_id, detail, before, after}
severity: INFO / LOW / MEDIUM / HIGH / CRITICAL
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# สถานะ integrity ของคอนฟิกกลุ่ม
INTEGRITY_NORMAL = "NORMAL"
INTEGRITY_CHANGED = "CHANGED"
INTEGRITY_SUSPICIOUS = "SUSPICIOUS"
INTEGRITY_REQUIRES_REVIEW = "REQUIRES_REVIEW"

# ธงสิทธิ์แอดมินที่ Bot API เปิดให้เห็น (ChatMemberAdministrator)
ADMIN_PERMS = (
    "can_manage_chat", "can_delete_messages", "can_manage_video_chats",
    "can_restrict_members", "can_promote_members", "can_change_info",
    "can_invite_users", "can_pin_messages", "can_manage_topics",
    "can_post_messages", "can_edit_messages", "is_anonymous",
)

# การได้/เสียสิทธิ์เหล่านี้ถือว่า "อ่อนไหวสูง" (ยึดกลุ่มได้)
_SENSITIVE_PERMS = {"can_promote_members", "can_restrict_members",
                    "can_delete_messages", "can_change_info"}

# คุณสมบัติคอนฟิกที่ถือว่าอ่อนไหว (เปลี่ยนแล้วน่าสงสัย)
_SENSITIVE_CONFIG = {"username", "permissions", "linked_chat_id",
                     "join_by_request", "title"}


# ---------------------------------------------------------------------------
# แอดมิน
# ---------------------------------------------------------------------------

def snapshot_admins(admins: List[Dict[str, Any]], taken_iso: str) -> Dict[str, Any]:
    """สร้าง snapshot โครงแอดมินจาก list ของ dict (แต่ละตัวมาจาก ChatMember*)"""
    norm = {}
    for a in admins or []:
        uid = a.get("user_id")
        if uid is None:
            continue
        norm[str(uid)] = {
            "user_id": uid,
            "status": a.get("status", "administrator"),
            "username": a.get("username"),
            "display": a.get("display"),
            "perms": {p: bool(a.get(p, False)) for p in ADMIN_PERMS},
        }
    return {"taken_iso": taken_iso, "admins": norm}


def diff_admins(old: Optional[Dict[str, Any]], new: Dict[str, Any]
                ) -> List[Dict[str, Any]]:
    """เทียบ snapshot แอดมินเก่า/ใหม่ คืน list เหตุการณ์

    ถ้า old เป็น None (ยังไม่เคยมี baseline) คืน [] — ครั้งแรกแค่ตั้ง baseline
    """
    if not old:
        return []
    events: List[Dict[str, Any]] = []
    old_a = old.get("admins", {})
    new_a = new.get("admins", {})

    for uid, info in new_a.items():
        if uid not in old_a:
            sev = "HIGH" if info["perms"].get("can_promote_members") else "MEDIUM"
            events.append(_ev("admin_promoted", sev, None,
                              f"แอดมินใหม่: {_who(info)}", None, info))
        else:
            changed = _perm_delta(old_a[uid]["perms"], info["perms"])
            if changed:
                sev = "HIGH" if any(p in _SENSITIVE_PERMS for p, _ in changed) else "MEDIUM"
                detail = "สิทธิ์เปลี่ยน: " + ", ".join(
                    f"{p}={'+' if v else '-'}" for p, v in changed)
                events.append(_ev("admin_perms_changed", sev, None,
                                  f"{_who(info)} — {detail}",
                                  old_a[uid]["perms"], info["perms"]))
            if old_a[uid].get("status") != info.get("status"):
                events.append(_ev("admin_status_changed", "MEDIUM", None,
                                  f"{_who(info)}: {old_a[uid].get('status')} -> {info.get('status')}",
                                  old_a[uid].get("status"), info.get("status")))

    for uid, info in old_a.items():
        if uid not in new_a:
            events.append(_ev("admin_demoted", "MEDIUM", None,
                              f"ถูกถอดจากแอดมิน: {_who(info)}", info, None))
    return events


def diff_admin_transition(old_member: Optional[Dict[str, Any]],
                          new_member: Dict[str, Any],
                          actor_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """เทียบการเปลี่ยนสถานะแอดมินของ "รายคน" จาก ChatMemberUpdated (event-driven)

    ใช้จาก on_chat_member_update ของ app.py — ตรวจเลื่อน/ลดขั้น + สิทธิ์เปลี่ยน ทันที
    """
    old_status = (old_member or {}).get("status")
    new_status = new_member.get("status")
    admin_states = ("administrator", "creator")
    was_admin = old_status in admin_states
    is_admin = new_status in admin_states
    who = _who(new_member)
    events: List[Dict[str, Any]] = []

    if not was_admin and is_admin:
        perms = {p: bool(new_member.get(p, False)) for p in ADMIN_PERMS}
        sev = "HIGH" if perms.get("can_promote_members") or new_status == "creator" else "MEDIUM"
        events.append(_ev("admin_promoted", sev, actor_id,
                          f"เลื่อนเป็นแอดมิน: {who}", None, {"perms": perms}))
    elif was_admin and not is_admin:
        events.append(_ev("admin_demoted", "MEDIUM", actor_id,
                          f"ถอดจากแอดมิน: {who}", {"status": old_status}, {"status": new_status}))
    elif was_admin and is_admin:
        oldp = {p: bool((old_member or {}).get(p, False)) for p in ADMIN_PERMS}
        newp = {p: bool(new_member.get(p, False)) for p in ADMIN_PERMS}
        changed = _perm_delta(oldp, newp)
        if changed:
            sev = "HIGH" if any(p in _SENSITIVE_PERMS for p, _ in changed) else "MEDIUM"
            detail = ", ".join(f"{p}={'+' if v else '-'}" for p, v in changed)
            events.append(_ev("admin_perms_changed", sev, actor_id,
                              f"{who} — สิทธิ์เปลี่ยน: {detail}", oldp, newp))
    return events


def _perm_delta(old_perms: Dict[str, bool], new_perms: Dict[str, bool]):
    out = []
    for p in ADMIN_PERMS:
        o = bool(old_perms.get(p, False))
        n = bool(new_perms.get(p, False))
        if o != n:
            out.append((p, n))
    return out


def _who(info: Dict[str, Any]) -> str:
    u = info.get("username")
    d = info.get("display")
    uid = info.get("user_id")
    if u:
        return f"@{u} ({uid})"
    if d:
        return f"{d} ({uid})"
    return f"user {uid}"


# ---------------------------------------------------------------------------
# คอนฟิกกลุ่ม
# ---------------------------------------------------------------------------

def snapshot_config(props: Dict[str, Any], taken_iso: str) -> Dict[str, Any]:
    """เก็บเฉพาะคุณสมบัติที่ Bot API เปิดให้เห็น — service เป็นคนเตรียม props"""
    keys = ("title", "description", "username", "has_photo", "photo_id",
            "permissions", "slow_mode_delay", "linked_chat_id",
            "join_by_request", "has_protected_content", "message_auto_delete_time")
    return {"taken_iso": taken_iso, "props": {k: props.get(k) for k in keys}}


def diff_config(old: Optional[Dict[str, Any]], new: Dict[str, Any]):
    """เทียบ snapshot คอนฟิกเก่า/ใหม่ คืน (events, integrity_status)

    old None -> ตั้ง baseline เงียบ ๆ คืน ([], NORMAL)
    """
    if not old:
        return [], INTEGRITY_NORMAL
    events: List[Dict[str, Any]] = []
    op = old.get("props", {})
    np = new.get("props", {})
    sensitive_hits = 0

    for key in np.keys():
        o, n = op.get(key), np.get(key)
        if o == n:
            continue
        if key == "permissions":
            loosened = _permissions_loosened(o or {}, n or {})
            sev = "HIGH" if loosened else "MEDIUM"
            sensitive_hits += 1
            events.append(_ev("config_permissions_changed", sev, None,
                              "สิทธิ์เริ่มต้นของสมาชิกถูกแก้" +
                              (" (ปลดล็อกให้ทำได้มากขึ้น)" if loosened else ""),
                              o, n))
        else:
            sev = "MEDIUM" if key in _SENSITIVE_CONFIG else "LOW"
            if key in _SENSITIVE_CONFIG:
                sensitive_hits += 1
            events.append(_ev(f"config_{key}_changed", sev, None,
                              _config_detail(key, o, n), o, n))

    status = _integrity_status(events, sensitive_hits)
    return events, status


def _integrity_status(events: List[Dict[str, Any]], sensitive_hits: int) -> str:
    if not events:
        return INTEGRITY_NORMAL
    if sensitive_hits >= 2:
        return INTEGRITY_REQUIRES_REVIEW
    if any(e["severity"] in ("HIGH", "CRITICAL") for e in events):
        return INTEGRITY_SUSPICIOUS
    if sensitive_hits == 1:
        return INTEGRITY_SUSPICIOUS
    return INTEGRITY_CHANGED


def _permissions_loosened(old_perms: Dict[str, Any], new_perms: Dict[str, Any]) -> bool:
    """True ถ้ามีสิทธิ์ที่เปลี่ยนจาก False->True (เปิดให้สมาชิกทำได้มากขึ้น)"""
    for k, nv in new_perms.items():
        if bool(nv) and not bool(old_perms.get(k, False)):
            return True
    return False


def _config_detail(key: str, old, new) -> str:
    label = {
        "title": "ชื่อกลุ่ม", "description": "คำอธิบายกลุ่ม", "username": "username กลุ่ม",
        "has_photo": "รูปกลุ่ม", "photo_id": "รูปกลุ่ม", "slow_mode_delay": "slow mode",
        "linked_chat_id": "แชนเนลที่ลิงก์", "join_by_request": "โหมดอนุมัติการเข้า",
        "has_protected_content": "ป้องกันการบันทึกเนื้อหา",
        "message_auto_delete_time": "ตั้งเวลาลบข้อความอัตโนมัติ",
    }.get(key, key)
    if key in ("description",) and (old or new):
        return f"{label}ถูกแก้"
    return f"{label}เปลี่ยน: {old!r} -> {new!r}"


# ---------------------------------------------------------------------------
# ลิงก์เชิญ
# ---------------------------------------------------------------------------

def diff_invites(registry: Dict[str, Any], current: List[Dict[str, Any]]
                 ) -> List[Dict[str, Any]]:
    """เทียบลิงก์เชิญที่เห็นตอนนี้กับทะเบียนที่รู้จัก คืน list เหตุการณ์

    current: list ของ {link, name, creator_id, is_revoked, is_primary}
    - ลิงก์ที่ไม่อยู่ในทะเบียน = สร้างใหม่ (อาจไม่ได้รับอนุญาต)
    - ลิงก์ในทะเบียนที่ตอนนี้ is_revoked = ถูกเพิกถอน
    หมายเหตุ: บอตเห็นเฉพาะลิงก์ที่ API เปิดให้ ไม่ครอบคลุมลิงก์ที่สร้างนอกสายตา
    """
    events: List[Dict[str, Any]] = []
    known = registry or {}
    seen = set()
    for inv in current or []:
        link = inv.get("link")
        if not link:
            continue
        seen.add(link)
        if link not in known:
            trusted = bool(inv.get("trusted"))
            events.append(_ev("invite_created",
                              "LOW" if trusted else "MEDIUM",
                              inv.get("creator_id"),
                              "พบลิงก์เชิญใหม่" + ("" if trusted else " (ยังไม่อยู่ในรายการเชื่อถือ)"),
                              None, _safe_invite(inv)))
        elif inv.get("is_revoked") and not known[link].get("is_revoked"):
            events.append(_ev("invite_revoked", "MEDIUM", inv.get("creator_id"),
                              "ลิงก์เชิญถูกเพิกถอน", _safe_invite(known[link]), _safe_invite(inv)))
    return events


def _safe_invite(inv: Dict[str, Any]) -> Dict[str, Any]:
    """ไม่คืนตัวลิงก์เต็มใน event (กันลิงก์หลุดใน log) — เก็บแค่เบาะแส"""
    link = inv.get("link") or ""
    tail = link[-6:] if len(link) > 6 else "••••"
    return {
        "link_tail": tail,
        "name": inv.get("name"),
        "creator_id": inv.get("creator_id"),
        "is_primary": bool(inv.get("is_primary")),
        "is_revoked": bool(inv.get("is_revoked")),
    }


# ---------------------------------------------------------------------------
# event helper
# ---------------------------------------------------------------------------

def _ev(kind: str, severity: str, actor_id, detail: str, before, after) -> Dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "actor_id": actor_id,
        "detail": detail,
        "before": before,
        "after": after,
    }
