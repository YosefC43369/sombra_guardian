# -*- coding: utf-8 -*-
"""group_security_intelligence/commands.py — คำสั่ง /security_* + แดชบอร์ด

ทุกคำสั่งตรวจสิทธิ์ "แอดมินจริงของกลุ่ม" ผ่าน is_admin ของ app.py (ไม่เชื่อ id ที่ผู้ใช้พิมพ์)
อ่านข้อมูลผ่าน store (wrap to_thread) และเรียก service สำหรับงาน async (poll/backup/recovery)

คำสั่ง:
  /group_security      ภาพรวมสถานะความปลอดภัยกลุ่ม (แดชบอร์ด)
  /security_audit      audit ล่าสุด (ค่าถูก redact)
  /security_admins     ความครบถ้วนของโครงแอดมิน
  /security_integrity  ตรวจความครบถ้วนคอนฟิกกลุ่ม (poll สด)
  /security_invites    สถานะลิงก์เชิญ
  /security_secrets    แจ้งเตือนข้อมูลลับ (redact)
  /security_incidents  incident ที่ correlate แล้ว
  /security_backup     สร้าง backup การตั้งค่า
  /security_recovery   จุดกู้คืน + diff + apply (ต้องยืนยัน)
  /security_report     รายงานความปลอดภัยรวม
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, List

from . import store, service, monitor

logger = logging.getLogger("modbot.gsi.commands")

IsAdmin = Callable[..., Awaitable[bool]]

_SEV_EMOJI = {"INFO": "ℹ️", "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
_INTEGRITY_EMOJI = {
    monitor.INTEGRITY_NORMAL: "🟢", monitor.INTEGRITY_CHANGED: "🟡",
    monitor.INTEGRITY_SUSPICIOUS: "🟠", monitor.INTEGRITY_REQUIRES_REVIEW: "🔴",
}


def _is_group(update) -> bool:
    ct = getattr(update.effective_chat, "type", "")
    return str(ct) in ("group", "supergroup") or "group" in str(ct)


async def _guard(update, context, is_admin) -> bool:
    """ต้องอยู่ในกลุ่ม + เป็นแอดมินจริง"""
    if not _is_group(update):
        await update.effective_message.reply_text("ใช้คำสั่งนี้ได้เฉพาะในกลุ่ม")
        return False
    if not await is_admin(update, context):
        await update.effective_message.reply_text("⛔ เฉพาะแอดมินของกลุ่มเท่านั้น")
        return False
    return True


# ---------------------------------------------------------------------------
# /group_security — แดชบอร์ด
# ---------------------------------------------------------------------------

async def cmd_group_security(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))

    # ไม่มี baseline -> สร้างให้เลย (เงียบ)
    if node.get("admins") is None and node.get("config") is None:
        await update.effective_message.reply_text("⏳ กำลังตั้งค่าพื้นฐานความปลอดภัยครั้งแรก…")
        await service.ensure_baseline(context.bot, chat_id)
        node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))

    integ = (node.get("invites", {}) or {}).get("last_status") or monitor.INTEGRITY_NORMAL
    admins = node.get("admins") or {}
    n_admins = len(admins.get("admins", {})) if admins else 0
    open_inc = [i for i in node["incidents"] if i.get("status") == "OPEN"]
    secrets_24 = _count_recent(node["secret_findings"], 86400)
    se_24 = _count_recent(node["se_findings"], 86400)
    last_backup = node["backups"][-1]["created_iso"] if node["backups"] else "— ยังไม่มี"

    lines = [
        "🛡 *ภาพรวมความปลอดภัยกลุ่ม*",
        f"สถานะระบบ: {'เปิด ✅' if node['policy'].get('enabled', True) else 'ปิด ⛔'}",
        f"โครงแอดมิน: {n_admins} คน (baseline {'มี' if admins else 'ยังไม่มี'})",
        f"ความครบถ้วนคอนฟิก: {_INTEGRITY_EMOJI.get(integ,'⚪')} {integ}",
        f"ลิงก์เชิญในทะเบียน: {len(node['invites'].get('registry', {}))}",
        f"ข้อมูลลับที่พบ (24ชม.): {secrets_24}",
        f"ข้อความหลอกลวง (24ชม.): {se_24}",
        f"incident ที่เปิดอยู่: {len(open_inc)}",
        f"backup ล่าสุด: {last_backup}",
        "",
        "ดูรายละเอียด: /security\\_admins /security\\_integrity /security\\_invites",
        "/security\\_secrets /security\\_incidents /security\\_audit /security\\_report",
    ]
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


# ---------------------------------------------------------------------------
# /security_audit
# ---------------------------------------------------------------------------

async def cmd_security_audit(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    rows = store.recent(node["audit_index"], 15)
    if not rows:
        return await update.effective_message.reply_text("ยังไม่มีบันทึก audit")
    verify = await asyncio.to_thread(service.verify_audit, chat_id)
    head = "🧾 *Audit ล่าสุด*"
    if verify.get("available"):
        head += f" _(ledger: {verify['entries']} รายการ, root {verify['merkle_root'][:12]}…)_"
    lines = [head]
    for r in rows:
        emo = _SEV_EMOJI.get(r.get("severity"), "•")
        ts = (r.get("ts") or "")[:19].replace("T", " ")
        lines.append(f"{emo} `{ts}` [{r.get('category')}] {r.get('detail','')[:140]}")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown",
                                               disable_web_page_preview=True)


# ---------------------------------------------------------------------------
# /security_admins
# ---------------------------------------------------------------------------

async def cmd_security_admins(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    # poll สดเพื่อให้ snapshot ล่าสุด
    await service.poll_chat(context.bot, chat_id)
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    snap = node.get("admins")
    if not snap:
        return await update.effective_message.reply_text("อ่านรายชื่อแอดมินไม่ได้ (บอตเป็นแอดมินหรือยัง?)")
    admins = snap.get("admins", {})
    lines = [f"👑 *โครงแอดมิน* ({len(admins)} คน) · snapshot {snap.get('taken_iso','')[:19].replace('T',' ')}"]
    for info in list(admins.values())[:30]:
        perms = info.get("perms", {})
        hot = [p for p in ("can_promote_members", "can_restrict_members",
                           "can_delete_messages", "can_change_info") if perms.get(p)]
        tag = "⭐" if info.get("status") == "creator" else "•"
        lines.append(f"{tag} {_who(info)} [{info.get('status')}] "
                     f"สิทธิ์สำคัญ: {', '.join(hot) if hot else '—'}")
    admin_events = [a for a in node["audit_index"] if a.get("category") == "admin"]
    if admin_events:
        lines.append("")
        lines.append("*การเปลี่ยนแปลงล่าสุด:*")
        for r in store.recent(admin_events, 5):
            lines.append(f"{_SEV_EMOJI.get(r.get('severity'),'•')} {r.get('detail','')[:120]}")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


# ---------------------------------------------------------------------------
# /security_integrity
# ---------------------------------------------------------------------------

async def cmd_security_integrity(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    summary = await service.poll_chat(context.bot, chat_id)
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    status = (node["invites"] or {}).get("last_status") or monitor.INTEGRITY_NORMAL
    cfg = node.get("config") or {}
    props = cfg.get("props", {})
    lines = [
        f"🧩 *ความครบถ้วนของคอนฟิกกลุ่ม*: {_INTEGRITY_EMOJI.get(status,'⚪')} {status}",
        f"snapshot ล่าสุด: {cfg.get('taken_iso','')[:19].replace('T',' ') or '—'}",
        f"ชื่อ: {props.get('title') or '—'}",
        f"username: {('@'+props['username']) if props.get('username') else '— (ไม่มี)'}",
        f"รูปกลุ่ม: {'มี' if props.get('has_photo') else 'ไม่มี'} · "
        f"slow mode: {props.get('slow_mode_delay') or 'ปิด'} · "
        f"อนุมัติการเข้า: {props.get('join_by_request')}",
    ]
    cfg_events = [a for a in node["audit_index"] if a.get("category") == "config"]
    if cfg_events:
        lines.append("")
        lines.append("*การเปลี่ยนแปลงล่าสุด:*")
        for r in store.recent(cfg_events, 6):
            lines.append(f"{_SEV_EMOJI.get(r.get('severity'),'•')} {r.get('detail','')[:120]}")
    if status != monitor.INTEGRITY_NORMAL:
        lines.append("")
        lines.append("_หมายเหตุ: Bot API ไม่แจ้งเตือนคอนฟิกแบบ real-time ทุกอย่าง "
                     "การตรวจพบอาจช้ากว่าการเปลี่ยนจริงตามรอบ snapshot_")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


# ---------------------------------------------------------------------------
# /security_invites
# ---------------------------------------------------------------------------

async def cmd_security_invites(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    reg = node["invites"].get("registry", {})
    hist = node["invites"].get("history", [])
    lines = [f"🔗 *ความปลอดภัยลิงก์เชิญ* · ในทะเบียน {len(reg)} ลิงก์"]
    trusted = sum(1 for v in reg.values() if v.get("trusted"))
    revoked = sum(1 for v in reg.values() if v.get("is_revoked"))
    lines.append(f"เชื่อถือ: {trusted} · เพิกถอนแล้ว: {revoked} · ไม่อยู่รายการเชื่อถือ: {len(reg)-trusted}")
    for v in list(reg.values())[-10:]:
        tail = (v.get("link") or "")[-6:]
        flag = "✅" if v.get("trusted") else "⚠️"
        state = "เพิกถอน" if v.get("is_revoked") else "ใช้ได้"
        lines.append(f"{flag} …{tail} [{state}] ผู้สร้าง: {v.get('creator_id') or '—'}")
    lines.append("")
    lines.append("_บอตเห็นเฉพาะลิงก์ที่ Bot API เปิดให้ (เช่นที่ติดมากับการเข้ากลุ่ม "
                 "หรือที่บันทึกเอง) — ไม่ครอบคลุมลิงก์ที่สร้างนอกสายตาบอต_")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown",
                                               disable_web_page_preview=True)


# ---------------------------------------------------------------------------
# /security_secrets
# ---------------------------------------------------------------------------

async def cmd_security_secrets(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    rows = store.recent(node["secret_findings"], 15)
    if not rows:
        return await update.effective_message.reply_text("✅ ไม่พบข้อมูลลับที่หลุดในบันทึกล่าสุด")
    lines = ["🔐 *แจ้งเตือนข้อมูลลับ* (แสดงแบบปิดบังค่าจริงเสมอ)"]
    for r in rows:
        emo = _SEV_EMOJI.get(r.get("severity"), "•")
        ts = (r.get("ts") or "")[:19].replace("T", " ")
        lines.append(f"{emo} `{ts}` {r.get('type')} = `{r.get('redacted')}` "
                     f"จาก {('@'+r['username']) if r.get('username') else r.get('user_id')}")
    lines.append("")
    lines.append("_ระบบไม่เก็บ/ไม่ส่งต่อค่าจริงของข้อมูลลับ — แนะนำให้หมุน/เพิกถอนคีย์ที่หลุด_")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown",
                                               disable_web_page_preview=True)


# ---------------------------------------------------------------------------
# /security_incidents
# ---------------------------------------------------------------------------

async def cmd_security_incidents(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    rows = store.recent(node["incidents"], 10)
    if not rows:
        return await update.effective_message.reply_text("✅ ไม่มี incident ที่ correlate ได้")
    lines = ["🚨 *Security Incidents* (เหตุการณ์ที่อาจเชื่อมโยงกัน)"]
    for r in rows:
        emo = _SEV_EMOJI.get(r.get("level"), "•")
        ts = (r.get("created_iso") or "")[:19].replace("T", " ")
        lines.append(f"{emo} #{r.get('id')} [{r.get('level')}] score {r.get('score')} · "
                     f"{r.get('event_count')} เหตุการณ์ · {ts} · {r.get('status')}")
        lines.append(f"    {r.get('explanation','')[:220]}")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


# ---------------------------------------------------------------------------
# /security_backup
# ---------------------------------------------------------------------------

async def cmd_security_backup(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    await update.effective_message.reply_text("⏳ กำลังสร้าง backup การตั้งค่า…")
    try:
        rec = await service.create_backup(context.bot, chat_id,
                                          actor_id=update.effective_user.id)
    except Exception:
        logger.exception("GSI backup command error | chat=%s", chat_id)
        return await update.effective_message.reply_text("❌ สร้าง backup ไม่สำเร็จ")
    n_admin = len(rec["admins"].get("admins", {}))
    await update.effective_message.reply_text(
        f"✅ สร้าง backup *#{rec['id']}* แล้ว ({rec['created_iso'][:19].replace('T',' ')})\n"
        f"เก็บ: โครงแอดมิน {n_admin} คน, คอนฟิกกลุ่ม, นโยบายความปลอดภัย, meta ลิงก์เชิญ\n"
        f"ดูจุดกู้คืน: /security\\_recovery", parse_mode="Markdown")


# ---------------------------------------------------------------------------
# /security_recovery
# ---------------------------------------------------------------------------

async def cmd_security_recovery(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    args = list(context.args or [])

    if not args:
        backups = await asyncio.to_thread(service.list_backups, chat_id)
        if not backups:
            return await update.effective_message.reply_text(
                "ยังไม่มี backup — สร้างด้วย /security\\_backup", parse_mode="Markdown")
        lines = ["💾 *จุดกู้คืนที่มี*"]
        for b in backups[-10:]:
            lines.append(f"#{b['id']} · {b['created_iso'][:19].replace('T',' ')} · "
                         f"แอดมิน {len(b['admins'].get('admins',{}))} คน")
        lines.append("")
        lines.append("ดูความต่าง: `/security_recovery diff <id>`")
        lines.append("กู้คืน: `/security_recovery apply <id> <title|description|permissions|all> confirm`")
        return await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

    sub = args[0].lower()
    if sub == "diff":
        if len(args) < 2 or not args[1].isdigit():
            return await update.effective_message.reply_text("ใช้: `/security_recovery diff <id>`",
                                                             parse_mode="Markdown")
        return await _recovery_diff(update, context, chat_id, int(args[1]))

    if sub == "apply":
        return await _recovery_apply(update, context, chat_id, args[1:])

    return await update.effective_message.reply_text(
        "คำสั่งย่อยไม่ถูกต้อง — `diff <id>` หรือ `apply <id> <keys> confirm`",
        parse_mode="Markdown")


async def _recovery_diff(update, context, chat_id, backup_id):
    plan = await service.recovery_diff(context.bot, chat_id, backup_id)
    if not plan.get("ok"):
        return await update.effective_message.reply_text(f"⚠️ {plan.get('reason')}")
    lines = [f"🔍 *ความต่างจาก backup #{backup_id}*"]
    if not plan["changes"] and not plan["unrestorable"]:
        lines.append("ไม่มีความต่างในคุณสมบัติที่ตรวจ — คอนฟิกตรงกับ backup")
    for c in plan["changes"]:
        lines.append(f"• `{c['key']}` ปัจจุบัน: {str(c['current'])[:60]!r} → backup: {str(c['backup'])[:60]!r} (กู้คืนได้)")
    for c in plan["unrestorable"]:
        lines.append(f"• `{c['key']}` ต่างกัน แต่ *กู้คืนผ่าน Bot API ไม่ได้*")
    if plan["changes"]:
        keys = "|".join(c["key"] for c in plan["changes"])
        lines.append("")
        lines.append(f"กู้คืน: `/security_recovery apply {backup_id} {keys} confirm`")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


async def _recovery_apply(update, context, chat_id, rest):
    if len(rest) < 2 or not rest[0].isdigit():
        return await update.effective_message.reply_text(
            "ใช้: `/security_recovery apply <id> <title|description|permissions|all> confirm`",
            parse_mode="Markdown")
    backup_id = int(rest[0])
    if rest[-1].lower() != "confirm":
        return await update.effective_message.reply_text(
            "⚠️ การกู้คืนจะ *เปลี่ยนการตั้งค่ากลุ่มจริง* — เติม `confirm` ท้ายคำสั่งเพื่อยืนยัน\n"
            f"`/security_recovery apply {backup_id} {' '.join(rest[1:-1]) or 'all'} confirm`",
            parse_mode="Markdown")
    key_args = [a.lower() for a in rest[1:-1]]
    keys = list(service.RESTORABLE) if ("all" in key_args or not key_args) else \
        [k for k in key_args if k in service.RESTORABLE]
    if not keys:
        return await update.effective_message.reply_text(
            f"ไม่มีคุณสมบัติที่กู้คืนได้ที่ระบุ (กู้คืนได้: {', '.join(service.RESTORABLE)})")
    await update.effective_message.reply_text(f"⏳ กำลังกู้คืน {', '.join(keys)} จาก backup #{backup_id}…")
    res = await service.apply_recovery(context.bot, chat_id, backup_id, keys,
                                       actor_id=update.effective_user.id)
    if not res.get("ok"):
        return await update.effective_message.reply_text(f"⚠️ {res.get('reason')}")
    msg = f"✅ กู้คืนสำเร็จ: {', '.join(res['restored']) or '—'}"
    if res.get("failed"):
        msg += "\nไม่สำเร็จ: " + "; ".join(f"{f['key']} ({f['reason']})" for f in res["failed"])
    await update.effective_message.reply_text(msg)


# ---------------------------------------------------------------------------
# /security_report
# ---------------------------------------------------------------------------

async def cmd_security_report(update, context, is_admin: IsAdmin) -> None:
    if not await _guard(update, context, is_admin):
        return
    chat_id = update.effective_chat.id
    await service.poll_chat(context.bot, chat_id)
    node = await asyncio.to_thread(lambda: store.get_chat(store.load(), chat_id))
    integ = (node["invites"] or {}).get("last_status") or monitor.INTEGRITY_NORMAL
    verify = await asyncio.to_thread(service.verify_audit, chat_id)
    open_inc = [i for i in node["incidents"] if i.get("status") == "OPEN"]

    lines = [
        "📑 *รายงานความปลอดภัยกลุ่ม (ฉบับเต็ม)*",
        "",
        f"1) แอดมิน: {len((node.get('admins') or {}).get('admins', {}))} คน · "
        f"เหตุการณ์แอดมินสะสม {sum(1 for a in node['audit_index'] if a.get('category')=='admin')}",
        f"2) ความครบถ้วนคอนฟิก: {_INTEGRITY_EMOJI.get(integ,'⚪')} {integ}",
        f"3) ลิงก์เชิญในทะเบียน: {len(node['invites'].get('registry', {}))}",
        f"4) ข้อมูลลับที่พบทั้งหมด: {len(node['secret_findings'])} "
        f"(24ชม. {_count_recent(node['secret_findings'],86400)})",
        f"5) ข้อความหลอกลวงที่พบ: {len(node['se_findings'])} "
        f"(24ชม. {_count_recent(node['se_findings'],86400)})",
        f"6) incident: ทั้งหมด {len(node['incidents'])} · เปิดอยู่ {len(open_inc)}",
        f"7) backup: {len(node['backups'])} จุด",
        f"8) audit trail: {len(node['audit_index'])} รายการใน index"
        + (f" · tamper-evident ledger {verify['entries']} รายการ (root {verify['merkle_root'][:10]}…)"
           if verify.get("available") else " · ledger ไม่พร้อม"),
        "",
        "*ข้อจำกัด Bot API:* ตรวจคอนฟิกตามรอบ snapshot (ไม่ real-time ทุกอย่าง), "
        "เห็นเฉพาะลิงก์เชิญที่ API เปิดให้, กู้คืนได้เฉพาะ title/description/permissions, "
        "ไม่เห็น session/อุปกรณ์/IP ของผู้ใช้",
    ]
    if open_inc:
        lines.append("")
        lines.append("*incident ที่ต้องดู:*")
        for r in open_inc[-3:]:
            lines.append(f"{_SEV_EMOJI.get(r.get('level'),'•')} #{r['id']} [{r['level']}] {r['explanation'][:160]}")
    await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------

def _who(info) -> str:
    u = info.get("username")
    d = info.get("display")
    uid = info.get("user_id")
    if u:
        return f"@{u}"
    return f"{d or 'user'} ({uid})"


def _count_recent(rows, seconds) -> int:
    cutoff = store.utcnow().timestamp() - seconds
    n = 0
    for r in rows:
        ts = store.parse_iso(r.get("ts"))
        if ts and ts.timestamp() >= cutoff:
            n += 1
    return n
