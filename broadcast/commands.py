# -*- coding: utf-8 -*-
"""broadcast/commands.py — handler คำสั่ง /broadcast (เฉพาะเจ้าของบอต)

ควบคุมตัวกระจายลิงก์: ตั้งลิงก์เดียว แล้วยิงออกไปทุกปลายทางตามรอบเวลา
สิทธิ์: เฉพาะ user id ใน env BROADCAST_OWNER_IDS เท่านั้น (feature นี้แรง
พอจะทำให้บอตโดนรีพอร์ต/แบนได้ จึงล็อกไว้ที่เจ้าของบอต และดีฟอลต์ปิด)
"""

from __future__ import annotations

import asyncio
import logging
from typing import List

from . import store, core, loop

logger = logging.getLogger("modbot.broadcast.commands")

HELP = (
    "📡 *Broadcast* — ตั้งลิงก์เดียว ยิงออกไปทุกห้อง/ทุกคนอัตโนมัติตามรอบเวลา\n"
    "_(เฉพาะเจ้าของบอต · ดีฟอลต์ปิด ต้องสั่ง on เอง)_\n"
    "\n"
    "*ตั้งค่า*\n"
    "`/broadcast setlink <url>` — ลิงก์ที่จะยิง\n"
    "`/broadcast interval <เวลา>` — ยิงทุก ๆ (เช่น 1h, 30m, 1d)\n"
    "`/broadcast message <ข้อความ>` — ข้อความนำหน้าลิงก์ (ว่าง=ล้าง)\n"
    "`/broadcast template <ข้อความ>` — รูปแบบขั้นสูง ตัวแปร {url} {label}\n"
    "`/broadcast on` · `/broadcast off` — เปิด/ปิดการยิงอัตโนมัติ\n"
    "`/broadcast now` — ยิงทุกปลายทางเดี๋ยวนี้\n"
    "`/broadcast status` — ดูสถานะ + จำนวนปลายทาง + รอบถัดไป\n"
    "`/broadcast silent <on|off>` · `/broadcast preview <on|off>`\n"
    "`/broadcast delay <มิลลิวินาที>` — หน่วงระหว่างปลายทาง (กันโดน flood)\n"
    "\n"
    "*ปลายทาง*\n"
    "`/broadcast collect <on|off>` — เก็บห้อง/แชตที่บอตเห็นอัตโนมัติ\n"
    "`/broadcast target add <chat_id|@user|t.me/..>` — เพิ่มเอง\n"
    "`/broadcast target del <chat_id|@user>` — ลบ\n"
    "`/broadcast target list` — ดูปลายทางทั้งหมด\n"
    "`/broadcast target mute <chat_id> <on|off>` — พักปลายทาง\n"
    "`/broadcast target clear` — ล้างปลายทางทั้งหมด\n"
    "`/broadcast test <chat_id|@user>` — ยิงทดสอบปลายทางเดียว\n"
    "\n"
    "⚠️ Telegram: บอตส่งหา *คน* ได้เฉพาะคนที่เคยกด Start/ทักบอตก่อน และส่งเข้า "
    "*กลุ่ม/แชนเนล* ได้เฉพาะที่บอตเป็นสมาชิก — เปิด collect ไว้ ระบบจะสะสมปลายทางเอง"
)

NO_OWNER = (
    "🔒 ยังไม่ได้ตั้งเจ้าของ Broadcast\n"
    "ตั้ง env `BROADCAST_OWNER_IDS` เป็น user id ของคุณก่อน (คั่นหลายคนด้วย comma)\n"
    "เช่น `BROADCAST_OWNER_IDS=123456789` แล้วรีสตาร์ตบอต\n"
    "ดู user id ตัวเองได้จากคำสั่ง /id"
)


def _fmt_status(cfg: dict, n_targets: int, n_muted: int) -> str:
    nxt = core.seconds_until_due(cfg)
    when = ("—" if nxt < 0 else ("พร้อมยิง" if nxt == 0 else f"อีก {core.format_duration(nxt)}"))
    lines = [
        "📡 *สถานะ Broadcast*",
        f"สวิตช์: {'เปิด ▶️' if cfg.get('enabled') else 'ปิด ⏸'}",
        f"ลิงก์: {cfg.get('link') or '— (ยังไม่ตั้ง)'}",
        f"ความถี่: ทุก {core.format_duration(cfg.get('interval_sec', 0))} · รอบถัดไป: {when}",
        f"ปลายทาง: {n_targets} ({n_muted} พัก) · ยิงไปแล้ว {cfg.get('runs', 0)} รอบ",
        f"เสียง: {'ปิด' if cfg.get('silent') else 'เปิด'} · "
        f"พรีวิว: {'เปิด' if cfg.get('preview', True) else 'ปิด'} · "
        f"เก็บปลายทางอัตโนมัติ: {'เปิด' if cfg.get('collect', True) else 'ปิด'}",
    ]
    if cfg.get("message"):
        lines.append(f"message: {cfg['message']}")
    if cfg.get("template"):
        lines.append(f"template: `{cfg['template']}`")
    lines.append("")
    lines.append(f"ตัวอย่างข้อความที่จะยิง:\n{core.render(cfg) or '—'}")
    return "\n".join(lines)


async def cmd_broadcast(update, context) -> None:
    msg = update.effective_message
    user = update.effective_user
    args: List[str] = list(context.args or [])

    if args and args[0].lower() in ("help", "h", "?"):
        return await msg.reply_text(HELP, parse_mode="Markdown",
                                    disable_web_page_preview=True)

    # ด่านสิทธิ์: ต้องตั้งเจ้าของก่อน และผู้สั่งต้องเป็นเจ้าของ
    if not core.owner_configured():
        return await msg.reply_text(NO_OWNER, parse_mode="Markdown")
    if not core.is_owner(user.id):
        return await msg.reply_text("⛔ คำสั่งนี้เฉพาะเจ้าของบอตเท่านั้น")

    if not args:
        return await msg.reply_text(HELP, parse_mode="Markdown",
                                    disable_web_page_preview=True)

    sub = args[0].lower()
    rest = args[1:]
    try:
        if sub == "status":
            return await _do_status(msg)
        if sub == "setlink":
            return await _do_setlink(msg, rest)
        if sub == "interval":
            return await _do_interval(msg, rest)
        if sub == "message":
            return await _do_text_field(msg, "message", rest)
        if sub == "template":
            return await _do_text_field(msg, "template", rest)
        if sub in ("on", "off"):
            return await _do_switch(msg, sub == "on")
        if sub == "now":
            return await _do_now(context, msg)
        if sub in ("silent", "preview"):
            return await _do_toggle(msg, sub, rest)
        if sub == "collect":
            return await _do_toggle(msg, "collect", rest)
        if sub == "delay":
            return await _do_delay(msg, rest)
        if sub == "target":
            return await _do_target(context, msg, rest)
        if sub == "test":
            return await _do_test(context, msg, rest)
    except ValueError as e:
        return await msg.reply_text(f"⚠️ {e}")
    except Exception:
        logger.exception("BROADCAST COMMAND ERROR | sub=%s", sub)
        return await msg.reply_text("❌ เกิดข้อผิดพลาดภายใน ลองใหม่อีกครั้ง")

    return await msg.reply_text(
        f"ไม่รู้จักคำสั่งย่อย `{sub}` — พิมพ์ `/broadcast help`", parse_mode="Markdown")


# ---------------------------------------------------------------------------
# handlers ย่อย
# ---------------------------------------------------------------------------

async def _do_status(msg):
    db = await asyncio.to_thread(store.load)
    targets = store.list_targets(db, include_muted=True)
    muted = sum(1 for t in targets if t.get("muted"))
    return await msg.reply_text(
        _fmt_status(db["config"], len(targets), muted),
        parse_mode="Markdown", disable_web_page_preview=True)


async def _do_setlink(msg, rest):
    if not rest:
        raise ValueError("ใช้: /broadcast setlink <url>")
    url = core.normalize_link(rest[0])
    await asyncio.to_thread(store.update_config, lambda c: c.__setitem__("link", url))
    return await msg.reply_text(f"✅ ตั้งลิงก์เป็น: {url}", disable_web_page_preview=True)


async def _do_interval(msg, rest):
    if not rest:
        raise ValueError("ใช้: /broadcast interval <เวลา> (เช่น 1h, 30m, 1d)")
    secs = core.parse_duration(rest[0])
    if secs < store.MIN_INTERVAL_SEC:
        raise ValueError(f"ช่วงเวลาสั้นเกินไป ขั้นต่ำ {store.MIN_INTERVAL_SEC} วินาที")
    await asyncio.to_thread(store.update_config,
                            lambda c: c.__setitem__("interval_sec", secs))
    return await msg.reply_text(f"✅ ยิงทุก {core.format_duration(secs)}")


async def _do_text_field(msg, field, rest):
    val = " ".join(rest).replace("\\n", "\n").strip()
    await asyncio.to_thread(store.update_config, lambda c: c.__setitem__(field, val))
    if val:
        return await msg.reply_text(f"✅ ตั้ง {field} แล้ว")
    return await msg.reply_text(f"✅ ล้าง {field} แล้ว")


async def _do_switch(msg, enabled):
    # กันเปิดทั้งที่ยังไม่พร้อม
    db = await asyncio.to_thread(store.load)
    cfg = db["config"]
    if enabled:
        if not (cfg.get("link") or "").strip():
            raise ValueError("ยังไม่ได้ตั้งลิงก์ — /broadcast setlink <url> ก่อน")
        if not store.list_targets(db, include_muted=False):
            raise ValueError("ยังไม่มีปลายทาง — เปิด collect หรือ /broadcast target add ก่อน")
    await asyncio.to_thread(store.update_config,
                            lambda c: c.__setitem__("enabled", enabled))
    if enabled:
        nxt = core.format_duration(cfg.get("interval_sec", 0))
        return await msg.reply_text(f"▶️ เปิดการยิงอัตโนมัติแล้ว — ทุก {nxt}")
    return await msg.reply_text("⏸ ปิดการยิงอัตโนมัติแล้ว")


async def _do_now(context, msg):
    await msg.reply_text("📤 กำลังยิงไปทุกปลายทาง…")
    stats = await loop.send_to_all(context.bot, mark_ran=True)
    if stats.get("error") and stats["total"] == 0:
        return await msg.reply_text(f"⚠️ {stats['error']}")
    return await msg.reply_text(
        f"✅ ยิงเสร็จ — สำเร็จ {stats['sent']} / พลาด {stats['failed']} "
        f"(ทั้งหมด {stats['total']} ปลายทาง)")


async def _do_toggle(msg, field, rest):
    if not rest or rest[0].lower() not in ("on", "off"):
        raise ValueError(f"ใช้: /broadcast {field} <on|off>")
    val = rest[0].lower() == "on"
    await asyncio.to_thread(store.update_config, lambda c: c.__setitem__(field, val))
    return await msg.reply_text(f"✅ {field} = {rest[0].lower()}")


async def _do_delay(msg, rest):
    if not rest:
        raise ValueError("ใช้: /broadcast delay <มิลลิวินาที>")
    try:
        ms = int(rest[0])
    except ValueError:
        raise ValueError(f"ค่าไม่ถูกต้อง: {rest[0]!r}")
    if ms < 0 or ms > 10000:
        raise ValueError("ช่วงที่รับได้ 0–10000 ms")
    await asyncio.to_thread(store.update_config,
                            lambda c: c.__setitem__("per_send_delay_ms", ms))
    return await msg.reply_text(f"✅ หน่วงระหว่างปลายทาง {ms} ms")


async def _do_target(context, msg, rest):
    if not rest:
        raise ValueError("ใช้: /broadcast target <add|del|list|mute|clear> ...")
    action = rest[0].lower()
    tail = rest[1:]

    if action == "list":
        db = await asyncio.to_thread(store.load)
        targets = store.list_targets(db, include_muted=True)
        if not targets:
            return await msg.reply_text("ยังไม่มีปลายทาง — เปิด collect หรือ target add")
        lines = ["📍 *ปลายทางทั้งหมด*"]
        for t in targets[:100]:
            mute = " 🔇" if t.get("muted") else ""
            src = "🤖" if t.get("source") == "auto" else "✋"
            lines.append(f"{src} `{t['chat_id']}` {t.get('title','')} "
                         f"[{t.get('type','?')}]{mute}")
        if len(targets) > 100:
            lines.append(f"…และอีก {len(targets)-100} ปลายทาง")
        return await msg.reply_text("\n".join(lines), parse_mode="Markdown")

    if action == "clear":
        n = await asyncio.to_thread(store.clear_targets)
        return await msg.reply_text(f"🗑 ล้างปลายทางทั้งหมด {n} รายการแล้ว")

    if action == "add":
        if not tail:
            raise ValueError("ใช้: /broadcast target add <chat_id|@user|t.me/..>")
        return await _target_add(context, msg, tail[0])

    if action == "del":
        if not tail:
            raise ValueError("ใช้: /broadcast target del <chat_id|@user>")
        return await _target_del(context, msg, tail[0])

    if action == "mute":
        if len(tail) < 2 or tail[1].lower() not in ("on", "off"):
            raise ValueError("ใช้: /broadcast target mute <chat_id> <on|off>")
        ref = core.parse_target(tail[0])
        if ref["kind"] != "id":
            raise ValueError("mute ใช้กับ chat id ตัวเลขเท่านั้น (ดูจาก target list)")
        t = await asyncio.to_thread(store.set_muted, ref["ref"], tail[1].lower() == "on")
        if not t:
            return await msg.reply_text("ไม่พบปลายทางนั้นในทะเบียน")
        return await msg.reply_text(
            f"✅ {'พัก' if t['muted'] else 'เลิกพัก'}ปลายทาง {ref['ref']} แล้ว")

    raise ValueError(f"ไม่รู้จัก target {action!r}")


async def _resolve_chat(context, token: str):
    """พยายาม resolve ปลายทางเป็น (chat_id, title, type) ผ่าน bot.get_chat
    คืน None ถ้า resolve ไม่ได้"""
    ref = core.parse_target(token)
    try:
        chat = await context.bot.get_chat(ref["ref"])
        title = chat.title or chat.username or (chat.full_name if hasattr(chat, "full_name") else "")
        return int(chat.id), title or str(chat.id), str(getattr(chat, "type", "") or "")
    except Exception as e:
        # ตัวเลขล้วน: ยอมเก็บดิบ ๆ ได้ (บอตอาจส่งได้แม้ get_chat ไม่ผ่าน)
        if ref["kind"] == "id":
            return int(ref["ref"]), "", ""
        raise ValueError(f"resolve ปลายทางไม่ได้: {token!r} ({e})")


async def _target_add(context, msg, token):
    chat_id, title, ctype = await _resolve_chat(context, token)
    rec = await asyncio.to_thread(store.add_target, chat_id, title, ctype, "manual")
    return await msg.reply_text(
        f"✅ เพิ่มปลายทาง `{rec['chat_id']}` {rec.get('title','')}", parse_mode="Markdown")


async def _target_del(context, msg, token):
    ref = core.parse_target(token)
    if ref["kind"] == "id":
        chat_id = ref["ref"]
    else:
        chat_id, _, _ = await _resolve_chat(context, token)
    ok = await asyncio.to_thread(store.del_target, chat_id)
    return await msg.reply_text(
        f"🗑 ลบปลายทาง {chat_id} แล้ว" if ok else f"ไม่พบปลายทาง {chat_id}")


async def _do_test(context, msg, rest):
    if not rest:
        raise ValueError("ใช้: /broadcast test <chat_id|@user>")
    chat_id, title, _ = await _resolve_chat(context, rest[0])
    cfg = await asyncio.to_thread(store.get_config)
    text = core.render(cfg)
    if not text.strip():
        raise ValueError("ยังไม่ได้ตั้งลิงก์")
    await context.bot.send_message(
        chat_id=chat_id, text=text,
        disable_notification=bool(cfg.get("silent", False)),
        disable_web_page_preview=not bool(cfg.get("preview", True)))
    return await msg.reply_text(f"📤 ยิงทดสอบไปที่ {chat_id} {title} แล้ว")
