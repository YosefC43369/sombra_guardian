# -*- coding: utf-8 -*-
"""autolink/commands.py — ตัว handler คำสั่ง /autolink สำหรับ Telegram

จุดเชื่อมเดียวที่ app.py ต้องเรียก: ``cmd_autolink(update, context, is_admin)``
(is_admin คือฟังก์ชัน async เดิมของ app.py — ส่งเข้ามาเพื่อไม่ผูก import วน)

ทุกการแตะดิสก์ห่อด้วย asyncio.to_thread ตามแนว reputation.py เพื่อไม่บล็อก event loop
ทุกคำสั่งที่ "เปลี่ยนสถานะ" ต้องเป็นแอดมินของห้องเท่านั้น
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, List

from . import store, engine, loop

logger = logging.getLogger("modbot.autolink.commands")

IsAdmin = Callable[..., Awaitable[bool]]


# ---------------------------------------------------------------------------
# ข้อความช่วยเหลือ
# ---------------------------------------------------------------------------

HELP = (
    "🔗 *AutoLink* — ส่งลิงก์เว็บอัตโนมัติแบบตลอดเวลา\n"
    "\n"
    "*สร้าง/จัดการ* (เฉพาะแอดมิน)\n"
    "`/autolink add <ช่วงเวลา> <url> [url2 ...]` — สร้างแคมเปญใหม่\n"
    "`/autolink list` — ดูแคมเปญทั้งหมดในห้องนี้\n"
    "`/autolink show <id>` — ดูรายละเอียด + รายการลิงก์\n"
    "`/autolink addurl <id> <url ...>` — เพิ่มลิงก์\n"
    "`/autolink delurl <id> <ลำดับ>` — ลบลิงก์ตามลำดับ\n"
    "`/autolink interval <id> <ช่วงเวลา>` — เปลี่ยนความถี่\n"
    "`/autolink mode <id> <sequential|random|single>` — โหมดวนลิงก์\n"
    "`/autolink title <id> <ชื่อ>` — ตั้งชื่อแคมเปญ\n"
    "`/autolink template <id> <ข้อความ>` — รูปแบบข้อความ (ว่าง=ล้าง)\n"
    "`/autolink silent <id> <on|off>` — ปิด/เปิดเสียงแจ้งเตือน\n"
    "`/autolink preview <id> <on|off>` — แสดง/ซ่อนพรีวิวลิงก์\n"
    "`/autolink jitter <id> <ช่วงเวลา>` — สุ่มหน่วงกันดูเป็นบอท\n"
    "`/autolink pause <id>` · `/autolink resume <id>` — หยุด/เล่นต่อ\n"
    "`/autolink now <id>` — ส่งเดี๋ยวนี้ทันที\n"
    "`/autolink remove <id>` — ลบแคมเปญ\n"
    "\n"
    "*ช่วงเวลา*: `45s` `30m` `2h` `1d` (เลขเปล่า = นาที)\n"
    "*template* ใช้ตัวแปร: `{url} {label} {n} {total} {title}`\n"
    "\n"
    "ตัวอย่าง:\n"
    "`/autolink add 2h https://example.com https://github.com`\n"
    "`/autolink template 1 📣 {title}: {label}\\n{url}  ({n}/{total})`"
)


def _fmt_campaign_line(c: dict) -> str:
    state = "▶️" if c.get("enabled", True) else "⏸"
    nxt = engine.seconds_until_due(c)
    when = "—" if nxt < 0 else ("พร้อมส่ง" if nxt == 0 else f"อีก {engine.format_duration(nxt)}")
    return (f"{state} *#{c.get('id')}* {c.get('title','')} · "
            f"{len(c.get('links') or [])} ลิงก์ · ทุก {engine.format_duration(c.get('interval_sec',0))} · "
            f"[{c.get('mode','sequential')}] · ส่งแล้ว {c.get('runs',0)} ครั้ง · {when}")


def _fmt_detail(c: dict) -> str:
    lines = [
        f"🔗 *แคมเปญ #{c.get('id')}* — {c.get('title','')}",
        f"สถานะ: {'เปิด ▶️' if c.get('enabled', True) else 'หยุด ⏸'}",
        f"ความถี่: ทุก {engine.format_duration(c.get('interval_sec',0))}",
        f"โหมด: {c.get('mode','sequential')}",
        f"เสียงแจ้งเตือน: {'ปิด' if c.get('silent') else 'เปิด'} · "
        f"พรีวิว: {'เปิด' if c.get('preview', True) else 'ปิด'} · "
        f"jitter: {engine.format_duration(c.get('jitter_sec',0))}",
        f"ส่งไปแล้ว: {c.get('runs',0)} ครั้ง · ล่าสุด: {c.get('last_run_iso') or 'ยังไม่เคย'}",
    ]
    if c.get("template"):
        lines.append(f"template: `{c['template']}`")
    lines.append("")
    lines.append("*ลิงก์:*")
    links = c.get("links") or []
    if not links:
        lines.append("_(ยังไม่มีลิงก์)_")
    else:
        cur = int(c.get("cursor", 0)) % len(links)
        for i, lk in enumerate(links):
            mark = "➡️" if i == cur and c.get("mode") == "sequential" else "  "
            label = lk.get("label") or ""
            suffix = f" ({label})" if label else ""
            lines.append(f"{mark} {i+1}. {lk.get('url')}{suffix}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# dispatcher
# ---------------------------------------------------------------------------

async def cmd_autolink(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    chat_id = update.effective_chat.id
    args: List[str] = list(context.args or [])

    if not args or args[0].lower() in ("help", "h", "?"):
        return await msg.reply_text(HELP, parse_mode="Markdown")

    sub = args[0].lower()
    rest = args[1:]

    # คำสั่งอ่านอย่างเดียว — ใครก็ดูได้
    if sub == "list":
        return await _do_list(update, msg, chat_id)
    if sub in ("show", "links", "info"):
        return await _do_show(msg, chat_id, rest)

    # ตั้งแต่นี้คือคำสั่งแก้สถานะ -> ต้องเป็นแอดมิน
    if not await is_admin(update, context):
        return await msg.reply_text("⛔ เฉพาะแอดมินของห้องเท่านั้นที่ตั้งค่า AutoLink ได้")

    try:
        if sub == "add":
            return await _do_add(msg, chat_id, rest)
        if sub == "addurl":
            return await _do_addurl(msg, chat_id, rest)
        if sub == "delurl":
            return await _do_delurl(msg, chat_id, rest)
        if sub == "interval":
            return await _do_interval(msg, chat_id, rest)
        if sub == "mode":
            return await _do_mode(msg, chat_id, rest)
        if sub == "title":
            return await _do_title(msg, chat_id, rest)
        if sub == "template":
            return await _do_template(msg, chat_id, rest)
        if sub in ("silent", "preview"):
            return await _do_toggle(msg, chat_id, sub, rest)
        if sub == "jitter":
            return await _do_jitter(msg, chat_id, rest)
        if sub in ("pause", "resume"):
            return await _do_pause_resume(msg, chat_id, sub, rest)
        if sub in ("remove", "delete", "del", "rm"):
            return await _do_remove(msg, chat_id, rest)
        if sub == "now":
            return await _do_now(context, msg, chat_id, rest)
    except ValueError as e:
        return await msg.reply_text(f"⚠️ {e}")
    except Exception:
        logger.exception("AUTOLINK COMMAND ERROR | sub=%s", sub)
        return await msg.reply_text("❌ เกิดข้อผิดพลาดภายใน ลองใหม่อีกครั้ง")

    return await msg.reply_text(
        f"ไม่รู้จักคำสั่งย่อย `{sub}` — พิมพ์ `/autolink help`", parse_mode="Markdown")


# ---------------------------------------------------------------------------
# handlers ย่อย
# ---------------------------------------------------------------------------

def _need_id(rest: List[str]) -> int:
    if not rest:
        raise ValueError("ต้องระบุเลขแคมเปญ (ดูได้จาก /autolink list)")
    try:
        return int(rest[0])
    except ValueError:
        raise ValueError(f"เลขแคมเปญไม่ถูกต้อง: {rest[0]!r}")


async def _do_list(update, msg, chat_id):
    camps = await asyncio.to_thread(lambda: store.list_campaigns(store.load(), chat_id))
    if not camps:
        return await msg.reply_text(
            "ยังไม่มีแคมเปญในห้องนี้ — สร้างด้วย\n"
            "`/autolink add 1h https://example.com`", parse_mode="Markdown")
    body = "\n".join(_fmt_campaign_line(c) for c in camps)
    return await msg.reply_text("📋 *แคมเปญ AutoLink ในห้องนี้*\n" + body,
                                parse_mode="Markdown", disable_web_page_preview=True)


async def _do_show(msg, chat_id, rest):
    cid = _need_id(rest)
    camp = await asyncio.to_thread(lambda: store.get_campaign(store.load(), chat_id, cid))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(_fmt_detail(camp), parse_mode="Markdown",
                                disable_web_page_preview=True)


async def _do_add(msg, chat_id, rest):
    if len(rest) < 2:
        raise ValueError("ใช้: /autolink add <ช่วงเวลา> <url> [url2 ...]")
    interval = engine.parse_duration(rest[0])
    links = [engine.normalize_link(u) for u in rest[1:]]
    camp = await asyncio.to_thread(
        store.create_campaign, chat_id, links, interval, "")
    return await msg.reply_text(
        f"✅ สร้างแคมเปญ *#{camp['id']}* แล้ว — {len(links)} ลิงก์ ทุก "
        f"{engine.format_duration(interval)}\nลิงก์แรกจะถูกส่งภายในไม่กี่วินาที",
        parse_mode="Markdown")


async def _do_addurl(msg, chat_id, rest):
    cid = _need_id(rest)
    if len(rest) < 2:
        raise ValueError("ใช้: /autolink addurl <id> <url ...>")
    new_links = [engine.normalize_link(u) for u in rest[1:]]

    def _mut(c):
        links = c.setdefault("links", [])
        if len(links) + len(new_links) > store.MAX_LINKS_PER_CAMPAIGN:
            raise ValueError(f"เกินเพดานลิงก์ ({store.MAX_LINKS_PER_CAMPAIGN})")
        links.extend(new_links)

    camp = await asyncio.to_thread(store.update_campaign, chat_id, cid, _mut)
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(
        f"✅ เพิ่ม {len(new_links)} ลิงก์เข้าแคมเปญ #{cid} (รวม {len(camp['links'])})")


async def _do_delurl(msg, chat_id, rest):
    cid = _need_id(rest)
    if len(rest) < 2:
        raise ValueError("ใช้: /autolink delurl <id> <ลำดับ>")
    try:
        pos = int(rest[1])
    except ValueError:
        raise ValueError(f"ลำดับไม่ถูกต้อง: {rest[1]!r}")

    removed = {}

    def _mut(c):
        links = c.get("links", [])
        if pos < 1 or pos > len(links):
            raise ValueError(f"ลำดับ {pos} เกินช่วง (มี {len(links)} ลิงก์)")
        removed["url"] = links.pop(pos - 1).get("url")
        # กัน cursor หลุดช่วง
        if links:
            c["cursor"] = int(c.get("cursor", 0)) % len(links)
        else:
            c["cursor"] = 0

    camp = await asyncio.to_thread(store.update_campaign, chat_id, cid, _mut)
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(f"🗑 ลบลิงก์แล้ว: {removed.get('url')}")


async def _do_interval(msg, chat_id, rest):
    cid = _need_id(rest)
    if len(rest) < 2:
        raise ValueError("ใช้: /autolink interval <id> <ช่วงเวลา>")
    secs = engine.parse_duration(rest[1])
    if secs < store.MIN_INTERVAL_SEC:
        raise ValueError(f"ช่วงเวลาสั้นเกินไป ขั้นต่ำ {store.MIN_INTERVAL_SEC} วินาที")

    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__("interval_sec", secs))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(
        f"✅ แคมเปญ #{cid} เปลี่ยนเป็นส่งทุก {engine.format_duration(secs)}")


async def _do_mode(msg, chat_id, rest):
    cid = _need_id(rest)
    if len(rest) < 2 or rest[1].lower() not in store.VALID_MODES:
        raise ValueError(f"โหมดต้องเป็นหนึ่งใน: {', '.join(store.VALID_MODES)}")
    mode = rest[1].lower()
    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__("mode", mode))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(f"✅ แคมเปญ #{cid} ใช้โหมด [{mode}]")


async def _do_title(msg, chat_id, rest):
    cid = _need_id(rest)
    title = " ".join(rest[1:]).strip()
    if not title:
        raise ValueError("ใช้: /autolink title <id> <ชื่อ>")
    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__("title", title[:120]))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(f"✅ ตั้งชื่อแคมเปญ #{cid} เป็น “{title[:120]}”")


async def _do_template(msg, chat_id, rest):
    cid = _need_id(rest)
    # รองรับ \n ที่ผู้ใช้พิมพ์ให้กลายเป็นขึ้นบรรทัดใหม่จริง
    tmpl = " ".join(rest[1:]).replace("\\n", "\n").strip()
    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__("template", tmpl))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    if tmpl:
        return await msg.reply_text(f"✅ ตั้ง template ของแคมเปญ #{cid} แล้ว")
    return await msg.reply_text(f"✅ ล้าง template ของแคมเปญ #{cid} (กลับเป็นค่าเริ่มต้น)")


async def _do_toggle(msg, chat_id, field, rest):
    cid = _need_id(rest)
    if len(rest) < 2 or rest[1].lower() not in ("on", "off"):
        raise ValueError(f"ใช้: /autolink {field} <id> <on|off>")
    val = rest[1].lower() == "on"
    # silent: on = ปิดเสียง (silent=True) ; preview: on = เปิดพรีวิว
    stored = val if field == "preview" else val

    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__(field, stored))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(f"✅ แคมเปญ #{cid}: {field} = {rest[1].lower()}")


async def _do_jitter(msg, chat_id, rest):
    cid = _need_id(rest)
    if len(rest) < 2:
        raise ValueError("ใช้: /autolink jitter <id> <ช่วงเวลา>  (0 = ปิด)")
    secs = engine.parse_duration(rest[1])
    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__("jitter_sec", secs))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(
        f"✅ แคมเปญ #{cid} สุ่มหน่วงเพิ่ม 0–{engine.format_duration(secs)} ต่อครั้ง")


async def _do_pause_resume(msg, chat_id, sub, rest):
    cid = _need_id(rest)
    enabled = sub == "resume"
    camp = await asyncio.to_thread(
        store.update_campaign, chat_id, cid,
        lambda c: c.__setitem__("enabled", enabled))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(
        f"{'▶️ เล่นต่อ' if enabled else '⏸ หยุด'}แคมเปญ #{cid} แล้ว")


async def _do_remove(msg, chat_id, rest):
    cid = _need_id(rest)
    ok = await asyncio.to_thread(store.delete_campaign, chat_id, cid)
    if not ok:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    return await msg.reply_text(f"🗑 ลบแคมเปญ #{cid} แล้ว")


async def _do_now(context, msg, chat_id, rest):
    cid = _need_id(rest)
    camp = await asyncio.to_thread(lambda: store.get_campaign(store.load(), chat_id, cid))
    if not camp:
        return await msg.reply_text(f"ไม่พบแคมเปญ #{cid}")
    if not camp.get("links"):
        return await msg.reply_text(f"แคมเปญ #{cid} ยังไม่มีลิงก์")
    await loop._send_one(context.bot, str(chat_id), camp)
    return await msg.reply_text(f"📤 ส่งลิงก์ของแคมเปญ #{cid} แล้ว")
