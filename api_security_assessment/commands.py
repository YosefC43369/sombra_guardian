# -*- coding: utf-8 -*-
"""api_security_assessment/commands.py — /api_assess /api_import /api_status /api_report /api_stop

ใช้ร่วม authorization กับ WVA: อนุญาตโดเมนด้วย /allowscan (simple_scope เดิม) ครั้งเดียว
แล้ว /api_assess ใช้ URL ล้วนได้ — ไม่ซ้ำระบบ scope
"""

from __future__ import annotations

import io
import asyncio
import logging
from typing import Awaitable, Callable, Dict, List

from . import store, engine, spec, report, notify
from web_vulnerability_assessment import simple_scope

logger = logging.getLogger("modbot.api.commands")

IsAdmin = Callable[..., Awaitable[bool]]

HELP = (
    "🔌 *API Security Assessment* (authorized เท่านั้น)\n"
    "\n"
    "`/allowscan <url>` — อนุญาตโดเมนก่อน (ใช้ร่วมกับ WVA)\n"
    "`/api_import <url|แนบไฟล์ .json/.yaml>` — นำเข้า OpenAPI/Swagger/Postman\n"
    "`/api_assess <base_url> [categories…] [key=value…]`\n"
    "`/api_status [id]` · `/api_report <id>` · `/api_stop <id>`\n"
    "\n"
    "categories: authentication authorization input_validation sqli xss graphql cors "
    "info_disclosure misconfiguration\n"
    "options (ควรทำใน DM): `token=` (JWT/auth) `token_a= token_b= object=/path/{id} id=<synthetic>`\n"
    "\n"
    "safe-validation · ไม่ bypass/forge/brute/DoS · authz ใช้ test account + synthetic id เท่านั้น\n"
    "ส่งผลไปที่ `API_SECURITY_REPORT_CHAT_ID`"
)

_CATS = ("authentication", "authorization", "input_validation", "sqli", "xss",
         "graphql", "cors", "info_disclosure", "misconfiguration")


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    return True if ct == "private" else await is_admin(update, context)


def _parse_args(args: List[str]):
    cats, opts = [], {}
    rest = []
    for a in args:
        if "=" in a and a.split("=", 1)[0] in ("token", "token_a", "token_b", "object", "id", "origin"):
            k, v = a.split("=", 1)
            opts[{"object": "object_endpoint", "id": "synthetic_id"}.get(k, k)] = v
        elif a.lower() in _CATS:
            cats.append(a.lower())
        else:
            rest.append(a)
    return rest, (cats or None), opts


async def cmd_import(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม เฉพาะแอดมิน (ใน DM ใช้ได้)")
    args = list(context.args or [])
    text = None
    # แนบไฟล์หรือ reply ไปหาไฟล์
    doc = getattr(msg, "document", None) or (
        getattr(msg.reply_to_message, "document", None) if msg.reply_to_message else None)
    if doc is not None:
        try:
            f = await context.bot.get_file(doc.file_id)
            raw = await f.download_as_bytearray()
            text = bytes(raw).decode("utf-8", errors="replace")
        except Exception:
            return await msg.reply_text("อ่านไฟล์ไม่สำเร็จ")
    if text is None and args and args[0].startswith(("http://", "https://")):
        # ดึงสเปคจาก URL ที่อนุญาตแล้วเท่านั้น (gate)
        pid = await asyncio.to_thread(simple_scope.program_for, args[0])
        if pid is None:
            return await msg.reply_text(f"⛔ โดเมนยังไม่อนุญาต — `/allowscan {args[0]}` ก่อน",
                                        parse_mode="Markdown")
        text = await _fetch_spec(context, pid, args[0])
        if text is None:
            return await msg.reply_text("ดึงสเปคจาก URL ไม่สำเร็จ (หรือไม่ผ่าน scope)")
    if not text:
        return await msg.reply_text("แนบไฟล์ .json/.yaml หรือระบุ URL สเปคที่อนุญาตแล้ว")

    parsed = spec.from_spec(text)
    if not parsed.get("ok"):
        return await msg.reply_text(f"⚠️ {parsed.get('reason')}")
    # เก็บตาม host ของ base (ถ้า import จาก URL) หรือจาก title
    domain = _domain_hint(args)
    eps = parsed["endpoints"]
    cls = spec.classify_endpoints(eps)
    if domain:
        await asyncio.to_thread(store.store_spec, domain, eps, parsed.get("api_info", {}),
                                parsed.get("kind"))
    await msg.reply_text(
        f"✅ นำเข้า {parsed['kind']} — {len(eps)} endpoints\n"
        f"sensitive: {len(cls['sensitive'])} · admin: {len(cls['admin'])} · "
        f"no-auth: {len(cls['no_auth_documented'])} · มี object-id: {len(cls['with_object_id'])}"
        + (f"\nเก็บไว้กับโดเมน `{domain}` แล้ว — `/api_assess {args[0] if args else ''}`"
           if domain else "\n(ระบุ URL ตอน import เพื่อผูกกับโดเมน)"),
        parse_mode="Markdown")


async def _fetch_spec(context, program_id, url):
    """ดึงไฟล์สเปคจาก URL ที่อนุญาตแล้ว ผ่าน gated fetch ของ engine"""
    try:
        from scope_policy import normalize_target, TargetType
        from security_testing import _endpoint_from_target
        norm = normalize_target(url)
        if norm is None:
            return None
        base_ep, err = _endpoint_from_target(norm)
        if err:
            return None
        resp, reason = await engine._api_fetch(program_id, base_ep, base_ep["host"],
                                               norm.target_type, base_ep["path"], method="GET")
        return resp["body"] if resp else None
    except Exception:
        logger.exception("API fetch spec failed")
        return None


def _domain_hint(args):
    for a in args:
        if a.startswith(("http://", "https://")):
            try:
                import urlkit
                return urlkit.extract(a).host
            except Exception:
                return None
    return None


async def cmd_assess(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text(HELP, parse_mode="Markdown", disable_web_page_preview=True)
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม เฉพาะแอดมิน (ใน DM ใช้ได้)")

    rest, cats, opts = _parse_args(args)
    if not rest:
        return await msg.reply_text("ใช้: `/api_assess <base_url> [categories] [key=value]`",
                                    parse_mode="Markdown")
    target = rest[0]
    program_id = await asyncio.to_thread(simple_scope.program_for, target)
    if program_id is None:
        return await msg.reply_text(f"⛔ ยังไม่อนุญาตโดเมนนี้ — `/allowscan {target}` ก่อน",
                                    parse_mode="Markdown")

    # ลบ token ออกจากข้อความ echo (กันหลุดใน history)
    status = await msg.reply_text(f"🔌 เริ่มประเมิน API {target}…")

    async def _prog(text):
        try:
            await status.edit_text(text[:300])
        except Exception:
            pass

    notifier = notify.Notifier(context.bot, fallback_chat_id=update.effective_chat.id)

    async def _notify(f, a):
        await notifier.finding_alert(f, a)

    try:
        a = await engine.run_assessment(program_id, target, update.effective_user.id,
                                        options=opts, categories=cats,
                                        progress=_prog, notify=_notify)
    except Exception:
        logger.exception("api_assess failed")
        return await msg.reply_text("❌ การประเมินล้มเหลว (ภายใน)")

    await _prog(report.summary_text(a).split("\n\n")[0] + f" — #{a['id']}")
    await notifier.summary(a)
    if a["status"] == "completed":
        await _send_report(context, update.effective_chat.id, a)


async def cmd_status(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if args and args[0].isdigit():
        a = await asyncio.to_thread(lambda: store.get_assessment(int(args[0])))
        if not a:
            return await msg.reply_text(f"ไม่พบ #{args[0]}")
        return await msg.reply_text(report.summary_text(a))
    runs = await asyncio.to_thread(lambda: store.list_assessments(None, 10))
    if not runs:
        return await msg.reply_text("ยังไม่มีการประเมิน API")
    lines = ["🗒 *API assessments ล่าสุด*"]
    for a in runs:
        c = a.get("counts", {})
        lines.append(f"#{a['id']} {a['target']} · {a['status']} · "
                     f"ep {a.get('endpoints_analyzed',0)} · H{c.get('HIGH',0)}/M{c.get('MEDIUM',0)}")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_stop(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args or not args[0].isdigit():
        return await msg.reply_text("ใช้: `/api_stop <id>`", parse_mode="Markdown")
    ok = await asyncio.to_thread(lambda: store.request_cancel(int(args[0])))
    await msg.reply_text(f"🛑 ส่งสัญญาณยกเลิก #{args[0]}" if ok else f"ไม่พบ #{args[0]}")


async def cmd_report(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args or not args[0].isdigit():
        return await msg.reply_text("ใช้: `/api_report <id>`", parse_mode="Markdown")
    a = await asyncio.to_thread(lambda: store.get_assessment(int(args[0])))
    if not a:
        return await msg.reply_text(f"ไม่พบ #{args[0]}")
    await _send_report(context, update.effective_chat.id, a)


async def _send_report(context, chat_id, a) -> None:
    from telegram import InputFile
    try:
        for name, data in ((f"api_{a['id']}.md", report.render_markdown(a)),
                           (f"api_{a['id']}.json", report.render_json(a))):
            bio = io.BytesIO(data.encode("utf-8"))
            bio.name = name
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("API send report failed")
