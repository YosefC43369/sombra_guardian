# -*- coding: utf-8 -*-
"""attack_surface_correlation/commands.py — /asc_* (reuse บอต+report chat เดิม)

/asc_correlate <task_id>   correlate ข้อมูลที่ orchestrator เก็บไว้ (ไม่สแกนใหม่)
/asc_status [result_id]    สถานะ/ผลล่าสุด
/asc_report <result_id>    รายงานรวม (แนบไฟล์ md/json + graph.json)

ไม่สร้างบอต/handler ซ้ำ — ลงทะเบียนกับ Application เดิม และส่งผลไป SECURITY_REPORT_CHAT_ID
(reuse web_vulnerability_assessment.notify.report_chat_id)
"""

from __future__ import annotations

import io
import asyncio
import logging
from typing import Awaitable, Callable, List

from . import store, engine, report

logger = logging.getLogger("modbot.asc.commands")

IsAdmin = Callable[..., Awaitable[bool]]

HELP = (
    "🕸 *Attack Surface Correlation* — รวม/เชื่อมโยง asset จากโมดูลเดิม (ไม่สแกนเอง)\n"
    "\n"
    "`/asc_correlate <task_id>` — correlate ผลที่ orchestrator เก็บไว้ (ไม่สแกนใหม่)\n"
    "`/asc_status [result_id]` — ผลล่าสุด/ตามไอดี\n"
    "`/asc_report <result_id>` — รายงานรวม (แนบ md/json + graph.json)\n"
    "\n"
    "อ่านจาก unified findings ของ task · ทุกความสัมพันธ์มีหลักฐานหรือระบุเป็นสมมติฐาน · "
    "IP/CDN ร่วมกัน ไม่ถือเป็นเจ้าของเดียวกัน"
)


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    return True if ct == "private" else await is_admin(update, context)


async def cmd_correlate(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text(HELP, parse_mode="Markdown",
                                    disable_web_page_preview=True)
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม เฉพาะแอดมิน (ใน DM ใช้ได้)")
    task_id = args[0]
    await msg.reply_text(f"🕸 กำลัง correlate ข้อมูลของ `{task_id}` (ไม่สแกนใหม่)…",
                         parse_mode="Markdown")
    result = await engine.analyze_task(task_id)
    if result.get("error"):
        return await msg.reply_text(f"⛔ {result['error']}")
    await msg.reply_text(report.concise_report(result), parse_mode="Markdown",
                         disable_web_page_preview=True)
    await _deliver(context, update.effective_chat.id, result)


async def cmd_status(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if args:
        r = await asyncio.to_thread(lambda: store.get_result(args[0]))
        if not r:
            return await msg.reply_text(f"ไม่พบ {args[0]}")
        return await msg.reply_text(report.concise_report(r), parse_mode="Markdown",
                                    disable_web_page_preview=True)
    results = await asyncio.to_thread(lambda: store.list_results(10))
    if not results:
        return await msg.reply_text("ยังไม่มีผล correlation")
    lines = ["🕸 *Correlation ล่าสุด*"]
    for r in results:
        c = r.get("counts", {})
        lines.append(f"`{r['result_id']}` {r.get('target') or '(dataset)'} · "
                     f"assets {c.get('total_assets',0)} · rel {c.get('total_relationships',0)}")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_report(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/asc_report <result_id>`", parse_mode="Markdown")
    r = await asyncio.to_thread(lambda: store.get_result(args[0]))
    if not r:
        return await msg.reply_text(f"ไม่พบ {args[0]}")
    await _send_files(context, update.effective_chat.id, r)


async def _deliver(context, chat_id, result) -> None:
    """ส่งสรุป+ไฟล์ไป report chat เดิม (reuse SECURITY_REPORT_CHAT_ID)"""
    try:
        from web_vulnerability_assessment.notify import report_chat_id
        dest = report_chat_id() or chat_id
    except Exception:
        dest = chat_id
    try:
        await context.bot.send_message(chat_id=dest, text=report.summary_line(result))
    except Exception:
        pass
    await _send_files(context, dest, result)


async def _send_files(context, chat_id, result) -> None:
    from telegram import InputFile
    try:
        rid = str(result.get("result_id", "asc")).replace("-", "")
        files = ((f"{rid}.md", report.render_markdown(result)),
                 (f"{rid}.json", report.render_json(result)),
                 (f"{rid}_graph.json", report.graph_json(result)))
        for name, data in files:
            bio = io.BytesIO(data.encode("utf-8"))
            bio.name = name
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("asc send report failed")
