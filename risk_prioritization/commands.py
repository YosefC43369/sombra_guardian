# -*- coding: utf-8 -*-
"""risk_prioritization/commands.py — /risk_* (reuse บอต + report chat + admin perms)

/risk_assess <task_id>     จัดลำดับความเสี่ยงของ task (ไม่รันทดสอบใหม่) + ส่งรายงาน
/risk_status [result_id]   ผลล่าสุด/ตามไอดี
/risk_report <result_id>   รายงานรวม (แนบ md/json + payload execution details)
/risk_payloads [category]  รายงานความครอบคลุม payload library (audit)
"""

from __future__ import annotations

import io
import asyncio
import logging
from typing import Awaitable, Callable, List

from . import store, engine, report, transparency

logger = logging.getLogger("modbot.risk.commands")

IsAdmin = Callable[..., Awaitable[bool]]

HELP = (
    "⚖️ *Risk Prioritization* — จัดลำดับความเสี่ยงจาก finding ที่เก็บไว้ (ไม่รันทดสอบใหม่)\n"
    "\n"
    "`/risk_assess <task_id>` — ให้คะแนน+จัดลำดับ + รายงาน\n"
    "`/risk_status [result_id]` · `/risk_report <result_id>`\n"
    "`/risk_payloads [category]` — audit ความครอบคลุม payload library\n"
    "\n"
    "risk priority แยกจาก technical severity · NEEDS_VERIFICATION = ต้องทดสอบยืนยันเพิ่ม · "
    "ทุกคะแนนอธิบายได้"
)


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    return True if ct == "private" else await is_admin(update, context)


async def cmd_assess(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text(HELP, parse_mode="Markdown",
                                    disable_web_page_preview=True)
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม เฉพาะแอดมิน (ใน DM ใช้ได้)")
    task_id = args[0]
    await msg.reply_text(f"⚖️ กำลังจัดลำดับความเสี่ยงของ `{task_id}` (ไม่รันทดสอบใหม่)…",
                         parse_mode="Markdown")
    result = await engine.analyze_task(task_id)
    if result.get("error"):
        return await msg.reply_text(f"⛔ {result['error']}")
    await msg.reply_text(report.concise_report(result), parse_mode="Markdown",
                         disable_web_page_preview=True)
    # payload execution transparency (จาก findings ของ task)
    await _deliver(context, update.effective_chat.id, result, task_id)


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
        return await msg.reply_text("ยังไม่มีผลการจัดลำดับความเสี่ยง")
    lines = ["⚖️ *Risk results ล่าสุด*"]
    for r in results:
        c = r.get("counts", {})
        lines.append(f"`{r['result_id']}` {r.get('target') or '(assessment)'} · "
                     f"C{c.get('CRITICAL',0)}/H{c.get('HIGH',0)}/NV{c.get('NEEDS_VERIFICATION',0)}")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_report(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/risk_report <result_id>`", parse_mode="Markdown")
    r = await asyncio.to_thread(lambda: store.get_result(args[0]))
    if not r:
        return await msg.reply_text(f"ไม่พบ {args[0]}")
    await _deliver(context, update.effective_chat.id, r, r.get("source_task_id"))


async def cmd_payloads(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    try:
        from web_vulnerability_assessment import payload_engine as pe
        cov = await asyncio.to_thread(pe.audit_report)
    except Exception as e:
        return await msg.reply_text(f"โหลด payload library ไม่ได้: {e}")
    lines = ["🧪 *Payload Library Audit*",
             f"total test cases: {cov['total_test_cases']}",
             f"categories: {len(cov['categories_covered'])} covered, "
             f"{len(cov['categories_unsupported'])} unsupported",
             f"duplicates: {len(cov['duplicates_detected'])} · "
             f"rejected(unsafe/invalid): {len(cov['rejected_unsafe_or_invalid'])}",
             f"by profile: {cov['by_profile']}"]
    if args:
        cat = args[0].lower()
        n = cov["by_category"].get(cat, 0)
        subs = {k: v for k, v in cov["by_subcategory"].items() if k.startswith(cat + "/")}
        lines.append(f"\n*{cat}*: {n} test cases · subcategories: {subs}")
    else:
        lines.append(f"\nby category: {cov['by_category']}")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def _deliver(context, chat_id, result, task_id) -> None:
    try:
        from web_vulnerability_assessment.notify import report_chat_id
        dest = report_chat_id() or chat_id
    except Exception:
        dest = chat_id
    try:
        await context.bot.send_message(chat_id=dest, text=report.summary_line(result))
    except Exception:
        pass
    # build payload transparency จาก findings ของ task (ถ้าหา task ได้)
    trans = None
    if task_id:
        try:
            from red_team_orchestrator import store as rt_store
            from web_vulnerability_assessment import payload_engine as pe
            task = await asyncio.to_thread(lambda: rt_store.get_task(task_id))
            if task:
                pset = await asyncio.to_thread(pe.load_payloads)
                trans = transparency.build_transparency(task.get("findings", []),
                                                        payload_set=pset)
        except Exception:
            trans = None
    await _send_files(context, dest, result, trans)


async def _send_files(context, chat_id, result, trans) -> None:
    from telegram import InputFile
    try:
        rid = str(result.get("result_id", "risk")).replace("-", "")
        txt = report.render_txt(result)
        if trans:
            txt += "\n" + report.payload_execution_txt(trans)
        rj = result
        if trans:
            rj = dict(result)
            rj.update(report.payload_execution_json(trans))
        files = ((f"{rid}.txt", txt),
                 (f"{rid}.json", report.render_json(rj)))
        for name, data in files:
            bio = io.BytesIO(data.encode("utf-8"))
            bio.name = name
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("risk report send failed")
