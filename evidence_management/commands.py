# -*- coding: utf-8 -*-
"""evidence_management/commands.py — /evd_* (reuse บอต + report chat + admin perms เดิม)

/evd_collect <task_id>       ingest evidence จาก task ที่เก็บไว้ (ไม่สแกนใหม่)
/evd_list <assessment_id>    สรุป evidence ของการประเมิน
/evd_get <evidence_id>       รายละเอียด evidence หนึ่งรายการ (+ custody)
/evd_verify <evidence_id|assessment_id>  ตรวจ integrity/custody
/evd_finding <finding_id>    finding -> evidence mapping
/evd_timeline <task_id>      ไทม์ไลน์การประเมิน
/evd_report <assessment_id>  รายงาน (executive + technical appendix ไฟล์)

ไม่สร้างบอต/handler ซ้ำ · ไม่ส่ง raw artifact ใหญ่ · ไม่โชว์ secret (redact มาก่อนแล้ว)
"""

from __future__ import annotations

import io
import asyncio
import logging
from typing import Awaitable, Callable, List

from . import store, service, report, timeline

logger = logging.getLogger("modbot.evidence.commands")

IsAdmin = Callable[..., Awaitable[bool]]

HELP = (
    "🗂 *Evidence Management* — คลังหลักฐานการประเมิน (ไม่สแกนเอง)\n"
    "\n"
    "`/evd_collect <task_id>` — ingest evidence จาก task ที่เก็บไว้\n"
    "`/evd_list <assessment_id>` · `/evd_get <evidence_id>`\n"
    "`/evd_verify <evidence_id|assessment_id>` — ตรวจ integrity/custody\n"
    "`/evd_finding <finding_id>` — finding → evidence mapping\n"
    "`/evd_timeline <task_id>` · `/evd_report <assessment_id>`\n"
    "\n"
    "ทุก evidence hash ด้วย SHA-256 · chain-of-custody ตรวจได้ · redact secret ก่อนเก็บ · "
    "hash ไม่พิสูจน์ผู้เก็บ/เวลา และไม่ได้รับฟังตามกฎหมายอัตโนมัติ"
)


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    return True if ct == "private" else await is_admin(update, context)


def _actor(update) -> str:
    try:
        return f"user:{update.effective_user.id}"
    except Exception:
        return "user:unknown"


async def cmd_collect(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text(HELP, parse_mode="Markdown",
                                    disable_web_page_preview=True)
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม เฉพาะแอดมิน (ใน DM ใช้ได้)")
    task_id = args[0]
    try:
        from red_team_orchestrator import store as rt_store
        task = await asyncio.to_thread(lambda: rt_store.get_task(task_id))
    except Exception:
        task = None
    if not task:
        return await msg.reply_text(f"ไม่พบ task {task_id}")
    res = await asyncio.to_thread(lambda: service.ingest_task(task, actor=_actor(update)))
    if res.get("error"):
        return await msg.reply_text(f"⛔ {res['error']}")
    await msg.reply_text(f"🗂 ingest สำเร็จ {res['count']} รายการ "
                         f"(error {len(res.get('errors', []))}) · assessment `{task_id}`",
                         parse_mode="Markdown")


async def cmd_list(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/evd_list <assessment_id>`", parse_mode="Markdown")
    recs = await asyncio.to_thread(lambda: store.by_assessment(args[0]))
    if not recs:
        return await msg.reply_text(f"ไม่มี evidence ของ {args[0]}")
    await msg.reply_text(report.summary_line(recs, args[0]))
    lines = [f"`{r['evidence_id']}` {r['evidence_type']} [{r['integrity_status']}] "
             f"{r['title'][:40]}" for r in recs[:25]]
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_get(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/evd_get <evidence_id>`", parse_mode="Markdown")
    rec = await asyncio.to_thread(lambda: service.access(args[0], _actor(update)))
    if not rec or rec.get("error"):
        return await msg.reply_text(f"ไม่พบ {args[0]}")
    md = report.technical_appendix([rec], assessment_id=rec.get("assessment_id", ""))
    await msg.reply_text(md[:3500] or "—", parse_mode="Markdown",
                         disable_web_page_preview=True)


async def cmd_verify(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/evd_verify <evidence_id|assessment_id>`",
                                    parse_mode="Markdown")
    key = args[0]
    if key.startswith("EVD-"):
        res = await asyncio.to_thread(lambda: service.verify(key, actor=_actor(update)))
        if res.get("error"):
            return await msg.reply_text(f"ไม่พบ {key}")
        await msg.reply_text(report.verification_report([res]), parse_mode="Markdown")
    else:
        res = await asyncio.to_thread(lambda: service.verify_assessment(key))
        await msg.reply_text(f"🗂 verify `{key}`: {res['passed']}/{res['total']} ผ่าน "
                             f"(ล้ม {res['failed']})", parse_mode="Markdown")


async def cmd_finding(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/evd_finding <finding_id>`", parse_mode="Markdown")
    res = await asyncio.to_thread(lambda: service.evidence_for_finding(args[0]))
    roles = res["roles"]
    lines = [f"🔗 finding `{args[0]}` — evidence {res['evidence_count']} รายการ"]
    for role, ids in roles.items():
        if ids:
            lines.append(f"- {role}: {', '.join(ids[:8])}")
    lines.append(f"_{res['note']}_")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_timeline(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/evd_timeline <task_id>`", parse_mode="Markdown")
    try:
        from red_team_orchestrator import store as rt_store
        task = await asyncio.to_thread(lambda: rt_store.get_task(args[0]))
    except Exception:
        task = None
    tl = await asyncio.to_thread(lambda: service.get_timeline(args[0], task=task))
    lines = [f"🕒 *Timeline* `{args[0]}`" + (" (มีเวลา inferred)" if tl["has_inferred"] else "")]
    for e in tl["events"][:25]:
        ts = e["timestamp"] or "—"
        inf = "~" if e["timestamp_inferred"] else " "
        lines.append(f"`{ts[:19]}`{inf}{e['kind']}: {e['detail'][:50]}")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown",
                         disable_web_page_preview=True)


async def cmd_report(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/evd_report <assessment_id>`", parse_mode="Markdown")
    aid = args[0]
    recs = await asyncio.to_thread(lambda: store.by_assessment(aid))
    if not recs:
        return await msg.reply_text(f"ไม่มี evidence ของ {aid}")
    findings = []
    try:
        from red_team_orchestrator import store as rt_store
        task = await asyncio.to_thread(lambda: rt_store.get_task(aid))
        findings = task.get("findings", []) if task else []
    except Exception:
        pass
    await _deliver(context, update.effective_chat.id, aid, recs, findings)


async def _deliver(context, chat_id, aid, recs, findings) -> None:
    try:
        from web_vulnerability_assessment.notify import report_chat_id
        dest = report_chat_id() or chat_id
    except Exception:
        dest = chat_id
    try:
        await context.bot.send_message(chat_id=dest, text=report.summary_line(recs, aid))
    except Exception:
        pass
    from telegram import InputFile
    try:
        rid = str(aid).replace("-", "").replace("/", "")
        files = ((f"{rid}_executive.md", report.executive_summary(recs, assessment_id=aid,
                                                                  findings=findings)),
                 (f"{rid}_appendix.md", report.technical_appendix(recs, assessment_id=aid)),
                 (f"{rid}_evidence.json", report.render_json(recs)))
        for name, data in files:
            bio = io.BytesIO(data.encode("utf-8"))
            bio.name = name
            await context.bot.send_document(chat_id=dest,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("evd report send failed")
