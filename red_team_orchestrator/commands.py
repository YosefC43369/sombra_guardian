# -*- coding: utf-8 -*-
"""red_team_orchestrator/commands.py — /rt_* (ประสานโมดูลเดิมผ่าน Telegram)

/rt_assess <type> <target> [modules…] [key=value]   สร้าง task + plan
/rt_plan <type> <target>                             พรีวิวแผน (ไม่สร้าง task)
/rt_approve <task_id>                                อนุมัติ + รัน
/rt_status [task_id]                                 สถานะ
/rt_cancel <task_id>                                 ยกเลิก
/rt_report <task_id>                                 รายงานรวม (แนบไฟล์)
"""

from __future__ import annotations

import io
import asyncio
import logging
from typing import Awaitable, Callable, Dict, List

from . import store, engine, registry, report

logger = logging.getLogger("modbot.rt_orch.commands")

IsAdmin = Callable[..., Awaitable[bool]]

_TYPE_ALIAS = {"website": "website_assessment", "web": "website_assessment",
               "api": "api_assessment", "recon": "recon_only", "portscan": "port_scan",
               "port": "port_scan"}

HELP = (
    "🧭 *Red Team Orchestrator* — ประสานโมดูลเดิมให้ทำงานร่วมกัน\n"
    "\n"
    "`/rt_assess <website|api|recon|portscan> <target> [modules…] [key=value]`\n"
    "`/rt_plan <type> <target>` — ดูแผนก่อน (ไม่สร้าง task)\n"
    "`/rt_approve <task_id>` · `/rt_status [task_id]` · `/rt_cancel <task_id>` · `/rt_report <task_id>`\n"
    "\n"
    "pipelines: website = passive_recon → vuln_probe → web_vulnerability_assessment · "
    "api = passive_recon → api_security_assessment · recon = passive_recon · portscan = active_scan\n"
    "⚠️ โมดูล active ต้อง `/allowscan <target>` ก่อน (ใช้ scope เดิม) · "
    "options (DM): `spec_text=` `profile=` · token ไม่เก็บลง log"
)


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    return True if ct == "private" else await is_admin(update, context)


def _parse(args: List[str]):
    opts, mods, rest = {}, [], []
    for a in args:
        if "=" in a and a.split("=", 1)[0].isidentifier():
            k, v = a.split("=", 1)
            opts[k] = v
        elif a in registry.REGISTRY:
            mods.append(a)
        else:
            rest.append(a)
    return rest, (mods or None), opts


async def cmd_assess(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if not args:
        return await msg.reply_text(HELP, parse_mode="Markdown", disable_web_page_preview=True)
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม เฉพาะแอดมิน (ใน DM ใช้ได้)")
    rest, mods, opts = _parse(args)
    if len(rest) < 2:
        return await msg.reply_text("ใช้: `/rt_assess <type> <target> [modules] [key=value]`",
                                    parse_mode="Markdown")
    ttype = _TYPE_ALIAS.get(rest[0].lower(), rest[0].lower())
    target = rest[1]

    res = await asyncio.to_thread(engine.create_task, ttype, target,
                                  update.effective_user.id, update.effective_chat.id, opts, mods)
    if res.get("error"):
        extra = f" (มี task อยู่แล้ว: {res.get('existing')})" if res.get("existing") else ""
        return await msg.reply_text(f"⚠️ {res['error']}{extra}")
    if res["status"] == "FAILED":
        return await msg.reply_text(f"⛔ {res.get('status_reason')}")

    await msg.reply_text(report.plan_text(res), parse_mode="Markdown",
                         disable_web_page_preview=True)
    if res["status"] == "RUNNING":   # approval ไม่บังคับ -> รันเลย
        await _run_bg(context, update.effective_chat.id, res["task_id"])


async def cmd_plan(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if len(args) < 2:
        return await msg.reply_text("ใช้: `/rt_plan <type> <target>`", parse_mode="Markdown")
    ttype = _TYPE_ALIAS.get(args[0].lower(), args[0].lower())
    plan = await asyncio.to_thread(engine.build_plan, ttype, args[1], None)
    fake = {"task_id": "(preview)", "task_type": ttype, "target": args[1],
            "status": "PREVIEW", "plan": plan}
    await msg.reply_text(report.plan_text(fake), parse_mode="Markdown",
                         disable_web_page_preview=True)


async def cmd_approve(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/rt_approve <task_id>`", parse_mode="Markdown")
    tid = args[0]
    rec = await asyncio.to_thread(engine.approve, tid, update.effective_user.id)
    if rec is None:
        return await msg.reply_text(f"ไม่พบ task {tid}")
    if rec["status"] != "RUNNING":
        return await msg.reply_text(f"task {tid} อยู่สถานะ {rec['status']} (อนุมัติไม่ได้)")
    await msg.reply_text(f"✅ อนุมัติ {tid} — กำลังรัน…")
    await _run_bg(context, update.effective_chat.id, tid)


async def _run_bg(context, chat_id, task_id):
    """รันไปป์ไลน์เป็น background task เพื่อไม่บล็อก + ให้ /rt_cancel ทำงานระหว่างรันได้"""
    async def _job():
        async def _prog(text):
            try:
                await context.bot.send_message(chat_id=chat_id, text=text[:300])
            except Exception:
                pass
        try:
            task = await engine.run_task(task_id, progress=_prog)
            await _deliver(context, chat_id, task)
        except Exception:
            logger.exception("rt run_task failed %s", task_id)
    asyncio.create_task(_job())


async def _deliver(context, chat_id, task):
    """ส่งสรุป + รายงานไปยัง report chat (reuse SECURITY_REPORT_CHAT_ID) และแชตที่สั่ง"""
    try:
        from web_vulnerability_assessment.notify import report_chat_id
        dest = report_chat_id() or chat_id
    except Exception:
        dest = chat_id
    try:
        await context.bot.send_message(chat_id=dest, text=report.summary_text(task))
    except Exception:
        pass
    await _send_files(context, dest, task)


async def cmd_status(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    args = list(context.args or [])
    if args:
        t = await asyncio.to_thread(lambda: store.get_task(args[0]))
        if not t:
            return await msg.reply_text(f"ไม่พบ {args[0]}")
        return await msg.reply_text(report.summary_text(t), parse_mode="Markdown",
                                    disable_web_page_preview=True)
    tasks = await asyncio.to_thread(lambda: store.list_tasks(10))
    if not tasks:
        return await msg.reply_text("ยังไม่มี task")
    lines = ["🧭 *Tasks ล่าสุด*"]
    for t in tasks:
        c = t.get("counts", {})
        lines.append(f"`{t['task_id']}` {t['task_type']} {t['target']} · {t['status']} · "
                     f"F{c.get('total_findings',0)}")
    await msg.reply_text("\n".join(lines), parse_mode="Markdown")


async def cmd_cancel(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/rt_cancel <task_id>`", parse_mode="Markdown")
    ok = await asyncio.to_thread(lambda: store.request_cancel(args[0]))
    await msg.reply_text(f"🛑 ส่งสัญญาณยกเลิก {args[0]}" if ok else f"ไม่พบ {args[0]}")


async def cmd_report(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ เฉพาะแอดมิน")
    args = list(context.args or [])
    if not args:
        return await msg.reply_text("ใช้: `/rt_report <task_id>`", parse_mode="Markdown")
    t = await asyncio.to_thread(lambda: store.get_task(args[0]))
    if not t:
        return await msg.reply_text(f"ไม่พบ {args[0]}")
    await _send_files(context, update.effective_chat.id, t)


async def _send_files(context, chat_id, task):
    from telegram import InputFile
    try:
        tid = task["task_id"].replace("-", "")
        for name, data in ((f"{tid}.md", report.render_markdown(task)),
                           (f"{tid}.json", report.render_json(task))):
            bio = io.BytesIO(data.encode("utf-8"))
            bio.name = name
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("rt send report failed")
