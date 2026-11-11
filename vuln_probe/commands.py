# -*- coding: utf-8 -*-
"""vuln_probe/commands.py — /vprobe (safe-validation DAST, gated ด้วย scope_policy)"""

from __future__ import annotations

import io
import json
import asyncio
import logging
from typing import Awaitable, Callable, List

from . import store, engine, probes

logger = logging.getLogger("modbot.vuln_probe.commands")

IsAdmin = Callable[..., Awaitable[bool]]
_CHECKS = ("reflection", "sqli", "ssti", "open_redirect", "cors", "takeover")

HELP = (
    "🧪 *Vuln Probe* — ยืนยันช่องโหว่แบบ safe-validation (detection, ไม่ exploit)\n"
    "\n"
    "`/vprobe <program_id> <url> [checks…]`\n"
    f"checks: {', '.join(_CHECKS)} (ไม่ระบุ = ทั้งหมด)\n"
    "`/vprobe list [program_id]` · `/vprobe get <run_id>`\n"
    "\n"
    "⚠️ เป้าหมายต้องผ่าน scope\\_policy (authorization+scope) — ไม่งั้นถูกปฏิเสธ\n"
    "ตรวจแบบไม่ทำลายข้อมูล marker-based · ผลเป็น indicator ให้คนตรวจต่อ ไม่ใช่ข้อสรุปว่า exploit ได้"
)

_SEV = {"INFO": "ℹ️", "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "NONE": "✅"}


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    return True if ct == "private" else await is_admin(update, context)


def _render(run: dict) -> str:
    L = [f"# Vuln Probe #{run['id']} — {run['target']}",
         f"- program: {run['program_id']} · status: {run['status']} · "
         f"requests: {run.get('requests_made', 0)}"]
    if run.get("denied_reason"):
        L.append(f"- reason: {run['denied_reason']}")
    inds = run.get("indicators", [])
    if not inds:
        L.append("\n_ไม่พบ indicator (ไม่ได้แปลว่าปลอดภัย — เป็นการตรวจแบบจำกัด)_")
    for i in inds:
        L.append(f"\n## [{i['severity']}] {i['category']} (conf {i['confidence']})")
        L.append(f"- {i['detail']}")
        if i.get("evidence"):
            L.append(f"- evidence: `{i['evidence']}`")
    if run.get("errors"):
        L.append("\n## errors")
        for e in run["errors"][:10]:
            L.append(f"- {e.get('path')}: {e.get('reason')}")
    L.append("\n---\n_safe-validation · ยก indicator เป็น Finding ผ่าน review gate ของ redteam เมื่อผู้ดูแลยืนยัน_")
    return "\n".join(L)


def _summary(run: dict) -> str:
    if run["status"] == "denied":
        return f"⛔ probe #{run['id']} ปฏิเสธ: {run.get('denied_reason')}"
    if run["status"] != "completed":
        return f"probe #{run['id']}: {run['status']} ({run.get('denied_reason') or ''})"
    inds = run.get("indicators", [])
    worst = run.get("worst_severity", "NONE")
    return (f"{_SEV.get(worst,'•')} probe #{run['id']} {run['target']}: "
            f"{len(inds)} indicator (worst {worst}) · {run.get('requests_made',0)} คำขอ")


async def cmd_vprobe(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    chat_id = update.effective_chat.id
    args: List[str] = list(context.args or [])

    if not args or args[0].lower() in ("help", "h", "?"):
        return await msg.reply_text(HELP, parse_mode="Markdown", disable_web_page_preview=True)

    sub = args[0].lower()
    if sub == "list":
        pid = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
        runs = await asyncio.to_thread(lambda: store.list_runs(pid, 15))
        if not runs:
            return await msg.reply_text("ยังไม่มีการ probe")
        return await msg.reply_text("🗒 *Probe ล่าสุด*\n" + "\n".join(_summary(r) for r in runs),
                                    parse_mode="Markdown")
    if sub == "get":
        if len(args) < 2 or not args[1].isdigit():
            return await msg.reply_text("ใช้: `/vprobe get <run_id>`", parse_mode="Markdown")
        run = await asyncio.to_thread(lambda: store.get_run(int(args[1])))
        if not run:
            return await msg.reply_text(f"ไม่พบ run #{args[1]}")
        return await _send_report(context, chat_id, run)

    if not args[0].isdigit() or len(args) < 2:
        return await msg.reply_text("ใช้: `/vprobe <program_id> <url> [checks…]`",
                                    parse_mode="Markdown")
    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม คำสั่งนี้เฉพาะแอดมิน (ใน DM ใช้ได้)")

    program_id = int(args[0])
    target = args[1]
    checks = [c.lower() for c in args[2:] if c.lower() in _CHECKS] or None

    status = await msg.reply_text(f"🧪 เริ่ม probe {target} (program {program_id})…")

    async def _prog(text):
        try:
            await status.edit_text(text)
        except Exception:
            pass

    try:
        run = await engine.run_probe(program_id, target, update.effective_user.id,
                                     checks=checks, progress=_prog)
    except Exception:
        logger.exception("vprobe run failed")
        return await msg.reply_text("❌ probe ล้มเหลว (ภายใน)")

    try:
        await status.edit_text(_summary(run))
    except Exception:
        await msg.reply_text(_summary(run))
    if run["status"] == "completed":
        await _send_report(context, chat_id, run)


async def _send_report(context, chat_id, run) -> None:
    from telegram import InputFile
    try:
        md = _render(run).encode("utf-8")
        js = json.dumps(run, ensure_ascii=False, indent=2).encode("utf-8")
        for name, data in ((f"vprobe_{run['id']}.md", md), (f"vprobe_{run['id']}.json", js)):
            bio = io.BytesIO(data)
            bio.name = name
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("vprobe send report failed")
