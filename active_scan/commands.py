# -*- coding: utf-8 -*-
"""active_scan/commands.py — คำสั่ง /ascan (active port/service scan + AXFR)

ต่างจาก /scan เดิม (passive web checks) — /ascan เปิด socket จริงไปยังพอร์ต
จึงบังคับ "ต้องมี program ที่ได้รับอนุญาตใน scope_policy" และผ่าน guard ทุกครั้ง

การใช้:
  /ascan <program_id> <target> [quick|top100|web|db]
  /ascan list [program_id]
  /ascan get <scan_id>
  /ascan profiles
สิทธิ์: ในกลุ่มต้องเป็นแอดมิน (ใน DM ใช้ได้) — และเป้าหมายต้องผ่าน scope_policy อยู่แล้ว
"""

from __future__ import annotations

import io
import json
import logging
from typing import Awaitable, Callable, List

from . import store, engine, scanner

logger = logging.getLogger("modbot.active_scan.commands")

IsAdmin = Callable[..., Awaitable[bool]]

HELP = (
    "🛰 *Active Scan* — สแกนพอร์ต/บริการจริง (gated ด้วย scope\\_policy)\n"
    "\n"
    "`/ascan <program_id> <target> [profile]`\n"
    "โปรไฟล์: `quick` `top100` `web` `db` (ดีฟอลต์ quick)\n"
    "`/ascan list [program_id]` · `/ascan get <scan_id>` · `/ascan profiles`\n"
    "\n"
    "⚠️ เป้าหมายต้องอยู่ใน program ที่ได้รับ *authorization + scope* แล้ว "
    "(ตั้งผ่านระบบ scope\\_policy เดิม) — ถ้าไม่ผ่านจะถูกปฏิเสธทันที\n"
    "สแกนเฉพาะ IP สาธารณะ · ไม่แตะ loopback/private/metadata"
)


async def _allowed(update, context, is_admin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    if ct == "private":
        return True
    return await is_admin(update, context)


def _render(scan: dict) -> str:
    L = [f"# Active Scan #{scan['id']} — {scan['target']}",
         f"- program: {scan['program_id']} · profile: {scan['profile']} · status: {scan['status']}"]
    if scan.get("denied_reason"):
        L.append(f"- reason: {scan['denied_reason']}")
    s = scan.get("summary") or {}
    if s:
        L.append(f"- hosts up: {s.get('hosts_up')}/{s.get('hosts_scanned')} · "
                 f"open ports: {s.get('open_ports_total')} · services: {', '.join(s.get('services', []))}")
    for h in scan.get("hosts", []):
        if not h["ports"]:
            continue
        L.append(f"\n## {h['hostname']} ({h['ip']})")
        for p in h["ports"]:
            b = (p.get("banner") or "").replace("\n", " ")[:80]
            L.append(f"- {p['port']}/tcp  {p['service']:<12} {p['latency_ms']}ms  {b}")
    dns = scan.get("dns") or {}
    if dns.get("results"):
        L.append("\n## DNS AXFR")
        for r in dns["results"]:
            L.append(f"- {r.get('nameserver')}: {r.get('status')}"
                     + (f" ({r.get('record_count')} records)" if r.get('record_count') else ""))
    if scan.get("errors"):
        L.append("\n## errors")
        for e in scan["errors"]:
            L.append(f"- {e.get('host')}: {e.get('reason')}")
    return "\n".join(L)


def _summary_line(scan: dict) -> str:
    if scan["status"] == "denied":
        return f"⛔ scan #{scan['id']} ปฏิเสธ: {scan.get('denied_reason')}"
    if scan["status"] != "completed":
        return f"scan #{scan['id']}: {scan['status']} ({scan.get('denied_reason') or ''})"
    s = scan.get("summary") or {}
    return (f"✅ scan #{scan['id']} {scan['target']}: open {s.get('open_ports_total',0)} พอร์ต "
            f"/ {s.get('hosts_up',0)} host · {', '.join(s.get('services', [])[:8])}")


async def cmd_ascan(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    chat_id = update.effective_chat.id
    args: List[str] = list(context.args or [])

    if not args or args[0].lower() in ("help", "h", "?"):
        return await msg.reply_text(HELP, parse_mode="Markdown", disable_web_page_preview=True)

    sub = args[0].lower()

    if sub == "profiles":
        lines = ["📋 *โปรไฟล์ที่มี*"]
        for name, ports in scanner.PROFILES.items():
            lines.append(f"- `{name}`: {len(ports)} พอร์ต")
        return await msg.reply_text("\n".join(lines), parse_mode="Markdown")

    if sub == "list":
        pid = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
        scans = await _to_thread(lambda: store.list_scans(pid, 15))
        if not scans:
            return await msg.reply_text("ยังไม่มีการสแกน")
        return await msg.reply_text("🗒 *สแกนล่าสุด*\n" + "\n".join(_summary_line(s) for s in scans),
                                    parse_mode="Markdown")

    if sub == "get":
        if len(args) < 2 or not args[1].isdigit():
            return await msg.reply_text("ใช้: `/ascan get <scan_id>`", parse_mode="Markdown")
        scan = await _to_thread(lambda: store.get_scan(int(args[1])))
        if not scan:
            return await msg.reply_text(f"ไม่พบ scan #{args[1]}")
        return await _send_report(context, chat_id, scan)

    # รูปแบบสแกน: /ascan <program_id> <target> [profile]
    if not args[0].isdigit():
        return await msg.reply_text("ใช้: `/ascan <program_id> <target> [profile]`",
                                    parse_mode="Markdown")
    if len(args) < 2:
        return await msg.reply_text("ต้องระบุเป้าหมาย: `/ascan <program_id> <target> [profile]`",
                                    parse_mode="Markdown")

    if not await _allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม คำสั่งนี้เฉพาะแอดมิน (ใน DM ใช้ได้)")

    program_id = int(args[0])
    target = args[1]
    profile = args[2].lower() if len(args) > 2 and args[2].lower() in scanner.PROFILES else "quick"

    status = await msg.reply_text(f"🛰 เริ่มสแกน {target} (program {program_id}, {profile})…")

    async def _prog(text):
        try:
            await status.edit_text(text)
        except Exception:
            pass

    try:
        scan = await engine.run_scan(program_id, target, update.effective_user.id,
                                     profile=profile, progress=_prog)
    except Exception:
        logger.exception("ascan run failed")
        return await msg.reply_text("❌ สแกนล้มเหลว (ภายใน)")

    try:
        await status.edit_text(_summary_line(scan))
    except Exception:
        await msg.reply_text(_summary_line(scan))
    if scan["status"] == "completed":
        await _send_report(context, chat_id, scan)


async def _send_report(context, chat_id, scan) -> None:
    from telegram import InputFile
    try:
        md = _render(scan).encode("utf-8")
        js = json.dumps(scan, ensure_ascii=False, indent=2).encode("utf-8")
        for name, data in ((f"ascan_{scan['id']}.md", md), (f"ascan_{scan['id']}.json", js)):
            bio = io.BytesIO(data)
            bio.name = name
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=name))
    except Exception:
        logger.exception("ascan send report failed")


async def _to_thread(fn):
    import asyncio
    return await asyncio.to_thread(fn)
