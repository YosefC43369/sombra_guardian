# -*- coding: utf-8 -*-
"""passive_recon/commands.py — คำสั่ง /recon (เป้าหมายเดียว + ไฟล์ .txt หลายเป้าหมาย)

ผูกกับ dispatcher เดิมของบอต ไม่สร้าง instance ใหม่ ไม่แตะคำสั่งเดิม
- ในกลุ่ม: ต้องเป็นแอดมิน (กันใช้บอตยิง outbound มั่ว ๆ)
- ในแชตส่วนตัว: ใช้ได้ (เป็นเซสชันของผู้ใช้เอง)
ผลลัพธ์: สรุปสั้นในแชต + แนบรายงาน Markdown และ JSON เป็นไฟล์
"""

from __future__ import annotations

import io
import asyncio
import logging
from typing import Awaitable, Callable, List, Optional

from . import recon

logger = logging.getLogger("modbot.passive_recon.commands")

IsAdmin = Callable[..., Awaitable[bool]]

MAX_TARGETS = int(__import__("os").getenv("RECON_MAX_TARGETS", "20") or "20")
VALID_FORMATS = ("markdown", "json", "txt")


HELP = (
    "🛰 *Passive Recon* — เก็บข่าวกรองแบบ passive (ไม่สแกน/ไม่โจมตี)\n"
    "\n"
    "`/recon <url|domain>` — เป้าหมายเดียว เช่น `/recon https://example.com`\n"
    "`/recon` พร้อมแนบไฟล์ `.txt` (URL บรรทัดละ 1 อัน) — หลายเป้าหมาย\n"
    "ธงรูปแบบ (ออปชัน): `--json` `--txt` `--md`\n"
    "\n"
    "เก็บ: DNS, WHOIS/RDAP, subdomains (CT log), เทคโนโลยี, TLS, HTTP metadata, "
    "ASN/ISP/geo, ตัวชี้วัดความปลอดภัยเชิงข้อมูล\n"
    "_passive-only · SSRF-guarded · ไม่ brute-force/ไม่ exploit_"
)


def _parse_flags(args: List[str]):
    fmt = "markdown"
    targets = []
    for a in args:
        al = a.lower()
        if al in ("--json", "-json"):
            fmt = "json"
        elif al in ("--txt", "-txt", "--text"):
            fmt = "txt"
        elif al in ("--md", "--markdown"):
            fmt = "markdown"
        else:
            targets.append(a)
    return fmt, targets


async def _is_allowed(update, context, is_admin: IsAdmin) -> bool:
    ct = str(getattr(update.effective_chat, "type", ""))
    if ct == "private":
        return True
    return await is_admin(update, context)


async def _read_txt_targets(update, context) -> List[str]:
    """อ่าน URL จากไฟล์ .txt ที่แนบมา (หรือ reply ไปหา) — คืน list บรรทัด"""
    msg = update.effective_message
    doc = getattr(msg, "document", None)
    if doc is None and msg.reply_to_message is not None:
        doc = getattr(msg.reply_to_message, "document", None)
    if doc is None:
        return []
    name = (getattr(doc, "file_name", "") or "").lower()
    if not name.endswith(".txt"):
        return []
    try:
        f = await context.bot.get_file(doc.file_id)
        raw = await f.download_as_bytearray()
        text = bytes(raw).decode("utf-8", errors="replace")
    except Exception:
        logger.exception("recon: read .txt failed")
        return []
    lines = [ln.strip() for ln in text.splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("#")]


def _report_files(report: dict, fmt: str, label: str):
    """คืน list ของ (filename, bytes) สำหรับแนบ"""
    out = []
    dom = (report.get("target") or {}).get("domain") or label
    if fmt == "json":
        out.append((f"recon_{dom}.json", recon.render(report, "json").encode("utf-8")))
    elif fmt == "txt":
        out.append((f"recon_{dom}.txt", recon.render(report, "txt").encode("utf-8")))
    else:
        out.append((f"recon_{dom}.md", recon.render(report, "markdown").encode("utf-8")))
    # แนบ JSON เสมอ (ข้อมูลครบ + source/timestamp) เว้นแต่เลือก json อยู่แล้ว
    if fmt != "json":
        out.append((f"recon_{dom}.json", recon.render(report, "json").encode("utf-8")))
    return out


async def _send_files(context, chat_id, files) -> None:
    from telegram import InputFile
    for fname, data in files:
        try:
            bio = io.BytesIO(data)
            bio.name = fname
            await context.bot.send_document(chat_id=chat_id,
                                            document=InputFile(bio, filename=fname))
        except Exception:
            logger.exception("recon: send_document failed (%s)", fname)


async def cmd_recon(update, context, is_admin: IsAdmin) -> None:
    msg = update.effective_message
    chat_id = update.effective_chat.id
    fmt, targets = _parse_flags(list(context.args or []))

    # ไฟล์ .txt (หลายเป้าหมาย) ถ้ามี
    file_targets = await _read_txt_targets(update, context)
    targets = targets + file_targets

    if not targets:
        return await msg.reply_text(HELP, parse_mode="Markdown",
                                    disable_web_page_preview=True)

    if not await _is_allowed(update, context, is_admin):
        return await msg.reply_text("⛔ ในกลุ่ม คำสั่งนี้เฉพาะแอดมิน (ใน DM ใช้ได้เลย)")

    if len(targets) > MAX_TARGETS:
        await msg.reply_text(f"⚠️ จำกัดครั้งละ {MAX_TARGETS} เป้าหมาย — จะทำ {MAX_TARGETS} แรก")
        targets = targets[:MAX_TARGETS]

    status = await msg.reply_text(f"🛰 กำลังเก็บข่าวกรอง {len(targets)} เป้าหมาย…")

    async def _prog(text: str):
        try:
            await status.edit_text(text)
        except Exception:
            pass

    # แต่ละเป้าหมายแยกกัน — error เป้าหนึ่งไม่ล้มทั้งชุด
    summaries = []
    for i, tgt in enumerate(targets, 1):
        await _prog(f"[{i}/{len(targets)}] {tgt}")
        try:
            report = await recon.run_recon(tgt, progress=(_prog if len(targets) == 1 else None))
        except Exception:
            logger.exception("recon run failed: %s", tgt)
            summaries.append(f"❌ {tgt}: ข้อผิดพลาดภายใน")
            continue
        summaries.append(recon.summary_line(report))
        if report.get("ok"):
            await _send_files(context, chat_id, _report_files(report, fmt, tgt))

    try:
        await status.edit_text("✅ เสร็จสิ้น:\n" + "\n".join(summaries[:40]))
    except Exception:
        await msg.reply_text("✅ เสร็จสิ้น:\n" + "\n".join(summaries[:40]))
