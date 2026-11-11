# -*- coding: utf-8 -*-
"""broadcast/loop.py — background loop ที่ยิงลิงก์เดียวออกไปทุกปลายทาง ตลอดเวลา

เมื่อถึงรอบ: ส่งข้อความ (ลิงก์) ไปยัง target ทุกตัวที่ไม่ถูก mute ทีละตัว
มีการหน่วงระหว่างปลายทางกันชน flood limit ของ Telegram, เคารพ RetryAfter,
และ "ล้างปลายทางตาย" อัตโนมัติเมื่อบอตโดนบล็อก/เตะออก (Forbidden / chat ไม่พบ)

ทุก path ห่อ try/except — ปลายทางเดียวพังต้องไม่ล้มทั้งรอบ/ทั้งลูป
"""

from __future__ import annotations

import os
import asyncio
import logging

from . import store, core

logger = logging.getLogger("modbot.broadcast.loop")

TICK_SECONDS = int(os.getenv("BROADCAST_TICK", "30") or "30")

# import error classes ของ PTB แบบกันพัง (ตอนรันจริงมีครบ)
try:
    from telegram.error import TelegramError, Forbidden, BadRequest, RetryAfter
except Exception:  # pragma: no cover - เผื่อเทสต์ไม่มี telegram
    class TelegramError(Exception):
        pass

    class Forbidden(TelegramError):
        pass

    class BadRequest(TelegramError):
        pass

    class RetryAfter(TelegramError):
        retry_after = 0


# สัญญาณว่าปลายทาง "ตายถาวร" ควรลบทิ้งทันที ไม่ต้องรอสะสม fails
_PERMANENT_HINTS = (
    "bot was blocked", "user is deactivated", "chat not found",
    "bot was kicked", "peer_id_invalid", "chat_write_forbidden",
    "not enough rights", "bot is not a member", "group chat was deactivated",
    "need administrator rights",
)


def _is_permanent(exc: Exception) -> bool:
    msg = str(getattr(exc, "message", "") or exc).lower()
    return any(h in msg for h in _PERMANENT_HINTS)


async def _send_to_one(bot, target: dict, text: str, cfg: dict) -> bool:
    """ส่งข้อความไปปลายทางเดียว คืน True ถ้าสำเร็จ; บันทึกผล/ล้างตายให้เสร็จในตัว"""
    chat_id = target.get("chat_id")
    try:
        await bot.send_message(
            chat_id=chat_id,
            text=text,
            disable_notification=bool(cfg.get("silent", False)),
            disable_web_page_preview=not bool(cfg.get("preview", True)),
        )
        store.record_result(chat_id, ok=True)
        return True
    except RetryAfter as e:
        # โดน flood control — รอแล้วลองอีกครั้งเดียว
        wait = int(getattr(e, "retry_after", 1)) + 1
        logger.warning("BROADCAST flood wait %ss | chat=%s", wait, chat_id)
        await asyncio.sleep(min(wait, 60))
        try:
            await bot.send_message(
                chat_id=chat_id, text=text,
                disable_notification=bool(cfg.get("silent", False)),
                disable_web_page_preview=not bool(cfg.get("preview", True)),
            )
            store.record_result(chat_id, ok=True)
            return True
        except Exception as e2:
            store.record_result(chat_id, ok=False, drop=_is_permanent(e2))
            return False
    except (Forbidden, BadRequest) as e:
        # ส่วนใหญ่คือถาวร (โดนบล็อก/เตะ/ห้องถูกลบ) -> ล้างทิ้ง
        drop = _is_permanent(e) or isinstance(e, Forbidden)
        logger.info("BROADCAST drop=%s | chat=%s | %s", drop, chat_id, e)
        store.record_result(chat_id, ok=False, drop=drop)
        return False
    except TelegramError as e:
        store.record_result(chat_id, ok=False, drop=_is_permanent(e))
        return False
    except Exception:
        logger.exception("BROADCAST unexpected send error | chat=%s", chat_id)
        store.record_result(chat_id, ok=False, drop=False)
        return False


async def send_to_all(bot, mark_ran: bool = True) -> dict:
    """ยิงข้อความปัจจุบันไปทุกปลายทางที่ไม่ถูก mute — คืนสถิติ {sent, failed, total}

    ใช้ได้ทั้งจากลูป (ตามรอบ) และจากคำสั่ง /broadcast now
    """
    db = store.load()
    cfg = db["config"]
    text = core.render(cfg)
    if not text.strip():
        return {"sent": 0, "failed": 0, "total": 0, "error": "ยังไม่ได้ตั้งลิงก์"}

    targets = store.list_targets(db, include_muted=False)
    total = len(targets)
    if total == 0:
        if mark_ran:
            store.mark_broadcast_ran()
        return {"sent": 0, "failed": 0, "total": 0, "error": "ยังไม่มีปลายทาง"}

    delay = max(0, int(cfg.get("per_send_delay_ms", 50))) / 1000.0
    sent = failed = 0
    for t in targets:
        try:
            ok = await _send_to_one(bot, t, text, cfg)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("BROADCAST loop send wrapper error | chat=%s",
                             t.get("chat_id"))
            ok = False
        sent += 1 if ok else 0
        failed += 0 if ok else 1
        if delay:
            await asyncio.sleep(delay)

    if mark_ran:
        store.mark_broadcast_ran()
    logger.info("BROADCAST CYCLE DONE | sent=%s failed=%s total=%s", sent, failed, total)
    return {"sent": sent, "failed": failed, "total": total}


async def run_cycle(bot) -> None:
    cfg = store.get_config()
    if core.is_due(cfg):
        await send_to_all(bot, mark_ran=True)


async def broadcast_background_loop(bot) -> None:
    """ลูปหลัก — เรียกจาก post_init ด้วย _start_background_task(...)"""
    await asyncio.sleep(7)
    logger.info("BROADCAST LOOP STARTED | tick=%ss", TICK_SECONDS)
    while True:
        try:
            await run_cycle(bot)
        except asyncio.CancelledError:
            logger.info("BROADCAST LOOP CANCELLED — stopping")
            raise
        except Exception:
            logger.exception("BROADCAST BACKGROUND LOOP ERROR")
        await asyncio.sleep(TICK_SECONDS)
