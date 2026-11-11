# -*- coding: utf-8 -*-
"""autolink/loop.py — background loop ที่ยิงลิงก์อัตโนมัติ "ตลอดเวลา"

ตัวลูปเลียนแบบ news_background_loop ของโปรเจกต์ (asyncio while True + sleep):
ทุก TICK วินาที จะโหลด DB, หาแคมเปญที่ถึงเวลา, ส่งลิงก์, แล้วบันทึกผล
ต่อแคมเปญ (fresh load-modify-write) กัน lost-update กับคำสั่งที่ผู้ใช้แก้พร้อมกัน

ออกแบบให้ "ยืนยาว": ทุก path ห่อ try/except — ส่งห้องเดียวพังต้องไม่ล้มทั้งลูป
และเคารพ CancelledError เพื่อปิดสะอาดตอน shutdown (ผ่าน asyncio.sleep)
"""

from __future__ import annotations

import asyncio
import logging
import random

from . import store, engine

logger = logging.getLogger("modbot.autolink.loop")

# ตรวจทุกกี่วินาที (ควรละเอียดกว่า interval ที่สั้นสุดที่อนุญาต)
TICK_SECONDS = int(__import__("os").getenv("AUTOLINK_TICK", "15") or "15")


async def _send_one(bot, chat_id: str, campaign: dict) -> None:
    """ยิงลิงก์รอบเดียวให้แคมเปญหนึ่ง แล้วบันทึกผล"""
    link, next_cursor = engine.choose(campaign)
    # index ที่ใช้จริงรอบนี้ (ก่อน advance) ไว้โชว์ {n}
    links = campaign.get("links") or []
    try:
        shown_index = links.index(link)
    except ValueError:
        shown_index = int(campaign.get("cursor", 0)) % max(1, len(links))

    text = engine.render(campaign, link, shown_index)

    # jitter: หน่วงสุ่ม 0..jitter กันดูเป็นบอทยิงเป๊ะ ๆ (ถ้าตั้งไว้)
    jitter = int(campaign.get("jitter_sec", 0) or 0)
    if jitter > 0:
        await asyncio.sleep(random.uniform(0, jitter))

    await bot.send_message(
        chat_id=int(chat_id),
        text=text,
        disable_notification=bool(campaign.get("silent", False)),
        disable_web_page_preview=not bool(campaign.get("preview", True)),
    )

    # บันทึกผลแบบ fresh load-write (ปลอดภัยต่อการแก้พร้อมกัน)
    store.mark_ran(chat_id, campaign.get("id"), next_cursor)
    logger.info("AUTOLINK SENT | chat=%s campaign=%s url=%s",
                chat_id, campaign.get("id"), link.get("url"))


async def run_cycle(bot) -> None:
    """รอบตรวจเดียว: หาแคมเปญที่ถึงเวลาแล้วยิงทีละอัน"""
    now = store.utcnow()
    db = store.load()
    due = engine.due_campaigns(db, now)
    for chat_id, campaign in due:
        try:
            await _send_one(bot, chat_id, campaign)
        except asyncio.CancelledError:
            raise
        except Exception:
            # ส่งห้องเดียวพัง (บอทโดนเตะ/ลิงก์พัง/เน็ตล่ม) — log แล้วไปต่อ
            # แต่ "ขยับเวลา" ไว้กันวนยิงรัว ๆ ห้องที่ส่งไม่ได้
            logger.exception("AUTOLINK SEND FAILED | chat=%s campaign=%s",
                             chat_id, campaign.get("id"))
            try:
                store.mark_ran(chat_id, campaign.get("id"),
                               int(campaign.get("cursor", 0)))
            except Exception:
                logger.exception("AUTOLINK could not advance timer after failure")


async def autolink_background_loop(bot) -> None:
    """ลูปหลัก — เรียกจาก post_init ด้วย _start_background_task(...)"""
    await asyncio.sleep(5)  # ให้บอตบูตเสร็จก่อน
    logger.info("AUTOLINK LOOP STARTED | tick=%ss", TICK_SECONDS)
    while True:
        try:
            await run_cycle(bot)
        except asyncio.CancelledError:
            logger.info("AUTOLINK LOOP CANCELLED — stopping")
            raise
        except Exception:
            logger.exception("AUTOLINK BACKGROUND LOOP ERROR")
        await asyncio.sleep(TICK_SECONDS)
