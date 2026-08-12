"""
news.py — Phase 7: News Auto Forwarder

Watches configured RSS/Atom feeds (or, as a fallback, a listing page to
scrape) for new articles and forwards them to a Telegram chat/channel,
optionally summarized by Gemini.

Responsibilities (and only these):
  - Fetch feeds/pages over HTTP asynchronously (httpx) so the bot's event
    loop is never blocked by a slow/unresponsive news site.
  - Parse RSS/Atom via feedparser (in-memory, no network call inside
    feedparser itself); fall back to HTML scraping (BeautifulSoup +
    OpenGraph metadata) when a source has no feed.
  - Track which articles have already been forwarded (news_seen_items
    table) so restarts and repeated polling never re-send the same item,
    and so a source's first-ever check doesn't dump its whole backlog.
  - Format and send new articles to that source's configured chat_id.

news.py never touches Security/Quota/Analytics tables, never decides
moderation actions, and reuses gemini.ask_gemini() / split_telegram_message()
instead of standing up a second AI client. Matches the sqlite-per-module /
xxx_db_init() pattern already used by security.py / quota.py / analytics.py.
"""

import os
import time
import logging
import asyncio
import sqlite3
from dataclasses import dataclass
from typing import Optional, List
from urllib.parse import urljoin, urlparse

import httpx
import feedparser
from bs4 import BeautifulSoup

from telegram.error import TelegramError
from telegram.constants import ParseMode

from gemini import split_telegram_message

logger = logging.getLogger("modbot.news")

DB_PATH = "bot.db"

# ---------------- Config ----------------

HTTP_TIMEOUT_SECONDS = float(os.getenv("NEWS_HTTP_TIMEOUT", "15"))
CHECK_INTERVAL_DEFAULT = int(os.getenv("NEWS_CHECK_INTERVAL", "600"))
MAX_ITEMS_PER_CYCLE_DEFAULT = int(os.getenv("NEWS_MAX_ITEMS_PER_CYCLE", "5"))
SEND_BACKLOG_ON_FIRST_RUN = os.getenv("NEWS_SEND_BACKLOG_ON_FIRST_RUN", "false").lower() == "true"
AI_SUMMARY_MAX_CHARS = int(os.getenv("NEWS_AI_SUMMARY_MAX_CHARS", "600"))

_HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; NewsForwarderBot/1.0)"}

# System instruction used ONLY for news summaries — deliberately separate
# from gemini.GEMINT_PERSONA (the /ask persona), since forwarded news
# shouldn't carry that persona's tone into an automated news feed.
_NEWS_SUMMARY_INSTRUCTION = (
    "คุณเป็นนักเขียนข่าวมืออาชีพ สรุปข่าวที่ได้รับเป็นภาษาไทยแบบกระชับ เป็นกลาง "
    "ไม่ใส่ความคิดเห็นส่วนตัว ไม่ใช้คำหยาบ ความยาวไม่เกิน 4-5 บรรทัด"
)

# เพิ่มเว็บไซต์ข่าวใหม่ได้ที่นี่ — copy 1 dict ด้านล่างแล้วแก้ค่า ไม่ต้องแก้โค้ดส่วนอื่นของไฟล์นี้
# feed_url ใช้ก่อนเสมอถ้ามี (RSS/Atom); ถ้าไม่มีค่อย fallback ไป page_url (web scraping)
# chat_id อ่านจาก env var เสมอ ไม่ hard-code ปลายทางไว้ในโค้ด
NEWS_SOURCES = [
    {
        "name": "sanooknews",                                    # unique — ใช้กัน duplicate ต่อแหล่งข่าว
        "feed_url": os.getenv("NEWS_FEED_URL_SANOOKNEWS", ""),
        "page_url": os.getenv("NEWS_PAGE_URL_SANOOKNEWS", "https://www.sanook.com/news/"),
        "chat_id": int(os.getenv("NEWS_CHAT_ID_SANOOKNEWS", "0") or 0),
        "topic_id": int(os.getenv("NEWS_TOPIC_ID_SANOOKNEWS", "0") or 0) or None,
        "ai_summary": True,
        "max_items_per_cycle": 5,
    },
    {
        "name": "prachatai",
        "feed_url": os.getenv("NEWS_FEED_URL_PRACHATAI", ""),
        " page_url": os.getenv("NEWS_PAGE_URL_PRACHATAI", "https://prachatai.com"),
        "chat_id": int(os.getenv("NEWS_CHAT_ID_PRACHATAI", "0") or 0),
        "topic_id": int(os.getenv("NEWS_TOPIC_ID_PRACHATAI", "0") or 0) or None,
        "ai_summary": True,
        "max_items_per_cycle": 5,
    },
]


@dataclass
class NewsItem:
    source_name: str
    item_key: str            # url หรือ feed guid — ใช้กัน duplicate
    title: str
    url: str
    summary: str = ""
    image_url: Optional[str] = None


def _escape_html(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def news_db_init():
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS news_seen_items (
        source_name TEXT NOT NULL,
        item_key TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (source_name, item_key)
    )""")
    conn.commit()
    conn.close()
    logger.info("NEWS DATABASE: OK")


def _is_seen(conn, source_name: str, item_key: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM news_seen_items WHERE source_name=? AND item_key=?",
        (source_name, item_key),
    ).fetchone()
    return row is not None


def _mark_seen(conn, source_name: str, item_key: str, now: int):
    conn.execute(
        "INSERT OR IGNORE INTO news_seen_items (source_name, item_key, seen_at) VALUES (?, ?, ?)",
        (source_name, item_key, now),
    )


def _has_any_seen(conn, source_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM news_seen_items WHERE source_name=? LIMIT 1", (source_name,)
    ).fetchone()
    return row is not None


# ---------------- HTTP ----------------

async def _fetch_bytes(client: httpx.AsyncClient, url: str) -> Optional[bytes]:
    try:
        resp = await client.get(url, follow_redirects=True)
        resp.raise_for_status()
        return resp.content
    except httpx.HTTPError as e:
        logger.warning(f"NEWS FETCH ERROR | url={url} | {e}")
        return None


# ---------------- RSS/Atom path (preferred) ----------------

async def _fetch_rss_items(client: httpx.AsyncClient, feed_url: str, source_name: str) -> List[NewsItem]:
    raw = await _fetch_bytes(client, feed_url)
    if raw is None:
        return []
    try:
        parsed = await asyncio.to_thread(feedparser.parse, raw)
    except Exception:
        logger.exception(f"NEWS RSS PARSE ERROR | source={source_name}")
        return []

    items = []
    for entry in parsed.entries:
        url = entry.get("link") or ""
        if not url:
            continue
        item_key = entry.get("id") or url
        title = (entry.get("title") or "").strip()
        summary_raw = entry.get("summary") or entry.get("description") or ""
        items.append(NewsItem(
            source_name=source_name,
            item_key=item_key,
            title=title,
            url=url,
            summary=_strip_html(summary_raw)[:1000],
            image_url=_extract_feed_image(entry),
        ))
    return items


def _extract_feed_image(entry) -> Optional[str]:
    media = entry.get("media_content") or entry.get("media_thumbnail")
    if media:
        url = media[0].get("url")
        if url:
            return url
    for link in entry.get("links", []):
        if str(link.get("type", "")).startswith("image/"):
            return link.get("href")
    return None


def _strip_html(html: str) -> str:
    if not html:
        return ""
    try:
        return BeautifulSoup(html, "html.parser").get_text(separator=" ", strip=True)
    except Exception:
        return html


# ---------------- Web-scraping fallback (no RSS available) ----------------
# Heuristic/best-effort: works well for sites that expose OpenGraph tags on
# article pages (most news sites do). Prefer configuring feed_url when
# possible — this path only exists for sources with no RSS/Atom feed.

async def _fetch_page_items(
    client: httpx.AsyncClient, page_url: str, source_name: str, max_links: int
) -> List[NewsItem]:
    raw = await _fetch_bytes(client, page_url)
    if raw is None:
        return []
    try:
        candidate_links = await asyncio.to_thread(
            _discover_article_links, raw, page_url, max_links * 3
        )
    except Exception:
        logger.exception(f"NEWS LISTING PARSE ERROR | source={source_name}")
        return []

    # Skip links we've already forwarded before spending an HTTP request on them.
    conn = _conn()
    unseen_links = [u for u in candidate_links if not _is_seen(conn, source_name, u)][:max_links]
    conn.close()

    items = []
    for url in unseen_links:
        article_raw = await _fetch_bytes(client, url)
        if article_raw is None:
            continue
        try:
            meta = await asyncio.to_thread(_extract_article_metadata, article_raw)
        except Exception:
            logger.exception(f"NEWS ARTICLE PARSE ERROR | url={url}")
            continue
        if not meta.get("title"):
            continue
        items.append(NewsItem(
            source_name=source_name, item_key=url, title=meta["title"], url=url,
            summary=meta.get("summary", ""), image_url=meta.get("image_url"),
        ))
    return items


def _discover_article_links(html: bytes, base_url: str, max_links: int) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    base_domain = urlparse(base_url).netloc
    seen, links = set(), []
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        parsed = urlparse(href)
        if parsed.netloc != base_domain or href in seen:
            continue
        path = parsed.path.rstrip("/")
        # heuristic: skip home/category pages and static assets, keep likely article URLs
        if len(path) < 8 or path.count("/") < 2:
            continue
        if any(path.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".css", ".js", ".pdf")):
            continue
        seen.add(href)
        links.append(href)
        if len(links) >= max_links:
            break
    return links


def _extract_article_metadata(html: bytes) -> dict:
    soup = BeautifulSoup(html, "html.parser")

    def _meta(*names):
        for name in names:
            tag = soup.find("meta", property=name) or soup.find("meta", attrs={"name": name})
            if tag and tag.get("content"):
                return tag["content"].strip()
        return None

    title = _meta("og:title") or (soup.title.get_text(strip=True) if soup.title else "")
    return {
        "title": title,
        "summary": _meta("og:description", "description") or "",
        "image_url": _meta("og:image"),
    }


# ---------------- AI summary (reuses gemini.ask_gemini — no new AI client) ----------------

async def _summarize(item: NewsItem) -> str:
    from gemini import ask_gemini  # lazy import: only paid when ai_summary is actually on
    prompt = f"หัวข้อ: {item.title}\n\nเนื้อหา: {item.summary}"
    ok, text = await ask_gemini(prompt, system_instruction=_NEWS_SUMMARY_INSTRUCTION)
    if not ok:
        logger.warning(f"NEWS AI SUMMARY FAILED | url={item.url} | {text}")
        return item.summary[:AI_SUMMARY_MAX_CHARS]
    return text[:AI_SUMMARY_MAX_CHARS]


# ---------------- Sending ----------------

async def _send_item(bot, chat_id: int, item: NewsItem, message_thread_id: Optional[int] = None):
    caption = (
        f"📰 ข่าวใหม่\n\n"
        f"<b>{_escape_html(item.title)}</b>\n\n"
        f"{_escape_html(item.summary)}\n\n"
        f"🔗 อ่านข่าวต้นฉบับ:\n{item.url}"
    )
    if item.image_url:
        chunks = split_telegram_message(caption, limit=1024)
        await bot.send_photo(
            chat_id, photo=item.image_url, caption=chunks[0],
            parse_mode=ParseMode.HTML, message_thread_id=message_thread_id,
        )
        for extra in chunks[1:]:
            await bot.send_message(
                chat_id, extra, parse_mode=ParseMode.HTML, message_thread_id=message_thread_id,
            )
    else:
        for chunk in split_telegram_message(caption):
            await bot.send_message(
                chat_id, chunk, parse_mode=ParseMode.HTML, message_thread_id=message_thread_id,
            )


# ---------------- Per-source cycle ----------------

async def _check_one_source(client: httpx.AsyncClient, bot, source: dict):
    name = source["name"]

    topic_id = source.get("topic_id") or None
    for item in new_items:
        try:
            if source.get("ai_summary", True):
                item.summary = await _summarize(item)
            await _send_item(bot, chat_id, item, message_thread_id=topic_id)
            logger.info(f"NEWS SENT | source={name} | url={item.url} | topic_id={topic_id}")
        except TelegramError as e:
            logger.warning(f"NEWS TELEGRAM SEND ERROR | source={name} | url={item.url} | {e}")
        except Exception:
            logger.exception(f"NEWS SEND ERROR | source={name} | url={item.url}")
            
    chat_id = source.get("chat_id") or 0
    if not chat_id:
        logger.warning(f"NEWS SOURCE SKIPPED | source={name} | reason=no chat_id configured")
        return

    if source.get("feed_url"):
        items = await _fetch_rss_items(client, source["feed_url"], name)
    elif source.get("page_url"):
        max_items = source.get("max_items_per_cycle", MAX_ITEMS_PER_CYCLE_DEFAULT)
        items = await _fetch_page_items(client, source["page_url"], name, max_items)
    else:
        logger.warning(f"NEWS SOURCE SKIPPED | source={name} | reason=no feed_url or page_url configured")
        return

    conn = _conn()
    first_run = not _has_any_seen(conn, name)
    now = int(time.time())
    new_items = []
    for item in items:
        if _is_seen(conn, name, item.item_key):
            continue
        if first_run and not SEND_BACKLOG_ON_FIRST_RUN:
            _mark_seen(conn, name, item.item_key, now)  # baseline only, don't send
            continue
        new_items.append(item)
        _mark_seen(conn, name, item.item_key, now)
    conn.commit()
    conn.close()

    if first_run and not SEND_BACKLOG_ON_FIRST_RUN:
        logger.info(f"NEWS FIRST RUN | source={name} | baseline={len(items)} items marked seen, none sent")
        return

    max_items = source.get("max_items_per_cycle", MAX_ITEMS_PER_CYCLE_DEFAULT)
    new_items = new_items[:max_items]
    logger.info(f"NEWS CHECK | source={name} | found={len(items)} | new={len(new_items)}")

    for item in new_items:
        try:
            if source.get("ai_summary", True):
                item.summary = await _summarize(item)
            await _send_item(bot, chat_id, item)
            logger.info(f"NEWS SENT | source={name} | url={item.url}")
        except TelegramError as e:
            logger.warning(f"NEWS TELEGRAM SEND ERROR | source={name} | url={item.url} | {e}")
        except Exception:
            logger.exception(f"NEWS SEND ERROR | source={name} | url={item.url}")


async def run_news_check_cycle(bot):
    """One pass over every configured source. Each source's errors are
    caught independently — one dead/broken site never stops the others
    or crashes the main bot."""
    async with httpx.AsyncClient(headers=_HTTP_HEADERS, timeout=HTTP_TIMEOUT_SECONDS) as client:
        for source in NEWS_SOURCES:
            try:
                await _check_one_source(client, bot, source)
            except Exception:
                logger.exception(f"NEWS CYCLE ERROR | source={source.get('name')}")


async def news_background_loop(bot):
    """Started from app.py's post_init as an asyncio task; cancelled in
    post_shutdown. Runs forever until cancelled — never blocks the bot's
    polling loop since it's a separate task on the same event loop."""
    await asyncio.sleep(5)  # let polling come up first
    while True:
        try:
            await run_news_check_cycle(bot)
        except Exception:
            logger.exception("NEWS BACKGROUND LOOP ERROR")
        await asyncio.sleep(CHECK_INTERVAL_DEFAULT)