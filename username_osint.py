"""
username_osint.py — ค้นบัญชีผู้ใช้ข้ามเว็บไซต์ (username enumeration)

รวมความสามารถของ sites.py / checkings.py / maigret.py ให้เรียกใช้ได้จริงจาก
app.py, search.py, scrape.py และ coordinator.py

ทำไมไม่ import สามไฟล์นั้นตรงๆ
--------------------------------
ทั้งสามไฟล์เป็นสำเนาซอร์สของแพ็กเกจ maigret ที่ถูกดึงออกมาวางเดี่ยวๆ ที่ราก
โปรเจกต์ ซึ่งทำให้ใช้งานไม่ได้เลยด้วยสามเหตุผลพร้อมกัน:

  1. ใช้ relative import (sites.py: `from .utils import ...`,
     checkings.py: `from . import errors`) ซึ่งต้องอยู่ในแพ็กเกจเท่านั้น
     -> ImportError: attempted relative import with no known parent package
  2. ต้องมีโมดูลพี่น้องอีกสิบกว่าไฟล์ (utils, errors, activation, result,
     report, notify, submit, settings, __version__) ที่ไม่ได้ถูกคัดลอกมาด้วย
  3. ต้องมีแพ็กเกจภายนอกอีก 7 ตัวที่ไม่มีใน requirements.txt
     (aiodns, aiohttp, aiohttp_socks, alive_progress, curl_cffi,
     socid_extractor, maigret)

และ maigret.py ที่รากโปรเจกต์ยัง "บัง" แพ็กเกจ maigret ตัวจริงไว้ด้วย
(รากโปรเจกต์มาก่อน site-packages ใน sys.path) ต่อให้ติดตั้งแพ็กเกจจริงแล้ว
`import maigret` ก็ยังได้ไฟล์ที่พังอยู่ดี

โมดูลนี้จึงหยิบ "ของมีค่าจริง" ของสามไฟล์นั้นมาใช้ คือ **ฐานข้อมูลเว็บไซต์**
(resource/data.json ที่โปรเจกต์มีอยู่แล้ว — 4,990 เว็บ พร้อมกฎการตรวจ)
แล้วเขียนตัวตรวจใหม่บน requests + ThreadPoolExecutor ที่โปรเจกต์ใช้อยู่แล้ว
ผลคือได้ความสามารถเดียวกันโดยไม่ต้องเพิ่ม dependency ใดๆ และเข้ากันได้กับ
circuit breaker / budget / cache ที่มีอยู่

ใช้ยังไง
--------
    import username_osint as uo
    hits = uo.check_username("somchai")                  # [{site, url, profile, ...}]
    rows = uo.check_username_as_results("somchai")       # รูปแบบเดียวกับผลค้นหา
    await uo.check_username_async("somchai")
"""

import os
import re
import json
import time
import random
import logging
import threading
import asyncio
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import nethealth

logger = logging.getLogger("modbot.username")

# ---------------- Config ----------------

_HERE = os.path.dirname(os.path.abspath(__file__))

USERNAME_DB_PATH = os.getenv("USERNAME_DB_PATH", "").strip()
USERNAME_MAX_SITES = nethealth.env_int("USERNAME_MAX_SITES", 60)
USERNAME_MAX_WORKERS = nethealth.env_int("USERNAME_MAX_WORKERS", 16)
USERNAME_BUDGET_SECONDS = nethealth.env_float("USERNAME_BUDGET_SECONDS", 30)
USERNAME_CONNECT_TIMEOUT = nethealth.env_float("USERNAME_CONNECT_TIMEOUT", 4)
USERNAME_READ_TIMEOUT = nethealth.env_float("USERNAME_READ_TIMEOUT", 8)
USERNAME_ENABLED = nethealth.env_bool("USERNAME_ENUM_ENABLED", "true")
# อ่านเนื้อหาแค่พอให้ตรวจ absenceStrs/presenseStrs ไม่ต้องโหลดทั้งหน้า
USERNAME_MAX_BODY_BYTES = nethealth.env_int("USERNAME_MAX_BODY_BYTES", 65536)
# แท็กที่มีคุณค่าเชิงตัวตนสูง ใช้จัดลำดับเมื่อไม่มีในรายการหลัก
USERNAME_PREFERRED_TAGS = ("social", "coding", "tech", "photo", "music",
                           "video", "gaming", "blog", "forum", "business")

# เว็บที่ตรวจก่อนเสมอ — ชื่อตรงตามที่ปรากฏใน resource/data.json
PRIORITY_SITES = (
    "GitHub", "Twitter", "Instagram", "Facebook", "TikTok", "Reddit", "YouTube",
    "Telegram", "Pinterest", "Medium", "Twitch", "Steam", "SoundCloud", "Spotify",
    "VK", "Flickr", "Vimeo", "GitLab", "Keybase", "HackerNews", "Patreon",
    "About.me", "Behance", "Dribbble", "DeviantART", "Blogger", "WordPress",
    "Tumblr", "Quora", "Wattpad", "Roblox", "Duolingo", "last.fm", "SlideShare",
    "Xbox Gamertag", "Xing", "Kick", "Discord",
)

# map ชื่อเว็บ -> คีย์แพลตฟอร์มที่ osint.extract_profiles() ใช้
# เพื่อให้บัญชีที่เจอจากที่นี่ กับที่เจอจากการ scrape หน้าเว็บ เทียบกันได้
PLATFORM_KEYS = {
    "github": "github", "twitter": "x", "x": "x", "instagram": "instagram",
    "facebook": "facebook", "tiktok": "tiktok", "youtube": "youtube",
    "telegram": "telegram", "linkedin": "linkedin", "pantip": "pantip",
}

_RE_USERNAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{2,31}$")

_db_lock = threading.Lock()
_db_cache: Optional[List["SiteEntry"]] = None
_thread_local = threading.local()


@dataclass
class SiteEntry:
    """หนึ่งเว็บไซต์ในฐานข้อมูล — เทียบเท่า MaigretSite ใน sites.py
    แต่เก็บเฉพาะฟิลด์ที่ตัวตรวจของเราต้องใช้จริง"""
    name: str
    url_template: str
    url_main: str = ""
    check_type: str = "status_code"
    absence_strs: List[str] = field(default_factory=list)
    presence_strs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    rank: int = 0

    @property
    def platform_key(self) -> str:
        """คีย์ที่ใช้เทียบกับโปรไฟล์ที่สกัดได้จากหน้าเว็บ"""
        host = (urlparse(self.url_main or self.url_template).hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        base = host.split(".")[0] if host else self.name.lower()
        return PLATFORM_KEYS.get(base, base)

    def url_for(self, username: str) -> str:
        return self.url_template.replace("{username}", username)


# ---------------- ฐานข้อมูลเว็บไซต์ (แทน sites.MaigretDatabase) ----------------

def _db_candidates() -> List[str]:
    """ที่ที่จะไปหา data.json ตามลำดับ — ของโปรเจกต์มาก่อนเสมอ"""
    paths = []
    if USERNAME_DB_PATH:
        paths.append(USERNAME_DB_PATH)
    paths.append(os.path.join(_HERE, "resource", "data.json"))
    try:  # ถ้าเครื่องมีแพ็กเกจ maigret ติดตั้งไว้ ก็ใช้ของมันเป็นตัวสำรองได้
        import site as _site
        for sp in _site.getsitepackages():
            paths.append(os.path.join(sp, "maigret", "resources", "data.json"))
    except Exception:
        pass
    return paths


def _normalize(name: str, record: dict) -> Optional[SiteEntry]:
    url = str(record.get("url") or "")
    if "{username}" not in url:
        return None
    # เว็บที่ต้องล็อกอิน/ต้องมีคุกกี้ ตรวจแบบไม่มี session ไม่ได้ผล ข้ามไป
    if record.get("activation") or record.get("headers", {}).get("Authorization"):
        return None
    check_type = str(record.get("checkType") or "status_code")
    if check_type not in ("status_code", "message", "response_url"):
        check_type = "status_code"
    try:
        rank = int(record.get("alexaRank") or 0)
    except (TypeError, ValueError):
        rank = 0
    return SiteEntry(
        name=name,
        url_template=url,
        url_main=str(record.get("urlMain") or ""),
        check_type=check_type,
        absence_strs=[str(x) for x in (record.get("absenceStrs") or [])],
        presence_strs=[str(x) for x in (record.get("presenseStrs") or [])],
        tags=[str(t) for t in (record.get("tags") or [])],
        rank=rank,
    )


def load_sites(force: bool = False) -> List[SiteEntry]:
    """โหลดฐานข้อมูลเว็บไซต์ (แคชไว้ — ไฟล์ 2MB ไม่ควร parse ซ้ำทุกครั้ง)
    เรียงลำดับตามคุณค่าเชิงตัวตน: รายการหลักก่อน แล้วตามอันดับความนิยม
    แล้วจึงตามแท็กที่เกี่ยวกับตัวตน"""
    global _db_cache
    with _db_lock:
        if _db_cache is not None and not force:
            return _db_cache

        raw = None
        for path in _db_candidates():
            try:
                with open(path, encoding="utf-8") as handle:
                    raw = json.load(handle)
                logger.info("USERNAME DB | โหลดจาก %s", path)
                break
            except (OSError, ValueError) as exc:
                logger.debug("USERNAME DB | อ่าน %s ไม่ได้: %s", path, exc)

        if raw is None:
            logger.warning("USERNAME DB | ไม่พบ data.json — ปิดการค้นบัญชีข้ามเว็บ")
            _db_cache = []
            return _db_cache

        records = raw.get("sites", raw)
        entries = []
        for name, record in records.items():
            if not isinstance(record, dict):
                continue
            entry = _normalize(name, record)
            if entry is not None:
                entries.append(entry)

        priority = {name: i for i, name in enumerate(PRIORITY_SITES)}
        tag_rank = {tag: i for i, tag in enumerate(USERNAME_PREFERRED_TAGS)}

        def sort_key(entry: SiteEntry):
            return (
                priority.get(entry.name, len(priority)),
                min((tag_rank.get(t, 99) for t in entry.tags), default=99),
                entry.rank or 10 ** 9,
                entry.name.lower(),
            )

        entries.sort(key=sort_key)
        _db_cache = entries
        logger.info("USERNAME DB | ใช้งานได้ %d เว็บไซต์", len(entries))
        return _db_cache


def get_site(name: str) -> Optional[SiteEntry]:
    """หาเว็บตามชื่อ — เทียบเท่า MaigretDatabase.get_site()"""
    target = str(name).lower()
    for entry in load_sites():
        if entry.name.lower() == target:
            return entry
    return None


def search_sites(tags=None, limit: int = 0) -> List[SiteEntry]:
    """คัดเว็บตามแท็ก — เทียบเท่าการกรองด้วย tags ใน MaigretDatabase"""
    entries = load_sites()
    if tags:
        wanted = {str(t).lower() for t in tags}
        entries = [e for e in entries if wanted & {t.lower() for t in e.tags}]
    return entries[:limit] if limit else entries


def is_plausible_username(value: str) -> bool:
    """กันไม่ให้เอาชื่อคนไทยหรือประโยคไปยิงใส่ 60 เว็บโดยเปล่าประโยชน์
    (เทียบเท่า maigret.utils.is_plausible_username)"""
    value = str(value or "").strip()
    if not _RE_USERNAME_OK.match(value):
        return False
    if value.isdigit():
        return False
    return True


# ---------------- ตัวตรวจ (แทน checkings.py) ----------------

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
)

FOUND, NOT_FOUND, UNKNOWN = "found", "not_found", "unknown"


def _session():
    """session ต่อ thread — requests.Session ไม่ thread-safe"""
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        retry = Retry(total=1, read=0, connect=1, backoff_factor=0.3,
                      status_forcelist=[500, 502, 503, 504],
                      allowed_methods=frozenset(["GET", "HEAD"]),
                      raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _thread_local.session = session
    return session


def _timeout_for(deadline):
    connect, read = USERNAME_CONNECT_TIMEOUT, USERNAME_READ_TIMEOUT
    if deadline is not None:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        connect = min(connect, max(left, 1.0))
        read = min(read, max(left, 1.0))
    return (connect, read)


def _read_body(response, limit=None):
    limit = limit or USERNAME_MAX_BODY_BYTES
    chunks, size = [], 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    raw = b"".join(chunks)
    return raw.decode(response.encoding or "utf-8", errors="replace")


def _decide(entry: SiteEntry, response, body, expected_url: str) -> str:
    """ตัดสินว่าบัญชีนี้มีอยู่จริงไหม ตามกฎของแต่ละเว็บในฐานข้อมูล
    (ตรรกะเดียวกับ process_site_result() ใน checkings.py)"""
    status = response.status_code

    if entry.check_type == "status_code":
        if status in (404, 410):
            return NOT_FOUND
        return FOUND if 200 <= status < 300 else UNKNOWN

    if entry.check_type == "response_url":
        if status in (404, 410):
            return NOT_FOUND
        if not (200 <= status < 400):
            return UNKNOWN
        final = (response.url or "").rstrip("/").lower()
        return FOUND if final == expected_url.rstrip("/").lower() else NOT_FOUND

    # checkType == "message": ดูข้อความในหน้าเป็นหลัก
    if status in (404, 410) and not entry.presence_strs:
        return NOT_FOUND
    lowered = (body or "").lower()
    if any(marker.lower() in lowered for marker in entry.absence_strs):
        return NOT_FOUND
    if entry.presence_strs:
        return FOUND if any(m.lower() in lowered for m in entry.presence_strs) else NOT_FOUND
    return FOUND if 200 <= status < 300 else UNKNOWN


def check_site(entry: SiteEntry, username: str, deadline=None) -> dict:
    """ตรวจ 1 เว็บ — ไม่ raise ออกไปหา caller เด็ดขาด"""
    url = entry.url_for(username)
    result = {"site": entry.name, "url": url, "status": UNKNOWN,
              "platform": entry.platform_key, "tags": list(entry.tags)}

    site_key = f"site:{entry.name}"
    if nethealth.blocked(site_key):
        result["status"] = UNKNOWN
        result["error"] = "cooldown"
        return result

    timeout = _timeout_for(deadline)
    if timeout is None:
        result["error"] = "budget"
        return result

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
    }
    response = None
    try:
        need_body = entry.check_type == "message"
        # ต้องตาม redirect เสมอ รวมถึง checkType == "response_url" ด้วย
        # เพราะกฎของมันคือ "ปลายทางสุดท้ายยังเป็นหน้าโปรไฟล์อยู่ไหม"
        # ถ้าไม่ตาม จะได้ response.url เท่ากับที่ขอไปเสมอ แล้วตัดสินว่า "เจอ" ผิดทุกครั้ง
        response = _session().get(
            url, headers=headers, timeout=timeout, stream=True, allow_redirects=True,
        )
        body = _read_body(response) if need_body else ""
        result["status"] = _decide(entry, response, body, url)
        result["http_status"] = response.status_code
        nethealth.record(site_key, True, nethealth.ENGINE_FAILURE_THRESHOLD)
    except requests.RequestException as exc:
        result["error"] = type(exc).__name__
        nethealth.record(site_key, False, nethealth.ENGINE_FAILURE_THRESHOLD)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if response is not None:
            response.close()
    return result


def check_username(username: str, max_sites: int = 0, budget_seconds: float = 0,
                   tags=None, sites=None) -> List[dict]:
    """ค้นว่าชื่อบัญชีนี้มีอยู่บนเว็บไหนบ้าง — คืนเฉพาะที่ "เจอ"

    เทียบเท่า maigret.search() แต่ทำงานบน requests + ThreadPoolExecutor
    ที่โปรเจกต์ใช้อยู่แล้ว จึงไม่ต้องเพิ่ม dependency และเข้ากับ circuit
    breaker / budget เดิมได้ทันที
    """
    username = str(username or "").strip()
    if not USERNAME_ENABLED or not is_plausible_username(username):
        return []

    entries = list(sites) if sites else search_sites(tags)
    entries = entries[: (max_sites or USERNAME_MAX_SITES)]
    if not entries:
        return []

    budget = float(budget_seconds) if budget_seconds else USERNAME_BUDGET_SECONDS
    started = time.monotonic()
    deadline = started + budget
    workers = max(1, min(USERNAME_MAX_WORKERS, len(entries)))

    hits, checked = [], 0
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [executor.submit(check_site, e, username, deadline) for e in entries]
        try:
            for future in as_completed(futures, timeout=budget):
                try:
                    result = future.result()
                except Exception as exc:
                    logger.debug("USERNAME WORKER CRASHED | %s", exc)
                    continue
                checked += 1
                if result.get("status") == FOUND:
                    hits.append(result)
        except FuturesTimeout:
            logger.warning("USERNAME BUDGET TIMEOUT | user=%r checked=%d/%d",
                           username, checked, len(entries))
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    logger.info(
        "USERNAME DONE | user=%r เจอ %d จาก %d เว็บที่ตรวจ (ทั้งหมด %d) elapsed=%.1fs",
        username, len(hits), checked, len(entries), time.monotonic() - started,
    )
    return hits


# ---------------- ตัวเชื่อมเข้ากับท่อ OSINT เดิม ----------------

def check_username_as_results(username: str, max_sites: int = 0,
                              budget_seconds: float = 0, tags=None) -> List[dict]:
    """คืนผลในรูปแบบเดียวกับผลค้นหาของ search.py

    ทำแบบนี้เพื่อให้บัญชีที่เจอไหลเข้าท่อเดิมได้ทั้งสาย: merge_and_rank ->
    scrape -> verify_sources -> build_identity โดยไม่ต้องแก้อะไรปลายทางเลย
    โปรไฟล์ที่เจอจึงถูกดึงเนื้อหา ตรวจว่าพูดถึงเป้าหมายจริงไหม และถูกนับ
    corroboration เหมือนแหล่งอื่นทุกประการ
    """
    rows = []
    for hit in check_username(username, max_sites, budget_seconds, tags):
        rows.append({
            "title": f"{hit['site']}: บัญชี {username}",
            "link": hit["url"],
            "origin": "username",
            "engine": hit["site"],
        })
    return rows


async def check_username_async(username: str, max_sites: int = 0,
                               budget_seconds: float = 0, tags=None) -> List[dict]:
    """เวอร์ชัน async สำหรับ handler ของ app.py — ข้างในเป็น requests
    แบบ blocking ถ้าเรียกบน event loop ตรงๆ บอทจะค้างทั้งตัว"""
    return await asyncio.to_thread(check_username, username, max_sites, budget_seconds, tags)


async def check_username_as_results_async(username: str, max_sites: int = 0,
                                          budget_seconds: float = 0, tags=None) -> List[dict]:
    return await asyncio.to_thread(
        check_username_as_results, username, max_sites, budget_seconds, tags
    )


def profiles_from_hits(hits: List[dict]) -> List[str]:
    """แปลงผลเป็นรูปแบบ 'platform:handle' ที่ osint.build_identity() ใช้
    เพื่อให้บัญชีที่เจอจากที่นี่ กับที่เจอจากการ scrape หน้าเว็บ เป็นตัวเดียวกัน"""
    out, seen = [], set()
    for hit in hits:
        platform = hit.get("platform") or ""
        url = hit.get("url") or ""
        handle = url.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
        if not platform or not handle:
            continue
        value = f"{platform}:{handle}"
        if value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out


def format_username_report(username: str, hits: List[dict], limit: int = 30) -> str:
    """ข้อความพร้อมส่งเข้า gemini.split_telegram_message() ของ app.py"""
    if not is_plausible_username(username):
        return (f"'{username}' ไม่ใช่รูปแบบชื่อบัญชีที่ค้นได้\n"
                "ชื่อบัญชีต้องเป็นอักษรละติน 3-32 ตัว (ใส่ . _ - ได้)")
    if not hits:
        return f"ไม่พบบัญชีชื่อ {username} บนเว็บที่ตรวจ"

    lines = [f"พบบัญชี {username} บน {len(hits)} เว็บ", ""]
    for index, hit in enumerate(hits[:limit], start=1):
        tags = ", ".join(hit.get("tags", [])[:3])
        lines.append(f"{index}. {hit['site']}{f' [{tags}]' if tags else ''}")
        lines.append(f"   {hit['url']}")
    if len(hits) > limit:
        lines.append(f"... และอีก {len(hits) - limit} เว็บ")
    lines.append("")
    lines.append("การมีชื่อบัญชีตรงกันไม่ได้แปลว่าเป็นคนเดียวกันเสมอไป")
    lines.append("ใช้ /identity เพื่อให้ระบบดึงเนื้อหาและตรวจการยืนยันข้ามแหล่งต่อ")
    return "\n".join(lines)


def stats() -> dict:
    """สถานะโมดูล ใช้ใน log ตอนบูตและตอน debug"""
    entries = load_sites()
    return {
        "enabled": USERNAME_ENABLED,
        "sites_loaded": len(entries),
        "sites_checked_per_run": min(USERNAME_MAX_SITES, len(entries)),
        "budget_seconds": USERNAME_BUDGET_SECONDS,
    }
