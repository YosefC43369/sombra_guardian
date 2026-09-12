import os
import socket
import time
import asyncio
import requests
import random, re
import json
import logging
import threading
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import quote_plus, urlparse, parse_qs, unquote

logger = logging.getLogger("modbot.search")

# Same env vars and defaults scrape.py already uses (scrape.py lines 46-47);
# this module referenced them without ever defining them.
TOR_SOCKS_HOST = os.getenv("TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))

TOR_GATEWAY_SUFFIXES = [
    s.strip() for s in os.getenv("TOR_GATEWAY_SUFFIXES", ".ly,.ps").split(",") if s.strip()
]


def _env_int(name, default):
    """อ่าน env แบบไม่ระเบิดถ้าค่าพัง — app.py โหลด .env ก่อน import โมดูลนี้
    ค่าที่พิมพ์ผิดใน .env ต้องไม่ทำให้บอททั้งตัว import ไม่ผ่าน"""
    try:
        return int(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        logger.warning("SEARCH CONFIG | %s is not an int, using default %s", name, default)
        return int(default)


def _env_float(name, default):
    try:
        return float(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        logger.warning("SEARCH CONFIG | %s is not a float, using default %s", name, default)
        return float(default)


# ---------------- Limits (app.py runs inside a Telegram handler: ทุกอย่างต้องมีเพดานเวลา) ----------------
# ก่อนหน้านี้ค่า timeout เดียวคือ 25s ต่อ 1 request แต่มี 16 engine x จำนวน gateway
# => worst case หลายนาที ทำให้ handler ของ app.py ค้างยาวจน Telegram หมดความอดทน
SEARCH_CONNECT_TIMEOUT = _env_float("SEARCH_CONNECT_TIMEOUT", 6)
SEARCH_READ_TIMEOUT = _env_float("SEARCH_READ_TIMEOUT", 15)
SEARCH_TOTAL_BUDGET_SECONDS = _env_float("SEARCH_TOTAL_BUDGET_SECONDS", 45)
SEARCH_MAX_WORKERS = _env_int("SEARCH_MAX_WORKERS", 8)
SEARCH_MAX_RESULTS = _env_int("SEARCH_MAX_RESULTS", 40)
SEARCH_MAX_RESULTS_PER_ENGINE = _env_int("SEARCH_MAX_RESULTS_PER_ENGINE", 10)
SEARCH_MIN_TITLE_CHARS = _env_int("SEARCH_MIN_TITLE_CHARS", 4)
SEARCH_MAX_TITLE_CHARS = _env_int("SEARCH_MAX_TITLE_CHARS", 200)
SEARCH_MAX_QUERY_CHARS = _env_int("SEARCH_MAX_QUERY_CHARS", 500)
# "auto" = ใช้ Tor ถ้า SOCKS port เปิดอยู่, "true"/"false" = บังคับ
SEARCH_USE_TOR = os.getenv("SEARCH_USE_TOR", "auto").strip().lower()
TOR_PROBE_TTL_SECONDS = _env_float("TOR_PROBE_TTL_SECONDS", 60)

_thread_local = threading.local()
_tor_probe_lock = threading.Lock()
_tor_probe_state = {"checked_at": 0.0, "reachable": False}


def _onion_to_gateway(url, suffix):
    """แปลง http://xxxxx.onion/path -> https://xxxxx.onion<suffix>/path"""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host.endswith(".onion"):
        return url
    netloc = host + suffix
    if parsed.port:
        netloc += f":{parsed.port}"
    return parsed._replace(scheme="https", netloc=netloc).geturl()


def _gateway_to_onion(url):
    """ตรงข้ามกับ _onion_to_gateway — หน้าเว็บที่ดึงผ่าน gateway มักเขียนลิงก์ผลลัพธ์
    เป็นโดเมน gateway (xxx.onion.ly) ถ้าปล่อยไว้ scrape.py จะมองว่าเป็นลิงก์ clearnet
    และ dedupe ก็จะไม่รู้ว่า xxx.onion กับ xxx.onion.ly คืออันเดียวกัน
    จึงต้องถอด suffix กลับเป็น .onion ให้เป็นรูปแบบมาตรฐานก่อนส่งต่อเสมอ"""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    for suffix in TOR_GATEWAY_SUFFIXES:
        if host.endswith(".onion" + suffix):
            netloc = host[: -len(suffix)]
            if parsed.port:
                netloc += f":{parsed.port}"
            return parsed._replace(scheme="http", netloc=netloc).geturl()
    return url


def is_tor_reachable(timeout=2.0, force=False) -> bool:
    """เช็คไวๆ ว่ามีอะไรฟังอยู่ที่ SOCKS port ไหม จะได้ fail เร็ว
    แทนที่จะ retry ครบทุก engine ทั้ง 16 ตัวโดยเปล่าประโยชน์เมื่อ Tor ไม่รัน
    ผล probe ถูก cache ไว้ TOR_PROBE_TTL_SECONDS วินาที เพราะ get_search_results()
    เรียกจากหลาย worker thread พร้อมกัน ไม่ควรเปิด socket ใหม่ทุกครั้ง"""
    now = time.monotonic()
    with _tor_probe_lock:
        if not force and (now - _tor_probe_state["checked_at"]) < TOR_PROBE_TTL_SECONDS:
            return _tor_probe_state["reachable"]
    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=timeout):
            reachable = True
    except OSError:
        reachable = False
    with _tor_probe_lock:
        _tor_probe_state["checked_at"] = time.monotonic()
        _tor_probe_state["reachable"] = reachable
    return reachable


def _tor_enabled() -> bool:
    if SEARCH_USE_TOR in ("false", "0", "off", "no"):
        return False
    if SEARCH_USE_TOR in ("true", "1", "on", "yes"):
        return True
    return is_tor_reachable()

import warnings
warnings.filterwarnings("ignore")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54"
]

SEARCH_ENGINES = [
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"},
    {"name": "Torgle", "url": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}"},
    {"name": "Amnesia", "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}"},
    {"name": "Kaizer", "url": "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}"},
    {"name": "Anima", "url": "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}"},
    {"name": "Tornado", "url": "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}"},
    {"name": "TorNet", "url": "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}"},
    {"name": "Torland", "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}"},
    {"name": "Find Tor", "url": "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}"},
    {"name": "Excavator", "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}"},
    {"name": "Onionway", "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"},
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"},
    {"name": "OSS", "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}"},
    {"name": "Torgol", "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "The Deep Searches", "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}"},
]

# Backward-compatible flat list used by existing search logic
DEFAULT_SEARCH_ENGINES = [e["url"] for e in SEARCH_ENGINES]

_ENGINE_NAME_BY_URL = {e["url"]: e["name"] for e in SEARCH_ENGINES}


def _build_onion_url_re():
    """regex เดิม (r'https?:\\/\\/[a-z0-9\\.]+\\.onion.*') มีสองปัญหา:
    (1) ไม่สนใจตัวพิมพ์ใหญ่ (2) '.*' กินท้ายยาวจนติดเครื่องหมายคำพูด/แท็กที่ตามมา
    และเมื่อดึงผ่าน gateway ลิงก์ในหน้าจะเป็น xxx.onion.ly ซึ่งต้องจับให้ครบ
    ทั้ง suffix ก่อน แล้วค่อยถอดกลับเป็น .onion ด้วย _gateway_to_onion()"""
    suffixes = [re.escape(s) for s in TOR_GATEWAY_SUFFIXES if s]
    suffix_group = "(?:" + "|".join(suffixes) + ")?" if suffixes else ""
    return re.compile(
        r"https?://(?:[a-z0-9\-]+\.)*[a-z0-9\-]{10,64}\.onion"
        + suffix_group
        + r"(?::\d+)?(?:/[^\s\"'<>\\]*)?",
        re.IGNORECASE,
    )


_ONION_URL_RE = _build_onion_url_re()
_REDIRECT_PARAM_KEYS = ("url", "u", "redirect", "r", "target", "link", "q")


def get_tor_session():
    session = requests.Session()
    retry = Retry(
        total=2,
        # read=0: read-timeout ต้องไม่ retry — ไม่งั้นเวลาจริงจะกลายเป็น
        # timeout x (retry+1) ทะลุ deadline ที่ _timeout_for() คำนวณไว้
        read=0,
        connect=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.proxies = {
        "http": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    }
    return session


def _build_direct_session():
    """session สำหรับ gateway (clearnet) — retry น้อยกว่า get_tor_session()
    เพราะ gateway ล่มถาวรบ่อยกว่าล่มชั่วคราว การ retry นานๆ คือการเสียเวลาเปล่า"""
    session = requests.Session()
    retry = Retry(
        total=1,
        read=0,
        connect=1,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _get_session(use_tor=False):
    """session แยกต่อ thread — requests.Session ไม่ thread-safe และ
    get_search_results() ยิงพร้อมกันหลาย worker"""
    key = "tor_session" if use_tor else "direct_session"
    session = getattr(_thread_local, key, None)
    if session is None:
        session = get_tor_session() if use_tor else _build_direct_session()
        setattr(_thread_local, key, session)
    return session


def _remaining(deadline):
    """เหลือเวลาอีกกี่วินาทีก่อนหมด budget (None = ไม่จำกัด)"""
    if deadline is None:
        return None
    return deadline - time.monotonic()


def _timeout_for(deadline):
    """คืน (connect, read) ที่ไม่มีทางเกินเวลาที่เหลือของ budget รวม"""
    read_timeout = SEARCH_READ_TIMEOUT
    connect_timeout = SEARCH_CONNECT_TIMEOUT
    left = _remaining(deadline)
    if left is not None:
        if left <= 0:
            return None
        read_timeout = min(read_timeout, max(left, 1.0))
        connect_timeout = min(connect_timeout, max(left, 1.0))
    return (connect_timeout, read_timeout)


def _clean_title(raw_title):
    title = " ".join((raw_title or "").split())
    return title[:SEARCH_MAX_TITLE_CHARS]


def _href_to_onion(href, base_host):
    """ดึง .onion URL จาก href หนึ่งอัน — รองรับทั้งลิงก์ตรงและลิงก์ที่ engine
    ห่อไว้ด้วย redirect (เช่น /redirect?url=http%3A%2F%2Fxxx.onion/)"""
    if not href:
        return None

    candidates = [href]
    if "%3a%2f%2f" in href.lower() or "%3A%2F%2F" in href:
        candidates.append(unquote(href))
    if "?" in href:
        try:
            params = parse_qs(urlparse(href).query)
        except ValueError:
            params = {}
        for key in _REDIRECT_PARAM_KEYS:
            for value in params.get(key, []):
                candidates.append(unquote(value))

    for candidate in candidates:
        match = _ONION_URL_RE.search(candidate)
        if not match:
            continue
        url = _gateway_to_onion(match.group(0).rstrip('.,);\'"'))
        host = (urlparse(url).hostname or "").lower()
        if not host or host == base_host:
            # ลิงก์ที่ชี้กลับหน้า engine เอง (paging / หน้าค้นหา) ไม่ใช่ผลลัพธ์
            continue
        return url
    return None


def _extract_links(html, base_url, limit):
    """แทน inline-parsing เดิมที่ใช้ `except:` เปล่าครอบทุกอย่าง
    (ซึ่งกลืน KeyboardInterrupt/SystemExit ไปด้วย) และคัดลิงก์ด้วย
    'search' not in link ซึ่งตัดผลลัพธ์จริงที่บังเอิญมีคำว่า search ทิ้งไปฟรีๆ"""
    soup = BeautifulSoup(html, "html.parser")
    base_host = (urlparse(_gateway_to_onion(base_url)).hostname or "").lower()

    links = []
    seen = set()
    for anchor in soup.find_all("a", href=True):
        url = _href_to_onion(anchor.get("href"), base_host)
        if not url:
            continue

        key = url.rstrip("/").lower()
        if key in seen:
            continue

        title = _clean_title(anchor.get_text(strip=True))
        if len(title) < SEARCH_MIN_TITLE_CHARS:
            # ยังไม่ทิ้ง: ลองใช้ title/aria-label ของแท็กแทนข้อความว่างๆ
            title = _clean_title(anchor.get("title") or anchor.get("aria-label") or "")
        if len(title) < SEARCH_MIN_TITLE_CHARS:
            continue

        seen.add(key)
        links.append({"title": title, "link": url})
        if limit and len(links) >= limit:
            break

    return links


def fetch_search_results(endpoint, query, deadline=None, max_results=None):
    """ยิง 1 engine แล้วคืน [{"title", "link"}]
    ลำดับการลอง: Tor SOCKS ตรงๆ (ถ้า Tor รันอยู่) -> tor2web gateway ทีละ suffix
    ของเดิมข้าม Tor ไปเลยทั้งที่นิยาม get_tor_session()/is_tor_reachable() ไว้
    แปลว่าเครื่องที่รัน Tor อยู่ก็ยังถูกบังคับให้ผ่าน gateway ที่ล่มเป็นส่วนใหญ่"""
    encoded_query = quote_plus(query)
    onion_url = endpoint.format(query=encoded_query)
    engine_name = _ENGINE_NAME_BY_URL.get(endpoint, urlparse(onion_url).hostname or endpoint)
    limit = SEARCH_MAX_RESULTS_PER_ENGINE if max_results is None else max_results

    attempts = []
    if _tor_enabled():
        attempts.append((onion_url, True))
    for suffix in TOR_GATEWAY_SUFFIXES:
        attempts.append((_onion_to_gateway(onion_url, suffix), False))

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
    }

    for attempt_url, use_tor in attempts:
        timeout = _timeout_for(deadline)
        if timeout is None:
            logger.debug("SEARCH BUDGET EXHAUSTED | engine=%s", engine_name)
            break
        try:
            response = _get_session(use_tor=use_tor).get(
                attempt_url, headers=headers, timeout=timeout, allow_redirects=True
            )
            if response.status_code != 200:
                logger.debug(
                    "SEARCH NON-200 | engine=%s tor=%s status=%s",
                    engine_name, use_tor, response.status_code,
                )
                continue
            links = _extract_links(response.text, attempt_url, limit)
            if links:
                logger.debug(
                    "SEARCH OK | engine=%s tor=%s results=%d", engine_name, use_tor, len(links)
                )
                return links
        except requests.exceptions.InvalidSchema as exc:
            # socks5h ต้องมี PySocks (มีใน requirements.txt) — ถ้าหาย ให้ตกไป gateway
            logger.warning("SEARCH TOR UNAVAILABLE | engine=%s: %s", engine_name, exc)
            continue
        except requests.RequestException as exc:
            logger.debug("SEARCH ATTEMPT FAILED | engine=%s tor=%s: %s", engine_name, use_tor, exc)
            continue
        except Exception as exc:
            logger.debug("SEARCH PARSE FAILED | engine=%s: %s", engine_name, exc)
            continue

    return []


def get_search_results(refined_query, max_workers=None, budget_seconds=None, max_results=None):
    """ค้นหลาย engine พร้อมกันแล้ว dedupe — เรียกจาก coordinator._collect_darkweb_evidence()
    ซึ่งถูกเรียกต่อจาก /identity และ /corporate ใน app.py

    ของเดิมไม่มีเพดานเวลารวม: ทุก engine ที่ค้าง = handler ของ app.py ค้างตาม
    ตอนนี้มี budget รวม (SEARCH_TOTAL_BUDGET_SECONDS) และไม่ยอม raise ออกไปหา
    caller เด็ดขาด — ค้นไม่ได้ก็คืน [] ให้ coordinator fallback ไปตอบแบบไม่มี evidence"""
    query = " ".join(str(refined_query or "").split())[:SEARCH_MAX_QUERY_CHARS]
    if not query:
        logger.info("SEARCH SKIPPED | empty query")
        return []

    workers = max_workers if max_workers else SEARCH_MAX_WORKERS
    workers = max(1, min(int(workers), len(DEFAULT_SEARCH_ENGINES)))
    budget = float(budget_seconds) if budget_seconds else SEARCH_TOTAL_BUDGET_SECONDS
    cap = int(max_results) if max_results else SEARCH_MAX_RESULTS
    started = time.monotonic()
    deadline = started + budget
    tor = _tor_enabled()

    results = []
    engines_ok = 0
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {
            executor.submit(fetch_search_results, endpoint, query, deadline): endpoint
            for endpoint in DEFAULT_SEARCH_ENGINES
        }
        try:
            for future in as_completed(futures, timeout=budget):
                try:
                    result_urls = future.result()
                except Exception as exc:
                    logger.debug("SEARCH WORKER CRASHED | %s", exc)
                    continue
                if result_urls:
                    engines_ok += 1
                    results.extend(result_urls)
        except FuturesTimeout:
            logger.warning(
                "SEARCH BUDGET TIMEOUT | query=%r budget=%.1fs engines_done=%d",
                query, budget, engines_ok,
            )
    finally:
        # cancel_futures: งานที่ยังไม่เริ่มถูกทิ้ง, wait=False: ไม่ให้ handler ของ
        # app.py ต้องรอ thread ที่ยังค้างอยู่จนครบ (ทุก request มี timeout ของตัวเองอยู่แล้ว)
        executor.shutdown(wait=False, cancel_futures=True)

    # Deduplicate results
    seen_links = set()
    unique_results = []
    for res in results:
        link = (res.get("link") or "").strip()
        if not link:
            continue
        # Remove trailing slashes for better deduplication
        clean_link = link.rstrip('/').lower()
        if clean_link not in seen_links:
            seen_links.add(clean_link)
            unique_results.append(res)
            if len(unique_results) >= cap:
                break

    logger.info(
        "SEARCH DONE | query=%r tor=%s engines_ok=%d/%d raw=%d unique=%d elapsed=%.1fs",
        query, tor, engines_ok, len(DEFAULT_SEARCH_ENGINES),
        len(results), len(unique_results), time.monotonic() - started,
    )
    return unique_results


# ---------------- async / Telegram helpers (สำหรับ app.py) ----------------

async def get_search_results_async(refined_query, max_workers=None, budget_seconds=None,
                                   max_results=None):
    """เวอร์ชัน async ของ get_search_results() สำหรับเรียกตรงจาก handler ของ app.py
    (ทุกอย่างข้างในเป็น requests แบบ blocking จึงต้องออกไปอยู่บน thread
    ไม่งั้น event loop ของ python-telegram-bot จะถูกบล็อกทั้งบอท)"""
    return await asyncio.to_thread(
        get_search_results, refined_query, max_workers, budget_seconds, max_results
    )


def format_search_results(results, limit=None, header="🔎 ผลการค้นหา"):
    """จัดผลลัพธ์เป็นข้อความไทยพร้อมส่งเข้า gemini.split_telegram_message() ของ app.py
    (ส่งเป็น plain text ไม่มี Markdown/HTML เพราะชื่อเว็บบน .onion มีอักขระพิเศษเยอะ
    ถ้าใส่ parse_mode แล้ว escape ไม่ครบ Telegram จะตีกลับทั้งข้อความ)"""
    if not results:
        return "ไม่พบผลการค้นหา (Tor/gateway อาจใช้งานไม่ได้ในตอนนี้)"

    shown = results[: (limit or SEARCH_MAX_RESULTS)]
    lines = [f"{header} {len(shown)}/{len(results)} รายการ", ""]
    for index, item in enumerate(shown, start=1):
        title = _clean_title(item.get("title")) or "Untitled"
        lines.append(f"{index}. {title}\n{item.get('link', '')}")
    return "\n".join(lines)
