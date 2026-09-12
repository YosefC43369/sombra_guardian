import os
import time
import asyncio
import requests
import random, re
import logging
import threading
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import quote_plus, urlparse, parse_qs, unquote
from collections import OrderedDict

import nethealth

logger = logging.getLogger("modbot.search")

# config ของ Tor/gateway และตัวอ่าน env อยู่ที่ nethealth.py ที่เดียว —
# เดิมไฟล์นี้กับ scrape.py มีคนละก๊อป ทำให้ .env ค่าว่างให้ผลต่างกันสองที่
_env_int = nethealth.env_int
_env_float = nethealth.env_float

TOR_SOCKS_HOST = nethealth.TOR_SOCKS_HOST
TOR_SOCKS_PORT = nethealth.TOR_SOCKS_PORT
TOR_GATEWAY_SUFFIXES = nethealth.TOR_GATEWAY_SUFFIXES
TOR_PROBE_TTL_SECONDS = nethealth.TOR_PROBE_TTL_SECONDS


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
# หยุดค้นทันทีที่ได้ผลไม่ซ้ำครบเป้า แทนที่จะรอ engine ที่เหลือจนหมด budget
SEARCH_EARLY_STOP = nethealth.env_bool("SEARCH_EARLY_STOP", "true")
# ผลค้นหาเดิมใช้ซ้ำได้ภายใน TTL — ผู้ใช้มักสั่ง /search แล้วตามด้วย /identity
# ด้วยเป้าหมายเดียวกัน ของเดิมยิงซ้ำทั้งชุดและได้หลักฐานคนละชุดกัน
SEARCH_CACHE_TTL_SECONDS = _env_float("SEARCH_CACHE_TTL_SECONDS", 600)
SEARCH_CACHE_MAX_ENTRIES = _env_int("SEARCH_CACHE_MAX_ENTRIES", 64)

_cache_lock = threading.Lock()
_cache = OrderedDict()


def _cache_get(key):
    if SEARCH_CACHE_TTL_SECONDS <= 0:
        return None
    with _cache_lock:
        entry = _cache.get(key)
        if not entry:
            return None
        expires_at, results = entry
        if expires_at < time.monotonic():
            _cache.pop(key, None)
            return None
        _cache.move_to_end(key)
        return list(results)


def _cache_put(key, results):
    if SEARCH_CACHE_TTL_SECONDS <= 0:
        return
    with _cache_lock:
        _cache[key] = (time.monotonic() + SEARCH_CACHE_TTL_SECONDS, list(results))
        _cache.move_to_end(key)
        while len(_cache) > SEARCH_CACHE_MAX_ENTRIES:
            _cache.popitem(last=False)


def clear_search_cache():
    with _cache_lock:
        _cache.clear()


_thread_local = threading.local()


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
    ใช้ probe ร่วมกับ scrape.py ผ่าน nethealth เพื่อไม่ให้เปิด socket ซ้ำซ้อน"""
    return nethealth.tor_reachable(timeout=timeout, force=force)


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

# แต่ละ engine พก:
#   result_selectors : CSS ที่ชี้ "แถวผลลัพธ์" — ดึงลิงก์+snippet เฉพาะในแถวนั้น
#                      ไม่งั้นจะได้ลิงก์ nav/ads/เอนจินอื่นของหน้า engine ปนมา
#   clearnet_index   : True = เป็นดัชนี .onion ที่มีหน้าเว็บเปิด ยิงตรงได้เลย
#                      ไม่ต้องผ่าน Tor/gateway (ผลที่ได้ยังเป็น .onion ตามปกติ)
# Ahmia เป็นดัชนี onion ที่คัดกรองมาแล้ว จึงแม่นกว่าเอนจิน onion ทั่วไป และ
# ahmia.fi (เว็บเปิด) ทำให้ค้น dark web ได้แม้ Tor ยังต่อไม่ได้
SEARCH_ENGINES = [
    {"name": "Ahmia (web)", "url": "https://ahmia.fi/search/?q={query}",
     "clearnet_index": True,
     "result_selectors": ["li.result h4 a", "ol.searchResults li h4 a", "li.result a"]},
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
     "result_selectors": ["li.result h4 a", "ol.searchResults li h4 a", "li.result a"]},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}",
     "result_selectors": ["div.result h2 a", "div.result a.title", "a.result-link"]},
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
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}",
     "result_selectors": ["div.result a", "a.title"]},
    {"name": "OSS", "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}"},
    {"name": "Torgol", "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "The Deep Searches", "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}",
     "result_selectors": ["div.result h5 a", "div.result a", "a.title"]},
]

# Backward-compatible flat list used by existing search logic
DEFAULT_SEARCH_ENGINES = [e["url"] for e in SEARCH_ENGINES]

_ENGINE_NAME_BY_URL = {e["url"]: e["name"] for e in SEARCH_ENGINES}
_ENGINE_BY_URL = {e["url"]: e for e in SEARCH_ENGINES}

# โฮสต์ของ "ตัวเอนจินค้นหา" ทั้งหมด — ผลลัพธ์ที่ชี้กลับไปหาเอนจินพวกนี้
# (ไม่ว่าเอนจินไหนเป็นคนคืนมา) ไม่ใช่หลักฐาน เป็นแค่ลิงก์ข้ามเอนจิน/nav
_ONION_ENGINE_HOSTS = frozenset(
    (urlparse(e["url"]).hostname or "").lower()
    for e in SEARCH_ENGINES
)

SEARCH_MAX_SNIPPET_CHARS = _env_int("SEARCH_MAX_SNIPPET_CHARS", 300)


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
# redirect_url = Ahmia, d = OnionLand — เอนจินห่อ .onion ปลายทางไว้ในพารามิเตอร์พวกนี้
_REDIRECT_PARAM_KEYS = ("redirect_url", "url", "u", "redirect", "r", "target", "link", "q", "d")


def _is_engine_onion(url: str) -> bool:
    """ผลลัพธ์ที่ชี้กลับไปหาตัวเอนจินค้นหาเอง (ข้ามเอนจิน/nav) — ไม่ใช่หลักฐาน"""
    host = (urlparse(url).hostname or "").lower()
    return host in _ONION_ENGINE_HOSTS


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


def _snippet_from(node, title: str) -> str:
    """ดึงคำโปรยของแถวผลลัพธ์ โดยตัดชื่อเรื่องที่ซ้ำอยู่หัวแถวออก
    snippet คือคำอธิบายที่เอนจินสรุปให้ — เป็นสัญญาณช่วยจัดอันดับก่อน scrape
    และเป็นข้อมูลสำรองเวลา scrape เนื้อหาจริงไม่ได้"""
    if node is None:
        return ""
    text = " ".join(node.get_text(separator=" ").split())
    if title and text.lower().startswith(title.lower()):
        text = text[len(title):].strip(" -–|:")
    return text[:SEARCH_MAX_SNIPPET_CHARS]


def _onion_result_rows(soup, selectors):
    """คืนแถวผลลัพธ์ตาม CSS selector ของเอนจิน (title anchor แต่ละอัน)
    ถ้าไม่มี selector หรือไม่แมตช์ ค่อยถอยไปพิจารณาทุก <a> ในหน้า"""
    for selector in selectors or []:
        try:
            found = soup.select(selector)
        except Exception:
            found = []
        anchors = [a for a in found if a.name == "a" and a.get("href")]
        if anchors:
            return anchors, True
    return [a for a in soup.find_all("a", href=True)], False


def _extract_links(html, base_url, limit, selectors=None):
    """ดึงผลลัพธ์ .onion จากหน้าเอนจิน — คืน [{"title","link","snippet"}]

    เดิมดึงทุก <a> ทั้งหน้าที่ resolve เป็น .onion ได้ จึงได้ลิงก์ข้ามเอนจิน,
    nav, และโฆษณาปนมาเยอะ ตอนนี้:
      1. ถ้ามี result_selectors ของเอนจิน ดึงเฉพาะในแถวผลลัพธ์
      2. ตัดผลที่ชี้กลับหาตัวเอนจินค้นหาใดๆ (ไม่ใช่แค่เอนจินปัจจุบัน)
      3. เก็บ snippet ของแต่ละแถวไว้ช่วยจัดอันดับและเป็นข้อมูลสำรอง
    """
    soup = BeautifulSoup(html, "html.parser")
    base_host = (urlparse(_gateway_to_onion(base_url)).hostname or "").lower()

    anchors, from_rows = _onion_result_rows(soup, selectors)
    links = []
    seen = set()
    for anchor in anchors:
        url = _href_to_onion(anchor.get("href"), base_host)
        if not url or _is_engine_onion(url):
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

        # snippet: ข้อความของแถว (บล็อกแม่ของ anchor) หักชื่อเรื่องออก
        row = anchor.find_parent(["li", "article", "section", "div", "td", "p"]) or anchor
        snippet = _snippet_from(row, title)

        seen.add(key)
        links.append({"title": title, "link": url, "snippet": snippet})
        if limit and len(links) >= limit:
            break

    if not from_rows and selectors:
        logger.debug("ONION FALLBACK | selector ไม่แมตช์ ใช้ทั้งหน้า base=%s", base_host)
    return links


def fetch_search_results(endpoint, query, deadline=None, max_results=None):
    """ยิง 1 engine แล้วคืน [{"title", "link"}]
    ลำดับการลอง: Tor SOCKS ตรงๆ (ถ้า Tor รันอยู่) -> tor2web gateway ทีละ suffix
    ของเดิมข้าม Tor ไปเลยทั้งที่นิยาม get_tor_session()/is_tor_reachable() ไว้
    แปลว่าเครื่องที่รัน Tor อยู่ก็ยังถูกบังคับให้ผ่าน gateway ที่ล่มเป็นส่วนใหญ่

    ทุกความพยายามถูกบันทึกเข้า circuit breaker: engine หรือ gateway ที่ล้มซ้ำๆ
    จะถูกข้ามชั่วคราว งบเวลาจะได้ตกไปอยู่กับเส้นทางที่ยังมีชีวิตจริง
    """
    encoded_query = quote_plus(query)
    onion_url = endpoint.format(query=encoded_query)
    engine = _ENGINE_BY_URL.get(endpoint, {})
    engine_name = engine.get("name", _ENGINE_NAME_BY_URL.get(endpoint, urlparse(onion_url).hostname or endpoint))
    selectors = engine.get("result_selectors")
    limit = SEARCH_MAX_RESULTS_PER_ENGINE if max_results is None else max_results

    engine_key = f"engine:{engine_name}"
    if nethealth.blocked(engine_key):
        logger.debug("SEARCH ENGINE SKIPPED (cooldown) | engine=%s", engine_name)
        return []

    def _tag(results):
        for item in results:
            item["engine"] = engine_name
            item["origin"] = "darkweb"
        return results

    # ดัชนี onion ที่มีหน้าเว็บเปิด (Ahmia web): ยิงตรงผ่าน clearnet ครั้งเดียว
    # ไม่ต้องมี Tor เลย — ผลที่ได้ยังเป็น .onion ตามปกติ ทำให้ค้น dark web ได้
    # แม้ Tor ต่อไม่ได้ และดัชนีที่คัดกรองแล้วให้ผลแม่นกว่าเอนจิน onion ทั่วไป
    if engine.get("clearnet_index"):
        timeout = _timeout_for(deadline)
        if timeout is None:
            return []
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
        }
        try:
            response = _get_session(use_tor=False).get(
                onion_url, headers=headers, timeout=timeout, allow_redirects=True
            )
            if response.status_code != 200:
                nethealth.record(engine_key, False, nethealth.ENGINE_FAILURE_THRESHOLD)
                return []
            nethealth.record(engine_key, True, nethealth.ENGINE_FAILURE_THRESHOLD)
            return _tag(_extract_links(response.text, onion_url, limit, selectors))
        except requests.RequestException as exc:
            logger.debug("SEARCH INDEX FAILED | engine=%s: %s", engine_name, exc)
            nethealth.record(engine_key, False, nethealth.ENGINE_FAILURE_THRESHOLD)
            return []
        except Exception as exc:
            logger.debug("SEARCH INDEX PARSE FAILED | engine=%s: %s", engine_name, exc)
            return []

    attempts = []
    if _tor_enabled():
        attempts.append((onion_url, True, "tor"))
    for suffix in TOR_GATEWAY_SUFFIXES:
        attempts.append((_onion_to_gateway(onion_url, suffix), False, suffix))

    # ข้ามเส้นทางที่กำลังถูกพัก — ถ้าโดนพักหมดก็ไม่ต้องเสียเวลายิงเลย
    attempts = [a for a in attempts if not nethealth.blocked(f"route:{a[2]}")]
    if not attempts:
        logger.debug("SEARCH NO LIVE ROUTE | engine=%s", engine_name)
        return []

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
    }

    reached = False          # มี attempt ไหนได้ HTTP 200 กลับมาบ้างไหม
    for attempt_url, use_tor, route in attempts:
        route_key = f"route:{route}"
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
                    "SEARCH NON-200 | engine=%s route=%s status=%s",
                    engine_name, route, response.status_code,
                )
                # 404 = gateway ตอบได้แต่ปลายทางไม่มี ไม่ใช่ความผิดของเส้นทาง
                # ถ้านับรวมด้วย onion site ที่ตายไปแล้วเพียงตัวเดียวจะลาก
                # gateway ทั้งตัวเข้า cooldown ไปด้วย ซึ่งผิดและทำให้ค้นไม่ได้
                if response.status_code >= 500 or response.status_code == 429:
                    nethealth.record(route_key, False, nethealth.ROUTE_FAILURE_THRESHOLD)
                continue

            # ได้ 200 = เส้นทางใช้ได้ ต่อให้ query นี้ไม่มีผลลัพธ์ก็ตาม
            reached = True
            nethealth.record(route_key, True, nethealth.ROUTE_FAILURE_THRESHOLD)
            links = _extract_links(response.text, attempt_url, limit, selectors)
            if links:
                logger.debug(
                    "SEARCH OK | engine=%s route=%s results=%d", engine_name, route, len(links)
                )
                nethealth.record(engine_key, True, nethealth.ENGINE_FAILURE_THRESHOLD)
                return _tag(links)
        except requests.exceptions.InvalidSchema as exc:
            # socks5h ต้องมี PySocks (มีใน requirements.txt) — ถ้าหาย ให้ตกไป gateway
            logger.warning("SEARCH TOR UNAVAILABLE | engine=%s: %s", engine_name, exc)
            nethealth.record(route_key, False, nethealth.ROUTE_FAILURE_THRESHOLD)
            continue
        except requests.RequestException as exc:
            logger.debug("SEARCH ATTEMPT FAILED | engine=%s route=%s: %s", engine_name, route, exc)
            nethealth.record(route_key, False, nethealth.ROUTE_FAILURE_THRESHOLD)
            continue
        except Exception as exc:
            logger.debug("SEARCH PARSE FAILED | engine=%s: %s", engine_name, exc)
            continue

    # engine ถือว่าล้มเฉพาะตอนที่ "ติดต่อไม่ได้เลย" ไม่ใช่ตอนที่แค่ไม่มีผลลัพธ์
    nethealth.record(engine_key, reached, nethealth.ENGINE_FAILURE_THRESHOLD)
    return []


def get_search_results(refined_query, max_workers=None, budget_seconds=None,
                       max_results=None, use_cache=True):
    """ค้นหลาย engine พร้อมกันแล้ว dedupe — เรียกจาก coordinator._collect_darkweb_evidence()
    ซึ่งถูกเรียกต่อจาก /identity และ /corporate ใน app.py

    ของเดิมไม่มีเพดานเวลารวม: ทุก engine ที่ค้างคือ handler ของ app.py ค้างตาม
    ตอนนี้มี budget รวม (SEARCH_TOTAL_BUDGET_SECONDS), หยุดทันทีที่ได้ผลครบเป้า,
    ใช้ผลเดิมซ้ำภายใน TTL, และไม่ยอม raise ออกไปหา caller เด็ดขาด — ค้นไม่ได้
    ก็คืน [] ให้ coordinator รายงานว่าเป็นช่องว่างข่าวกรอง
    """
    query = " ".join(str(refined_query or "").split())[:SEARCH_MAX_QUERY_CHARS]
    if not query:
        logger.info("SEARCH SKIPPED | empty query")
        return []

    workers = max_workers if max_workers else SEARCH_MAX_WORKERS
    workers = max(1, min(int(workers), len(DEFAULT_SEARCH_ENGINES)))
    budget = float(budget_seconds) if budget_seconds else SEARCH_TOTAL_BUDGET_SECONDS
    cap = int(max_results) if max_results else SEARCH_MAX_RESULTS

    cache_key = f"{query}|{cap}"
    if use_cache:
        cached = _cache_get(cache_key)
        if cached is not None:
            logger.info("SEARCH CACHE HIT | query=%r results=%d", query, len(cached))
            return cached

    started = time.monotonic()
    deadline = started + budget
    tor = _tor_enabled()

    # dedupe ระหว่างทาง ไม่ใช่ตอนจบ จะได้รู้ว่าครบเป้าเมื่อไหร่แล้วหยุดได้ทันที
    seen_links = set()
    unique_results = []
    engines_ok = 0
    raw_count = 0
    early_stop = False

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
                if not result_urls:
                    continue
                engines_ok += 1
                raw_count += len(result_urls)
                for res in result_urls:
                    link = (res.get("link") or "").strip()
                    if not link:
                        continue
                    # Remove trailing slashes for better deduplication
                    clean_link = link.rstrip("/").lower()
                    if clean_link in seen_links:
                        continue
                    seen_links.add(clean_link)
                    unique_results.append(res)
                if SEARCH_EARLY_STOP and len(unique_results) >= cap:
                    early_stop = True
                    break
        except FuturesTimeout:
            logger.warning(
                "SEARCH BUDGET TIMEOUT | query=%r budget=%.1fs engines_done=%d",
                query, budget, engines_ok,
            )
    finally:
        # cancel_futures: งานที่ยังไม่เริ่มถูกทิ้ง, wait=False: ไม่ให้ handler ของ
        # app.py ต้องรอ thread ที่ยังค้างอยู่จนครบ (ทุก request มี timeout ของตัวเองอยู่แล้ว)
        executor.shutdown(wait=False, cancel_futures=True)

    unique_results = unique_results[:cap]
    if use_cache and unique_results:
        _cache_put(cache_key, unique_results)

    logger.info(
        "SEARCH DONE | query=%r tor=%s engines_ok=%d/%d raw=%d unique=%d "
        "elapsed=%.1fs early_stop=%s cooldown_routes=%s",
        query, tor, engines_ok, len(DEFAULT_SEARCH_ENGINES), raw_count,
        len(unique_results), time.monotonic() - started, early_stop,
        nethealth.open_routes() or "-",
    )
    return unique_results


# ---------------- async / Telegram helpers (สำหรับ app.py) ----------------

async def get_search_results_async(refined_query, max_workers=None, budget_seconds=None,
                                   max_results=None, use_cache=True):
    """เวอร์ชัน async ของ get_search_results() สำหรับเรียกตรงจาก handler ของ app.py
    (ทุกอย่างข้างในเป็น requests แบบ blocking จึงต้องออกไปอยู่บน thread
    ไม่งั้น event loop ของ python-telegram-bot จะถูกบล็อกทั้งบอท)"""
    return await asyncio.to_thread(
        get_search_results, refined_query, max_workers, budget_seconds, max_results, use_cache
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


# ---------------- Clearnet search ----------------
# ของเดิมค้นเฉพาะ onion search engine ซึ่งไม่มีทางเจอชื่อคน เบอร์โทร หรือโปรไฟล์
# โซเชียลของใครเลย งาน OSINT ตัวตนบุคคลส่วนใหญ่อยู่บนเว็บเปิด จึงต้องมีชั้นนี้
# engine ทุกตัวที่เลือกมาเรียกได้โดยไม่ต้องใช้ API key

# แต่ละ engine พก:
#   result_selectors : CSS ที่ชี้ "โซนผลลัพธ์" เท่านั้น — ดึงลิงก์เฉพาะในโซนนี้
#                      ไม่งั้นจะได้ลิงก์ footer/nav/โซเชียลของตัว engine เองปนมา
#                      (นั่นคือบั๊กที่ทำให้ /search คืน app.startpage.com, git.marginalia.nu)
#   own_domains      : โดเมนของ engine เอง (จับรวม subdomain) ที่ต้องตัดทิ้งเสมอ
CLEARNET_ENGINES = [
    {"name": "DuckDuckGo", "url": "https://html.duckduckgo.com/html/?q={query}",
     "result_selectors": ["a.result__a", "a.result__url"],
     "own_domains": ["duckduckgo.com", "duck.com"]},
    {"name": "Mojeek", "url": "https://www.mojeek.com/search?q={query}",
     "result_selectors": ["ul.results-standard li h2 a", "a.ob", "ul.results-standard li a"],
     "own_domains": ["mojeek.com"]},
    {"name": "Brave", "url": "https://search.brave.com/search?q={query}",
     "result_selectors": ["a.result-header", "#results a[href^='http']", "a.h"],
     "own_domains": ["brave.com"]},
    {"name": "Startpage", "url": "https://www.startpage.com/sp/search?query={query}",
     "result_selectors": ["a.result-link", "a.w-gl__result-title",
                          "a.result-title", "div.w-gl__result a[href^='http']"],
     "own_domains": ["startpage.com"]},
    {"name": "Bing", "url": "https://www.bing.com/search?q={query}&setlang=th",
     "result_selectors": ["li.b_algo h2 a", "ol#b_results li.b_algo a[href^='http']"],
     "own_domains": ["bing.com", "microsoft.com", "microsofttranslator.com", "msn.com"]},
    {"name": "Marginalia", "url": "https://search.marginalia.nu/search?query={query}",
     "result_selectors": ["section.card.search-result h2 a", "div.result h2 a",
                          "a.result-title", "main a[href^='http']"],
     "own_domains": ["marginalia.nu", "marginalia-search.com"]},
    {"name": "Ecosia", "url": "https://www.ecosia.org/search?q={query}",
     "result_selectors": ["a.result__title-link", "a.result-title",
                          "div.mainline a.result__link"],
     "own_domains": ["ecosia.org"]},
]

CLEARNET_ENABLED = nethealth.env_bool("SEARCH_CLEARNET_ENABLED", "true")
CLEARNET_MAX_WORKERS = _env_int("SEARCH_CLEARNET_MAX_WORKERS", 6)
CLEARNET_MAX_RESULTS_PER_ENGINE = _env_int("SEARCH_CLEARNET_MAX_RESULTS_PER_ENGINE", 12)
# engine ที่ปิดได้เป็นรายตัวผ่าน .env เช่น SEARCH_CLEARNET_DISABLED=Bing,Brave
CLEARNET_DISABLED = {
    name.strip().lower()
    for name in nethealth.env_list("SEARCH_CLEARNET_DISABLED", "") or []
}

# โดเมนที่เป็นโครงสร้างของ engine / CDN / โซเชียลของตัว engine เอง / นโยบาย
# เทียบแบบ suffix จึงจับ subdomain ทั้งหมดด้วย (เดิมเทียบตรงตัว app.startpage.com
# กับ git.marginalia.nu จึงหลุดผ่านมาเป็น "ผลลัพธ์")
_CLEARNET_SKIP_DOMAINS = frozenset((
    "duckduckgo.com", "duck.com", "spreadprivacy.com",
    "mojeek.com", "brave.com", "startpage.com", "startpage.eu",
    "bing.com", "microsoft.com", "microsofttranslator.com", "msn.com",
    "marginalia.nu", "marginalia-search.com", "ecosia.org",
    "google.com", "gstatic.com", "googleapis.com", "gravatar.com",
    "w3.org", "schema.org", "creativecommons.org", "wikimedia.org",
    # โซเชียลของตัว engine (footer) — จับที่ path แทน ดูใน _is_engine_social()
))
# บัญชีโซเชียลของตัว engine เองที่โผล่ใน footer — ตัด path พวกนี้ทิ้ง
_ENGINE_SOCIAL_HANDLES = frozenset((
    "startpage", "startpagesearch", "duckduckgo", "mojeek", "brave",
    "bravesoftware", "bing", "ecosia", "marginaliasearch", "marginalia_nu",
))
# พารามิเตอร์ที่ engine ใช้ห่อ URL ปลายทางไว้ (DuckDuckGo=uddg, Bing=u, ทั่วไป=url)
_CLEARNET_REDIRECT_KEYS = ("uddg", "url", "u", "q", "r", "redirect", "target", "to")
_RE_THAI = re.compile(r"[฀-๿]")

_CLEARNET_ENGINE_NAME_BY_URL = {e["url"]: e["name"] for e in CLEARNET_ENGINES}
_CLEARNET_ENGINE_BY_URL = {e["url"]: e for e in CLEARNET_ENGINES}
DEFAULT_CLEARNET_ENGINES = [e["url"] for e in CLEARNET_ENGINES]


def _active_clearnet_engines():
    return [
        e["url"] for e in CLEARNET_ENGINES
        if e["name"].lower() not in CLEARNET_DISABLED
    ]


def _host_matches(host: str, domains) -> bool:
    """host ตรงกับโดเมนใน set ไหม โดยจับ subdomain ด้วย (suffix match)
    เช่น app.startpage.com ตรงกับ startpage.com"""
    host = (host or "").lower()
    if host.startswith("www."):
        host = host[4:]
    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _is_engine_social(url: str) -> bool:
    """ลิงก์โซเชียลของตัว engine เองใน footer (เช่น twitter.com/startpage)
    บัญชีโซเชียลจริงของเป้าหมายจะไม่ตรงกับรายชื่อแบรนด์ engine พวกนี้"""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    social_hosts = ("twitter.com", "x.com", "facebook.com", "instagram.com",
                    "mastodon.social", "reddit.com", "youtube.com", "linkedin.com",
                    "github.com", "t.me", "tiktok.com")
    if not any(host == h or host.endswith("." + h) for h in social_hosts):
        return False
    segments = [seg for seg in parsed.path.split("/") if seg]
    if not segments:
        return False
    # reddit ใช้ /r/<name> หรือ /user/<name>, ที่อื่นใช้ /<name>
    if segments[0].lower() in ("r", "user", "u") and len(segments) > 1:
        handle = segments[1]
    else:
        handle = segments[0]
    return handle.lstrip("@").lower() in _ENGINE_SOCIAL_HANDLES


def _accept_language_for(query: str) -> str:
    """คำค้นภาษาไทยต้องขอผลภาษาไทย ไม่งั้น engine หลายตัวคืนผลอังกฤษล้วน
    แล้วชื่อคนไทยก็จะหาไม่เจอทั้งที่มีข้อมูลอยู่"""
    if _RE_THAI.search(query or ""):
        return "th-TH,th;q=0.9,en-US;q=0.6,en;q=0.5"
    return "en-US,en;q=0.9,th;q=0.6"


def _href_to_clearnet(href, base_host, own_domains=()):
    """ดึง URL ผลลัพธ์จริงจาก href หนึ่งอัน — engine ส่วนใหญ่ห่อปลายทางไว้ใน
    พารามิเตอร์ redirect (DuckDuckGo ใช้ uddg=, Bing ใช้ u=) ถ้าไม่แกะออก
    เราจะได้แต่ลิงก์ของ engine เองซึ่งไม่มีค่าเชิงข่าวกรองเลย"""
    if not href:
        return None

    candidates = []
    if "?" in href:
        try:
            params = parse_qs(urlparse(href).query)
        except ValueError:
            params = {}
        for key in _CLEARNET_REDIRECT_KEYS:
            for value in params.get(key, []):
                value = unquote(value)
                if value.startswith("//"):
                    value = "https:" + value
                if value.startswith("http://") or value.startswith("https://"):
                    candidates.append(value)
    candidates.append(href)

    for candidate in candidates:
        if candidate.startswith("//"):
            candidate = "https:" + candidate
        if not (candidate.startswith("http://") or candidate.startswith("https://")):
            continue
        try:
            parsed = urlparse(candidate)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        if not host or host == base_host:
            continue
        # ตัดโดเมนของ engine เอง (รวม subdomain) + engine โครงสร้าง/CDN/นโยบาย
        if _host_matches(host, own_domains) or _host_matches(host, _CLEARNET_SKIP_DOMAINS):
            continue
        # ตัดลิงก์โซเชียลของตัว engine เองใน footer
        if _is_engine_social(candidate):
            continue
        # ตัด fragment ทิ้ง คนละ fragment ไม่ใช่คนละหน้า
        return parsed._replace(fragment="").geturl()
    return None


def _anchors_in_results(soup, selectors):
    """คืน anchor เฉพาะในโซนผลลัพธ์ตาม CSS selector ของ engine นั้น
    ถ้า selector ไม่แมตช์เลย (engine เปลี่ยน markup) ค่อยถอยไปทั้งหน้า
    ซึ่งตัวกรองโดเมน/โซเชียลจะช่วยกันขยะไว้อีกชั้น"""
    for selector in selectors or []:
        try:
            found = soup.select(selector)
        except Exception:
            found = []
        anchors = [a for a in found if a.name == "a" and a.get("href")]
        if anchors:
            return anchors, True
    return [a for a in soup.find_all("a", href=True)], False


def _extract_clearnet_links(html, base_url, limit, selectors=None, own_domains=()):
    soup = BeautifulSoup(html, "html.parser")
    base_host = (urlparse(base_url).hostname or "").lower()

    anchors, from_results = _anchors_in_results(soup, selectors)
    links = []
    seen = set()
    for anchor in anchors:
        url = _href_to_clearnet(anchor.get("href"), base_host, own_domains)
        if not url:
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue

        title = _clean_title(anchor.get_text(strip=True))
        if len(title) < SEARCH_MIN_TITLE_CHARS:
            title = _clean_title(anchor.get("title") or anchor.get("aria-label") or "")
        if len(title) < SEARCH_MIN_TITLE_CHARS:
            continue

        seen.add(key)
        links.append({"title": title, "link": url})
        if limit and len(links) >= limit:
            break
    if not from_results:
        logger.debug("CLEARNET FALLBACK | ใช้ทั้งหน้า (selector ไม่แมตช์) base=%s", base_host)
    return links


def fetch_clearnet_results(endpoint, query, deadline=None, max_results=None):
    """ยิง clearnet engine 1 ตัว ใช้ circuit breaker ตัวเดียวกับฝั่ง dark web
    จึงจำได้ว่า engine ไหนบล็อกเราอยู่และข้ามไปชั่วคราว"""
    engine = _CLEARNET_ENGINE_BY_URL.get(endpoint, {})
    engine_name = engine.get("name", _CLEARNET_ENGINE_NAME_BY_URL.get(endpoint, endpoint))
    engine_key = f"engine:{engine_name}"
    if nethealth.blocked(engine_key):
        logger.debug("CLEARNET ENGINE SKIPPED (cooldown) | engine=%s", engine_name)
        return []

    limit = CLEARNET_MAX_RESULTS_PER_ENGINE if max_results is None else max_results
    url = endpoint.format(query=quote_plus(query))
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": _accept_language_for(query),
    }

    timeout = _timeout_for(deadline)
    if timeout is None:
        return []

    try:
        response = _get_session(use_tor=False).get(
            url, headers=headers, timeout=timeout, allow_redirects=True
        )
        if response.status_code != 200:
            logger.debug("CLEARNET NON-200 | engine=%s status=%s",
                         engine_name, response.status_code)
            nethealth.record(engine_key, False, nethealth.ENGINE_FAILURE_THRESHOLD)
            return []
        links = _extract_clearnet_links(
            response.text, url, limit,
            selectors=engine.get("result_selectors"),
            own_domains=engine.get("own_domains", ()),
        )
        # ตอบ 200 = engine ยังใช้งานได้ ถึงจะไม่มีผลลัพธ์ก็ตาม
        # การนับ "ผลว่าง" เป็นความล้มเหลวจะพัก engine ที่ทำงานดีทิ้งไป 5 นาที
        # เพราะชื่อคนที่หายากจริงๆ ย่อมไม่มีผลในบาง engine เป็นเรื่องปกติ
        # ส่วนการโดนบล็อกจริงมักมาเป็น 403/429/5xx ซึ่งดักไว้ข้างบนแล้ว
        nethealth.record(engine_key, True, nethealth.ENGINE_FAILURE_THRESHOLD)
        logger.debug("CLEARNET OK | engine=%s results=%d", engine_name, len(links))
        for item in links:
            item["engine"] = engine_name
            item["origin"] = "clearnet"
        return links
    except requests.RequestException as exc:
        logger.debug("CLEARNET FAILED | engine=%s: %s", engine_name, exc)
        nethealth.record(engine_key, False, nethealth.ENGINE_FAILURE_THRESHOLD)
        return []
    except Exception as exc:
        logger.debug("CLEARNET PARSE FAILED | engine=%s: %s", engine_name, exc)
        return []


def get_clearnet_results(query, max_workers=None, budget_seconds=None,
                         max_results=None, use_cache=True):
    """ค้น clearnet หลาย engine พร้อมกัน แล้ว dedupe — สัญญาเดียวกับ
    get_search_results() ทุกประการ (คืน [] เสมอเมื่อล้มเหลว ไม่ raise)"""
    query = " ".join(str(query or "").split())[:SEARCH_MAX_QUERY_CHARS]
    if not query or not CLEARNET_ENABLED:
        return []

    engines = _active_clearnet_engines()
    if not engines:
        return []

    workers = max(1, min(int(max_workers or CLEARNET_MAX_WORKERS), len(engines)))
    budget = float(budget_seconds) if budget_seconds else SEARCH_TOTAL_BUDGET_SECONDS
    cap = int(max_results) if max_results else SEARCH_MAX_RESULTS

    cache_key = f"clearnet|{query}|{cap}"
    if use_cache:
        cached = _cache_get(cache_key)
        if cached is not None:
            logger.info("CLEARNET CACHE HIT | query=%r results=%d", query, len(cached))
            return cached

    started = time.monotonic()
    deadline = started + budget
    seen_links = set()
    unique_results = []
    engines_ok = 0

    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {
            executor.submit(fetch_clearnet_results, endpoint, query, deadline): endpoint
            for endpoint in engines
        }
        try:
            for future in as_completed(futures, timeout=budget):
                try:
                    results = future.result()
                except Exception as exc:
                    logger.debug("CLEARNET WORKER CRASHED | %s", exc)
                    continue
                if not results:
                    continue
                engines_ok += 1
                for res in results:
                    key = (res.get("link") or "").rstrip("/").lower()
                    if not key or key in seen_links:
                        continue
                    seen_links.add(key)
                    unique_results.append(res)
                if SEARCH_EARLY_STOP and len(unique_results) >= cap:
                    break
        except FuturesTimeout:
            logger.warning("CLEARNET BUDGET TIMEOUT | query=%r budget=%.1fs", query, budget)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    unique_results = unique_results[:cap]
    if use_cache and unique_results:
        _cache_put(cache_key, unique_results)

    logger.info(
        "CLEARNET DONE | query=%r engines_ok=%d/%d unique=%d elapsed=%.1fs",
        query, engines_ok, len(engines), len(unique_results), time.monotonic() - started,
    )
    return unique_results


def get_combined_results(query, budget_seconds=None, max_results=None,
                         include_clearnet=True, include_darkweb=True, use_cache=True):
    """ค้น clearnet และ dark web พร้อมกัน แล้วรวมผลโดยติดป้ายว่ามาจากฝั่งไหน

    ยิงสองฝั่งขนานกัน ไม่ใช่ต่อคิวกัน เวลารวมจึงเท่ากับฝั่งที่ช้ากว่า
    ไม่ใช่ผลบวกของทั้งสองฝั่ง
    """
    tasks = []
    if include_clearnet and CLEARNET_ENABLED:
        tasks.append(("clearnet", get_clearnet_results))
    if include_darkweb:
        tasks.append(("darkweb", get_search_results))
    if not tasks:
        return []

    merged = []
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        # ทั้งสองฟังก์ชันมีลำดับพารามิเตอร์เหมือนกัน
        # (query, max_workers, budget_seconds, max_results, use_cache)
        futures = {
            executor.submit(fn, query, None, budget_seconds, max_results, use_cache): origin
            for origin, fn in tasks
        }
        for future in as_completed(futures):
            origin = futures[future]
            try:
                results = future.result() or []
            except Exception as exc:
                logger.warning("COMBINED SEARCH FAILED | origin=%s: %s", origin, exc)
                continue
            for item in results:
                item.setdefault("origin", origin)
                merged.append(item)

    seen, unique = set(), []
    for item in merged:
        key = (item.get("link") or "").rstrip("/").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique[: (max_results or SEARCH_MAX_RESULTS)]


async def get_combined_results_async(query, budget_seconds=None, max_results=None,
                                     include_clearnet=True, include_darkweb=True,
                                     use_cache=True):
    return await asyncio.to_thread(
        get_combined_results, query, budget_seconds, max_results,
        include_clearnet, include_darkweb, use_cache,
    )
