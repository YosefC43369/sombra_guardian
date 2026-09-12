import os
import socket
import time
import asyncio
import random
import requests
import threading
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

import nethealth

import warnings
warnings.filterwarnings("ignore")

# Define a list of rotating user agents.
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

_logger = logging.getLogger("modbot.scrape")

# config ของ Tor/gateway และตัวอ่าน env อยู่ที่ nethealth.py ที่เดียว
# (.env ที่ commit ไว้ตั้ง TOR_GATEWAY_SUFFIXES= ว่าง ซึ่งเดิมแปลว่า "ไม่มี
#  gateway สำรองเลย" — nethealth ถือว่าค่าว่าง = ใช้ default)
TOR_GATEWAY_SUFFIXES = nethealth.TOR_GATEWAY_SUFFIXES
_env_int = nethealth.env_int
_env_float = nethealth.env_float


def _onion_to_gateway(url, suffix):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host.endswith(".onion"):
        return url
    netloc = host + suffix
    if parsed.port:
        netloc += f":{parsed.port}"
    return parsed._replace(scheme="https", netloc=netloc).geturl()


MAX_DOWNLOAD_BYTES = _env_int("SCRAPE_MAX_DOWNLOAD_BYTES", 1_000_000)
MAX_EXTRACTED_TEXT_CHARS = _env_int("SCRAPE_MAX_EXTRACTED_TEXT_CHARS", 50_000)
MAX_RETURN_CHARS = _env_int("SCRAPE_MAX_RETURN_CHARS", 2_000)
TOR_SOCKS_HOST = nethealth.TOR_SOCKS_HOST
TOR_SOCKS_PORT = nethealth.TOR_SOCKS_PORT
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

# ---------------- Limits (เรียกผ่าน coordinator จาก handler ของ app.py: ต้องมีเพดานเวลาเสมอ) ----------------
SCRAPE_CONNECT_TIMEOUT = _env_float("SCRAPE_CONNECT_TIMEOUT", 10)
SCRAPE_READ_TIMEOUT = _env_float("SCRAPE_READ_TIMEOUT", 25)
SCRAPE_TOTAL_BUDGET_SECONDS = _env_float("SCRAPE_TOTAL_BUDGET_SECONDS", 60)
SCRAPE_MAX_URLS = _env_int("SCRAPE_MAX_URLS", 20)
# "auto" = ใช้ Tor ถ้า SOCKS port เปิดอยู่, "true"/"false" = บังคับ
SCRAPE_USE_TOR = os.getenv("SCRAPE_USE_TOR", "auto").strip().lower()
TOR_PROBE_TTL_SECONDS = nethealth.TOR_PROBE_TTL_SECONDS
# บอกโมเดลให้ชัดว่าแหล่งนี้ดึงเนื้อหาไม่ได้ ไม่งั้น coordinator จะส่งแค่ "ชื่อเรื่อง"
# เข้าไปใน [SCRAPED EVIDENCE] แล้วโมเดลเข้าใจผิดว่านั่นคือเนื้อหาที่ยืนยันได้
CONTENT_UNAVAILABLE_MARKER = "[content unavailable]"

_thread_local = threading.local()


def _tor_reachable(timeout=2.0, force=False) -> bool:
    """ใช้ probe ร่วมกับ search.py ผ่าน nethealth — scrape_multiple() ยิงพร้อมกัน
    หลาย thread ถ้าเปิด socket ทดสอบใหม่ทุก URL คือเสียเวลาเปล่าล้วนๆ"""
    return nethealth.tor_reachable(timeout=timeout, force=force)


def _tor_enabled() -> bool:
    if SCRAPE_USE_TOR in ("false", "0", "off", "no"):
        return False
    if SCRAPE_USE_TOR in ("true", "1", "on", "yes"):
        return True
    return _tor_reachable()


def _normalize_url_data(url_data):
    """รับได้ทั้ง dict ที่ search.py คืนมา และ str ธรรมดา เผื่อ app.py
    ส่งลิสต์ URL ล้วนๆ เข้ามาเอง (เช่น จากคำสั่งที่ผู้ใช้พิมพ์ลิงก์มาตรงๆ)"""
    if isinstance(url_data, str):
        return url_data.strip(), "Untitled"
    if not isinstance(url_data, dict):
        return "", "Untitled"
    url = str(url_data.get("link") or "").strip()
    title = str(url_data.get("title") or "Untitled").strip() or "Untitled"
    return url, title


def _remaining(deadline):
    if deadline is None:
        return None
    return deadline - time.monotonic()


def _timeout_for(deadline, is_onion):
    """(connect, read) ที่ไม่มีทางเกินเวลาที่เหลือของ budget รวม
    คืน None เมื่อหมดเวลาแล้ว (ผู้เรียกต้องเลิกยิงต่อ)"""
    connect_timeout = SCRAPE_CONNECT_TIMEOUT if is_onion else max(SCRAPE_CONNECT_TIMEOUT / 2, 3.0)
    read_timeout = SCRAPE_READ_TIMEOUT
    left = _remaining(deadline)
    if left is not None:
        if left <= 0:
            return None
        connect_timeout = min(connect_timeout, max(left, 1.0))
        read_timeout = min(read_timeout, max(left, 1.0))
    return (connect_timeout, read_timeout)


def _build_session(use_tor=False):
    session = requests.Session()
    retry = Retry(
        total=2,
        # read=0: read-timeout ต้องไม่ retry — ของเดิม read=3 + read timeout 30s
        # แปลว่า URL เดียวกินได้ถึง ~120s ต่อ 1 gateway ซึ่งเป็นต้นเหตุที่
        # /identity, /corporate ใน app.py ค้างยาว
        read=0,
        connect=2,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if use_tor:
        session.proxies = {
            "http": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
        }

    return session


def _get_session(use_tor=False):
    key = "tor_session" if use_tor else "direct_session"
    if not hasattr(_thread_local, key):
        setattr(_thread_local, key, _build_session(use_tor=use_tor))
    return getattr(_thread_local, key)

def get_tor_session():
    """
    Creates a requests Session with Tor SOCKS proxy and automatic retries.
    """
    return _build_session(use_tor=True)


def _extract_text(response):
    """อ่านแบบ stream โดยไม่เกิน MAX_DOWNLOAD_BYTES แล้วถอดเป็นข้อความล้วน"""
    chunks = []
    bytes_read = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        bytes_read += len(chunk)
        if bytes_read > MAX_DOWNLOAD_BYTES:
            break
        chunks.append(chunk)

    raw = b"".join(chunks)
    if not raw:
        return ""

    html = raw.decode(response.encoding or "utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.extract()
    return ' '.join(soup.get_text(separator=' ').split())[:MAX_EXTRACTED_TEXT_CHARS]


def scrape_single(url_data, rotate=False, rotate_interval=5, control_port=9051,
                  control_password=None, deadline=None):
    """
    Scrapes a single URL. .onion URLs go through the local Tor SOCKS proxy
    when one is reachable, and fall back to a tor2web gateway (rewritten via
    TOR_GATEWAY_SUFFIXES) otherwise, failing over across suffixes since these
    gateways die often.
    Returns a tuple (url, scraped_text).

    ของเดิมบังคับ _get_session(use_tor=False) เสมอ ทั้งที่นิยาม get_tor_session()
    และ _tor_reachable() ไว้แล้ว — เครื่องที่รัน Tor อยู่จึงไม่เคยได้ใช้ Tor เลย
    """
    url, title = _normalize_url_data(url_data)
    if not url:
        return "", title

    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        _logger.debug("SCRAPE SKIPPED | unsupported scheme url=%s", url)
        return url, f"{title} - {CONTENT_UNAVAILABLE_MARKER}"

    is_onion = (parsed_url.hostname or "").lower().endswith(".onion")
    if is_onion:
        candidate_urls = []
        if _tor_enabled():
            candidate_urls.append((url, True, "tor"))
        candidate_urls.extend(
            (_onion_to_gateway(url, suffix), False, suffix) for suffix in TOR_GATEWAY_SUFFIXES
        )
        # ข้าม gateway ที่ circuit breaker พักอยู่ — ใช้ประวัติร่วมกับ search.py
        # จึงรู้ตั้งแต่ตอนค้นแล้วว่า gateway ตัวไหนตาย ไม่ต้องมาเรียนรู้ใหม่ตอน scrape
        candidate_urls = [c for c in candidate_urls if not nethealth.blocked(f"route:{c[2]}")]
        if not candidate_urls:
            _logger.debug("SCRAPE NO LIVE ROUTE | url=%s", url)
            return url, f"{title} - {CONTENT_UNAVAILABLE_MARKER}"
    else:
        candidate_urls = [(url, False, "direct")]

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    }

    for candidate, use_tor, route in candidate_urls:
        route_key = f"route:{route}"
        timeout = _timeout_for(deadline, is_onion)
        if timeout is None:
            _logger.debug("SCRAPE BUDGET EXHAUSTED | url=%s", url)
            break

        response = None
        try:
            response = _get_session(use_tor=use_tor).get(
                candidate, headers=headers, timeout=timeout, stream=True
            )
            if response.status_code != 200:
                _logger.debug(
                    "SCRAPE NON-200 | url=%s route=%s status=%s", url, route, response.status_code
                )
                # เช่นเดียวกับ search.py: 404 ไม่ใช่ความผิดของ gateway
                if is_onion and (response.status_code >= 500 or response.status_code == 429):
                    nethealth.record(route_key, False, nethealth.ROUTE_FAILURE_THRESHOLD)
                continue

            if is_onion:
                nethealth.record(route_key, True, nethealth.ROUTE_FAILURE_THRESHOLD)

            content_type = (response.headers.get("Content-Type") or "").lower()
            if content_type and not any(t in content_type for t in ALLOWED_CONTENT_TYPES):
                _logger.debug("SCRAPE SKIPPED | url=%s content-type=%s", url, content_type)
                return url, f"{title} - {CONTENT_UNAVAILABLE_MARKER}"

            text = _extract_text(response)
            return url, (f"{title} - {text}" if text else f"{title} - {CONTENT_UNAVAILABLE_MARKER}")
        except requests.exceptions.InvalidSchema as exc:
            # socks5h ต้องมี PySocks (มีอยู่ใน requirements.txt) — ถ้าหายให้ตกไป gateway
            _logger.warning("SCRAPE TOR UNAVAILABLE | url=%s: %s", url, exc)
            if is_onion:
                nethealth.record(route_key, False, nethealth.ROUTE_FAILURE_THRESHOLD)
            continue
        except Exception as exc:
            _logger.debug("Gateway attempt failed url=%s route=%s: %s", url, route, exc)
            if is_onion:
                nethealth.record(route_key, False, nethealth.ROUTE_FAILURE_THRESHOLD)
            continue
        finally:
            if response is not None:
                response.close()

    return url, f"{title} - {CONTENT_UNAVAILABLE_MARKER}"


def _truncate(content):
    if len(content) <= MAX_RETURN_CHARS:
        return content
    suffix = "...(truncated)"
    if len(suffix) >= MAX_RETURN_CHARS:
        # Fallback: ensure we never exceed MAX_RETURN_CHARS even if suffix is long
        return suffix[:MAX_RETURN_CHARS]
    return content[: MAX_RETURN_CHARS - len(suffix)] + suffix


def scrape_multiple(urls_data, max_workers=5, budget_seconds=None, max_urls=None):
    """
    Scrapes multiple URLs concurrently using a thread pool.

    เรียกจาก coordinator._collect_darkweb_evidence() -> /identity, /corporate ใน app.py
    จึงต้องมี budget รวม และต้องไม่ raise ออกไปหา caller เด็ดขาด (คืน {} แทน)
    """
    results = {}
    if not isinstance(urls_data, (list, tuple)):
        _logger.info("SCRAPE SKIPPED | urls_data is %s, expected list/tuple", type(urls_data).__name__)
        return results

    max_workers = max(1, min(int(max_workers or 5), 16))
    budget = float(budget_seconds) if budget_seconds else SCRAPE_TOTAL_BUDGET_SECONDS
    cap = int(max_urls) if max_urls else SCRAPE_MAX_URLS
    started = time.monotonic()
    deadline = started + budget

    # Deduplicate links to reduce unnecessary requests under real workloads.
    unique_urls_data = []
    seen_links = set()
    for item in urls_data:
        url, title = _normalize_url_data(item)
        key = url.rstrip("/").lower()
        if not url or key in seen_links:
            continue
        seen_links.add(key)
        unique_urls_data.append({"link": url, "title": title})
        if len(unique_urls_data) >= cap:
            break

    if not unique_urls_data:
        return results

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        future_to_url = {
            executor.submit(scrape_single, url_data, deadline=deadline): url_data
            for url_data in unique_urls_data
        }
        try:
            for future in as_completed(future_to_url, timeout=budget):
                try:
                    url, content = future.result()
                except Exception as exc:
                    _logger.debug("Worker failed to scrape a URL: %s", exc)
                    continue
                if not url:
                    continue
                results[url] = _truncate(content or "")
        except FuturesTimeout:
            _logger.warning(
                "SCRAPE BUDGET TIMEOUT | budget=%.1fs done=%d/%d",
                budget, len(results), len(unique_urls_data),
            )
    finally:
        # ไม่รอ thread ที่ยังค้าง (แต่ละ request มี timeout ของตัวเองอยู่แล้ว)
        # ไม่งั้น handler ของ app.py จะถูกหน่วงต่อแม้จะหมด budget ไปแล้ว
        executor.shutdown(wait=False, cancel_futures=True)

    fetched = sum(1 for text in results.values() if CONTENT_UNAVAILABLE_MARKER not in text)
    _logger.info(
        "SCRAPE DONE | requested=%d returned=%d with_content=%d elapsed=%.1fs",
        len(unique_urls_data), len(results), fetched, time.monotonic() - started,
    )
    return results


# ---------------- async / Telegram helpers (สำหรับ app.py) ----------------

async def scrape_multiple_async(urls_data, max_workers=5, budget_seconds=None, max_urls=None):
    """เวอร์ชัน async สำหรับเรียกตรงจาก handler ของ app.py — ข้างในเป็น requests
    แบบ blocking ทั้งหมด ถ้าเรียกบน event loop ตรงๆ บอทจะค้างทั้งตัว"""
    return await asyncio.to_thread(
        scrape_multiple, urls_data, max_workers, budget_seconds, max_urls
    )


async def scrape_single_async(url_data, budget_seconds=None):
    """สำหรับกรณีดึงลิงก์เดียว (เช่นผู้ใช้ส่งลิงก์มาให้บอทสรุป)"""
    deadline = time.monotonic() + (float(budget_seconds) if budget_seconds
                                   else SCRAPE_TOTAL_BUDGET_SECONDS)
    return await asyncio.to_thread(scrape_single, url_data, False, 5, 9051, None, deadline)


def format_scrape_results(results, limit=None, header="📄 เนื้อหาที่ดึงได้"):
    """จัดผลลัพธ์เป็นข้อความไทยพร้อมส่งเข้า gemini.split_telegram_message() ของ app.py
    (plain text ล้วน ไม่ใส่ Markdown/HTML เพราะเนื้อหาจากเว็บมีอักขระพิเศษเยอะ
    ถ้า escape ไม่ครบ Telegram จะตีข้อความกลับทั้งก้อน)"""
    if not results:
        return "ดึงเนื้อหาจากลิงก์ไม่สำเร็จ (Tor/gateway อาจใช้งานไม่ได้ในตอนนี้)"

    items = list(results.items())[: (limit or SCRAPE_MAX_URLS)]
    lines = [f"{header} {len(items)}/{len(results)} รายการ", ""]
    for index, (url, text) in enumerate(items, start=1):
        lines.append(f"{index}. {url}\n{text}")
    return "\n\n".join(lines)
