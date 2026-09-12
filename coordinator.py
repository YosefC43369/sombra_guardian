"""
coordinator.py — Phase 8: Coordinator / Parallel Worker Agents

Sits between app.py's check_gemini_mention() and gemini.ask_gemini().
Every worker below is a thin wrapper around a function that already
exists in security.py / analytics.py / detection.py / news.py /
gemini.py / quota.py — nothing is re-implemented.

Design constraints:
  - LOW complexity -> identical to pre-Coordinator behavior: exactly one
    gemini.ask_gemini(question) call, no workers, no extra latency, no
    extra AI cost.
  - security/analytics workers are local SQLite reads: zero network
    calls, zero AI quota cost.
  - The only extra AI cost this file can introduce is (a) one
    classify_spam() call in the Detection Worker, gated by the existing
    quota.check_and_use_classifier_quota(), and (b) one verification
    pass for HIGH complexity requests only (toggleable, see
    COORDINATOR_VERIFICATION_ENABLED). The per-user ask quota
    (quota.check_and_use_quota) is checked exactly once by app.py,
    same as before this file existed.
  - One worker failing/timing out never fails the request — Coordinator
    always has a plain-answer fallback.
  - No shell/code execution, no dynamic dispatch by name-from-user-input:
    each worker calls one fixed, pre-existing, read-only function.
"""

import os
import time
import asyncio
import logging
import search
import scrape
import osint
import username_osint
from dataclasses import dataclass
from typing import Optional, List, Tuple

import news
import gemini
from security import get_behavior
from analytics import get_group_summary
from detection import extract_urls
from quota import check_and_use_classifier_quota

logger = logging.getLogger("modbot.coordinator")


def _env_int(name, default):
    """os.getenv(name, default) คืน "" เมื่อ .env ตั้งคีย์ไว้แต่ปล่อยค่าว่าง
    ไม่ได้คืน default — int("") จึงระเบิดตั้งแต่ตอน import ทำให้บอทไม่สตาร์ทเลย
    (.env ที่ commit ไว้ตั้ง COORDINATOR_MAX_WORKERS= ว่างไว้จริงๆ)"""
    try:
        return int(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        logger.warning("COORDINATOR CONFIG | %s is not an int, using default %s", name, default)
        return int(default)


def _env_float(name, default):
    try:
        return float(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        logger.warning("COORDINATOR CONFIG | %s is not a float, using default %s", name, default)
        return float(default)


def _env_bool(name, default):
    value = str(os.getenv(name, default)).strip().lower()
    if not value:
        value = str(default).strip().lower()
    return value in ("true", "1", "yes", "on")


# ---------------- Config ----------------

COORDINATOR_MAX_WORKERS = _env_int("COORDINATOR_MAX_WORKERS", 3)

# ---------------- OSINT collection (preset personal_identity / corporate_espionage) ----------------
# ทุกค่ามีเพดานเวลาเพราะเส้นทางนี้ถูกเรียกตรงจาก handler ของ app.py
OSINT_MAX_QUERIES = _env_int("OSINT_MAX_QUERIES", 3)
OSINT_MAX_SOURCES = _env_int("OSINT_MAX_SOURCES", 12)
OSINT_SCRAPE_WORKERS = _env_int("OSINT_SCRAPE_WORKERS", 5)
OSINT_SEARCH_BUDGET_SECONDS = _env_float("OSINT_SEARCH_BUDGET_SECONDS", 35)
OSINT_SCRAPE_BUDGET_SECONDS = _env_float("OSINT_SCRAPE_BUDGET_SECONDS", 45)
OSINT_TOTAL_BUDGET_SECONDS = _env_float("OSINT_TOTAL_BUDGET_SECONDS", 100)
# หยุดค้นเมื่อได้ผลไม่ซ้ำครบเท่านี้ — ไม่ต้องรอ engine ที่เหลือจนหมด budget
OSINT_SEARCH_RESULT_CAP = _env_int("OSINT_SEARCH_RESULT_CAP", 24)
# scrape เป็นสองจังหวะ: ยิงชุดแรกที่ตรงเป้าที่สุดก่อน ถ้าได้หลักฐานพอก็จบ
OSINT_SCRAPE_FIRST_BATCH = _env_int("OSINT_SCRAPE_FIRST_BATCH", 6)
OSINT_MIN_VERIFIED_SOURCES = _env_int("OSINT_MIN_VERIFIED_SOURCES", 3)
# รอบสอง: เอาตัวระบุที่เพิ่งค้นเจอ (อีเมล/โปรไฟล์/เบอร์) ไปค้นต่อ
OSINT_PIVOT_ENABLED = _env_bool("OSINT_PIVOT_ENABLED", "true")
OSINT_PIVOT_QUERIES = _env_int("OSINT_PIVOT_QUERIES", 3)
OSINT_PIVOT_MIN_SECONDS = _env_float("OSINT_PIVOT_MIN_SECONDS", 20)
# ฝั่งที่จะค้น — เว็บเปิดคือที่ที่ข้อมูลตัวตนบุคคลอยู่จริง
OSINT_INCLUDE_CLEARNET = _env_bool("OSINT_INCLUDE_CLEARNET", "true")
OSINT_INCLUDE_DARKWEB = _env_bool("OSINT_INCLUDE_DARKWEB", "true")
# ค้นบัญชีข้ามเว็บจากชื่อบัญชีที่เจอในรอบแรก (ใช้ฐานข้อมูลเว็บใน resource/data.json)
OSINT_USERNAME_ENUM = _env_bool("OSINT_USERNAME_ENUM", "true")
OSINT_USERNAME_MAX_HANDLES = _env_int("OSINT_USERNAME_MAX_HANDLES", 2)
OSINT_USERNAME_BUDGET_SECONDS = _env_float("OSINT_USERNAME_BUDGET_SECONDS", 25)
# เว้นที่ให้คำสั่งงาน + ข้อความกรอบ ก่อนถึงเพดาน prompt ของ gemini
_DOSSIER_RESERVED_CHARS = 1500
COORDINATOR_VERIFICATION_ENABLED = _env_bool("COORDINATOR_VERIFICATION_ENABLED", "true")

WORKER_TIMEOUT_LOCAL = 5        # security / analytics: local SQLite reads
WORKER_TIMEOUT_NEWS = 20        # httpx fetch, bounded by news.HTTP_TIMEOUT_SECONDS
WORKER_TIMEOUT_DETECTION = 35   # may include one gemini.classify_spam() call

_WORKER_TIMEOUTS = {
    "security": WORKER_TIMEOUT_LOCAL,
    "analytics": WORKER_TIMEOUT_LOCAL,
    "news": WORKER_TIMEOUT_NEWS,
    "detection": WORKER_TIMEOUT_DETECTION,
}

CONTEXT_SNIPPET_MAX_CHARS = 500     # per-worker cap fed into the final prompt
MAX_CONTEXT_WORKERS_IN_PROMPT = 3   # never stuff more than N worker results into one prompt

# Coarse local router — intentionally NOT an AI call, this must stay free.
_SECURITY_KEYWORDS = (
    "ปลอดภัย", "เสี่ยง", "ความเสี่ยง", "สแปม", "หลอกลวง", "มิจฉาชีพ",
    "แฮก", "แฮ็ก", "มัลแวร์", "ไวรัส", "โดเมน", "ฟิชชิ่ง",
    "spam", "scam", "phishing", "hack", "malware", "virus", "risk",
)
_ANALYTICS_KEYWORDS = (
    "สถิติ", "ภาพรวมกลุ่ม", "คำฮิต", "แอคทีฟ", "ช่วงเวลา", "เทรนด์",
    "stat", "stats", "trend", "activity", "active",
)
_NEWS_KEYWORDS = (
    "ข่าว", "พาดหัว", "อัปเดตข่าว", "news", "headline", "hackernews", "krebs",
)

# Deliberately separate from gemini.GEMINT_PERSONA — this output is used
# for a pass/fail-style check, so it needs a neutral, predictable voice,
# same reasoning news.py already applies to its own _NEWS_SUMMARY_INSTRUCTION.
_VERIFICATION_INSTRUCTION = (
    "คุณเป็นผู้ตรวจทานความถูกต้อง (fact-checker) ไม่ใช่ตัวละครใด ๆ "
    "คุณจะได้รับ 'คำถามผู้ใช้', 'ข้อมูลประกอบ' และ 'คำตอบร่าง' "
    "ตรวจว่าคำตอบร่างขัดแย้งกับข้อมูลประกอบหรือไม่ "
    "ถ้าไม่ขัดแย้งหรือไม่มีข้อมูลพอจะตรวจ ให้ตอบคำเดียวว่า OK "
    "ถ้าขัดแย้งจริง ให้ตอบขึ้นต้นด้วย 'แก้ไข:' ตามด้วยข้อความสั้น ๆ "
    "ไม่เกิน 2 ประโยคระบุจุดที่ขัดแย้งและคำตอบที่ถูกต้อง ห้ามใส่คำอธิบายอื่น"
)

@dataclass
class WorkerResult:
    name: str
    ok: bool
    summary: str = ""
    error: str = ""
    duration_ms: int = 0


# ---------------- Routing (no AI call) ----------------

def _match_keywords(text_lower: str, keywords: Tuple[str, ...]) -> bool:
    return any(kw in text_lower for kw in keywords)


def assess_request(
    question: str, reply_text: Optional[str], has_reply_target: bool
) -> Tuple[str, List[str]]:
    """Cheap local routing decision — never calls an AI model.
    Returns (complexity, worker_names): complexity is 'LOW' | 'MEDIUM' | 'HIGH',
    worker_names is the ordered list of extra workers to run alongside the
    always-present General AI answer."""
    q = question.lower()
    combined_for_urls = f"{question}\n{reply_text or ''}"
    urls_present = bool(extract_urls(combined_for_urls))

    matched = []
    if _match_keywords(q, _SECURITY_KEYWORDS) or has_reply_target:
        matched.append("security")
    if _match_keywords(q, _ANALYTICS_KEYWORDS):
        matched.append("analytics")
    if _match_keywords(q, _NEWS_KEYWORDS):
        matched.append("news")
    if urls_present:
        matched.append("detection")

    seen = set()
    workers = [w for w in matched if not (w in seen or seen.add(w))]
    workers = workers[:COORDINATOR_MAX_WORKERS]

    if not workers:
        complexity = "LOW"
    elif len(workers) == 1 and len(question) < 300:
        complexity = "MEDIUM"
    else:
        complexity = "HIGH"

    return complexity, workers


# ---------------- Workers (each wraps ONE existing function) ----------------

async def _worker_security(
    chat_id: int, requester_id: int, requester_is_admin: bool, reply_user_id: Optional[int]
) -> WorkerResult:
    """Local-only, zero AI cost. A requester may always see their own
    risk data; seeing another member's data (reply_user_id) requires
    admin — same permission boundary as the existing /warnings command."""
    t0 = time.monotonic()
    target_id, label = requester_id, "คุณ"
    if reply_user_id is not None:
        if not requester_is_admin:
            return WorkerResult(name="security", ok=False,
                                 error="reply target requires admin, skipped")
        target_id, label = reply_user_id, "ผู้ใช้ที่ถูกตอบกลับ"
    try:
        behavior = get_behavior(chat_id, target_id)
    except Exception as e:
        logger.exception("COORDINATOR SECURITY WORKER ERROR")
        return WorkerResult(name="security", ok=False, error=str(e))
    summary = (
        f"ข้อมูลความเสี่ยงของ{label}: risk_score={behavior['risk_score']}/100 "
        f"({behavior['risk_level']}), เหตุการณ์สะสม={behavior['event_count']}"
    )
    return WorkerResult(name="security", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


async def _worker_analytics(chat_id: int) -> WorkerResult:
    t0 = time.monotonic()
    try:
        s = get_group_summary(chat_id, top_words=5, top_hours=3)
    except Exception as e:
        logger.exception("COORDINATOR ANALYTICS WORKER ERROR")
        return WorkerResult(name="analytics", ok=False, error=str(e))
    words = ", ".join(f"{w}({c})" for w, c in s["top_words"]) or "-"
    summary = f"สถิติกลุ่ม: ข้อความรวม={s['total_messages']}, คำฮิต={words}"
    return WorkerResult(name="analytics", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


async def _worker_news() -> WorkerResult:
    t0 = time.monotonic()
    try:
        items = await news.get_latest_headlines(limit=5)
    except Exception as e:
        logger.exception("COORDINATOR NEWS WORKER ERROR")
        return WorkerResult(name="news", ok=False, error=str(e))
    if not items:
        return WorkerResult(name="news", ok=False, error="no items")
    summary = "ข่าวล่าสุดที่ระบบติดตาม: " + "; ".join(it.title for it in items[:5])
    return WorkerResult(name="news", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


async def _worker_detection(chat_id: int, text_to_check: str) -> WorkerResult:
    """Read-only pattern analysis — never calls security.record_event;
    that stays the job of the live moderation path in app.py/detection.py.
    Optionally asks Gemini's dormant classify_spam() for a second opinion,
    gated by the existing chat-wide classifier quota (not the per-user one)."""
    t0 = time.monotonic()
    urls = extract_urls(text_to_check)
    findings = [f"พบลิงก์ {len(urls)} รายการ"] if urls else []

    allowed, used, limit = check_and_use_classifier_quota(chat_id)
    if allowed:
        try:
            ok, result = await gemini.classify_spam(text_to_check)
            if ok and result:
                findings.append(
                    f"AI ประเมิน: is_spam={result['is_spam']} "
                    f"category={result['category']} conf={result['confidence']:.2f}"
                )
        except Exception:
            logger.exception("COORDINATOR DETECTION WORKER classify_spam ERROR")
    else:
        logger.info(f"COORDINATOR DETECTION WORKER | classifier quota exhausted ({used}/{limit})")

    if not findings:
        return WorkerResult(name="detection", ok=False, error="nothing notable found")
    summary = "ผลตรวจข้อความ: " + "; ".join(findings)
    return WorkerResult(name="detection", ok=True, summary=summary[:CONTEXT_SNIPPET_MAX_CHARS],
                         duration_ms=int((time.monotonic() - t0) * 1000))


def _build_worker_coro(name, chat_id, user_id, is_admin, reply_user_id, reply_text, question):
    if name == "security":
        return _worker_security(chat_id, user_id, is_admin, reply_user_id)
    if name == "analytics":
        return _worker_analytics(chat_id)
    if name == "news":
        return _worker_news()
    if name == "detection":
        return _worker_detection(chat_id, reply_text if reply_text else question)
    raise ValueError(f"unknown worker: {name}")


async def _run_worker(name: str, coro) -> WorkerResult:
    try:
        return await asyncio.wait_for(coro, timeout=_WORKER_TIMEOUTS.get(name, WORKER_TIMEOUT_LOCAL))
    except asyncio.TimeoutError:
        logger.warning(f"COORDINATOR WORKER TIMEOUT | worker={name}")
        return WorkerResult(name=name, ok=False, error="timeout")
    except Exception as e:
        logger.exception(f"COORDINATOR WORKER CRASHED | worker={name}")
        return WorkerResult(name=name, ok=False, error=str(e))


# ---------------- Main entry point ----------------

async def _run_search_round(queries, budget_seconds):
    """ยิงทุก query ของรอบนี้พร้อมกัน ทั้ง clearnet และ dark web
    คืน (list ของกลุ่มผลลัพธ์, จำนวนผลดิบรวม)"""
    if not queries:
        return [], 0
    groups = await asyncio.gather(
        *[
            asyncio.to_thread(
                search.get_combined_results, q, budget_seconds, OSINT_SEARCH_RESULT_CAP,
                OSINT_INCLUDE_CLEARNET, OSINT_INCLUDE_DARKWEB, True,
            )
            for q in queries
        ],
        return_exceptions=True,
    )
    clean = []
    for query, group in zip(queries, groups):
        if isinstance(group, BaseException):
            logger.warning("OSINT SEARCH FAILED | query=%r: %s", query, group)
            continue
        clean.append(group)
    return clean, sum(len(g) for g in clean)


async def _scrape_and_assess(ranked, selectors, budget_seconds, scraped=None):
    """ดึงเนื้อหา -> ยืนยันด้วยเนื้อหา -> เชื่อมโยงตัวตน
    ส่ง `scraped` เดิมเข้ามาเพื่อไม่ให้ดึงหน้าที่เคยดึงไปแล้วซ้ำ"""
    scraped = dict(scraped or {})
    pending = [r for r in ranked if r.get("link") not in scraped]
    scraped_now = 0
    if pending:
        fresh = await asyncio.to_thread(
            scrape.scrape_multiple, pending, OSINT_SCRAPE_WORKERS,
            budget_seconds, len(pending),
        )
        scraped.update(fresh)
        scraped_now = len(pending)

    sources = osint.verify_sources(
        osint.build_sources(ranked, scraped, scrape.CONTENT_UNAVAILABLE_MARKER), selectors
    )
    identity = osint.build_identity(sources, selectors)
    return sources, scraped, identity, scraped_now


def _handles_to_enumerate(identity, selectors, limit):
    """ชื่อบัญชีที่ควรเอาไปค้นข้ามเว็บ — ที่ยืนยันแล้วมาก่อนเบาะแส"""
    out, seen = [], set()
    for link in list(identity.confirmed()) + list(identity.leads()):
        if link.kind == "profile":
            handle = link.value.split(":", 1)[-1]
        elif link.kind == "handle":
            handle = link.value
        elif link.kind == "email":
            handle = link.value.split("@", 1)[0]   # ชื่อบัญชีมักซ้ำกับส่วนหน้าอีเมล
        else:
            continue
        key = handle.lower()
        if key in seen or not username_osint.is_plausible_username(handle):
            continue
        seen.add(key)
        out.append(handle)
        if len(out) >= limit:
            break
    return out


async def _username_round(identity, selectors, budget_seconds):
    """ค้นบัญชีชื่อเดียวกันข้ามเว็บ แล้วคืนผลในรูปแบบเดียวกับผลค้นหา

    นี่คือส่วนที่หยิบความสามารถของ sites.py/checkings.py/maigret.py มาใช้จริง
    ผลที่ได้ไหลเข้าท่อเดิมทั้งหมด (จัดอันดับ -> ดึงเนื้อหา -> ยืนยัน -> เชื่อมตัวตน)
    จึงไม่มีการ "เชื่อว่าเป็นคนเดียวกัน" เพียงเพราะชื่อบัญชีตรงกัน
    """
    handles = _handles_to_enumerate(identity, selectors, OSINT_USERNAME_MAX_HANDLES)
    if not handles:
        return [], []

    per_handle = max(6.0, budget_seconds / len(handles))
    groups = await asyncio.gather(
        *[
            asyncio.to_thread(
                username_osint.check_username_as_results, h, 0, per_handle, None
            )
            for h in handles
        ],
        return_exceptions=True,
    )
    clean = []
    for handle, group in zip(handles, groups):
        if isinstance(group, BaseException):
            logger.warning("OSINT USERNAME FAILED | handle=%r: %s", handle, group)
            continue
        if group:
            logger.info("OSINT USERNAME | %r เจอ %d เว็บ", handle, len(group))
        clean.append(group)
    return clean, handles


async def _collect_osint_evidence(question: str):
    """เก็บหลักฐานตามวงจรข่าวกรอง แล้วคืน (dossier, stats)

    รอบที่ 1  วางแผนจาก selector -> ค้น clearnet + dark web พร้อมกัน ->
              จัดอันดับ -> ดึงเนื้อหาชุดที่ตรงเป้าที่สุด -> ยืนยันด้วยเนื้อหา
    รอบที่ 2  เอาตัวระบุที่เพิ่งได้ (อีเมล/โปรไฟล์/เบอร์) ไปค้นต่อ แล้วรวม
              ผลเข้ากับรอบแรก — นี่คือขั้นที่พาไปเจอแหล่งที่ค้นด้วยชื่อ
              เปล่าๆ ไม่มีทางเจอ
    ปิดท้าย   สกัด IOC, นับการยืนยันข้ามแหล่ง, สรุปกราฟตัวตน, ประกอบ dossier

    ทุกขั้นใช้ deadline ร่วมอันเดียว เวลาที่เหลือจากขั้นก่อนตกเป็นของขั้นถัดไป
    """
    deadline = time.monotonic() + OSINT_TOTAL_BUDGET_SECONDS

    def _left(floor=0.0):
        return max(floor, deadline - time.monotonic())

    selectors = osint.extract_selectors(question)
    queries = osint.plan_queries(question, selectors, max_queries=OSINT_MAX_QUERIES)
    logger.info("OSINT PLAN | selectors=%s | queries=%s", selectors.summary(), queries)

    groups, raw_total = await _run_search_round(
        queries, min(OSINT_SEARCH_BUDGET_SECONDS, _left(5.0))
    )
    ranked = osint.merge_and_rank(groups, selectors, limit=OSINT_MAX_SOURCES)
    if not ranked:
        logger.info("OSINT COLLECTION EMPTY | queries=%s raw=%d", queries, raw_total)
        return None, {"sources": 0, "retrieved": 0, "on_target": 0, "gaps": 0, "iocs": 0,
                      "corroborated_iocs": 0, "identity_confirmed": 0, "identity_leads": 0,
                      "queries": queries, "pivots": [], "rounds": 1}

    # ---- ดึงเนื้อหาชุดแรก (ตัวที่ตรงเป้าที่สุด) ----
    batch = ranked[: max(1, OSINT_SCRAPE_FIRST_BATCH)]
    scrape_passes = 0
    sources, scraped, identity, did = await _scrape_and_assess(
        batch, selectors, min(OSINT_SCRAPE_BUDGET_SECONDS, _left(5.0))
    )
    scrape_passes += 1 if did else 0
    verified = sum(1 for s in sources if s.on_target)

    # ---- หลักฐานยังไม่พอ: ดึงแหล่งที่เหลือของรอบแรกต่อ ----
    if verified < OSINT_MIN_VERIFIED_SOURCES and len(ranked) > len(batch) and _left() > 8.0:
        logger.info("OSINT SECOND PASS | verified=%d/%d ดึงต่ออีก %d แหล่ง",
                    verified, OSINT_MIN_VERIFIED_SOURCES, len(ranked) - len(batch))
        sources, scraped, identity, did = await _scrape_and_assess(
            ranked, selectors, min(OSINT_SCRAPE_BUDGET_SECONDS, _left(5.0)), scraped
        )
        scrape_passes += 1 if did else 0
        verified = sum(1 for s in sources if s.on_target)

    # ---- รอบที่ 2: ค้นต่อจากตัวระบุที่เพิ่งเจอ ----
    # สองงานนี้เป็นอิสระจากกัน: ค้นซ้ำด้วย query ใหม่ กับ ค้นบัญชีชื่อเดียวกัน
    # ข้ามเว็บ อย่างหลังต้องทำได้แม้ไม่มี query ใหม่ให้ยิง (เช่นเจอแต่โปรไฟล์)
    pivots: list = []
    handles: list = []
    pivot_groups: list = []
    username_groups: list = []
    rounds = 1

    if OSINT_PIVOT_ENABLED and _left() > OSINT_PIVOT_MIN_SECONDS:
        pivots = osint.pivot_queries(
            identity, selectors, already_used=queries, max_queries=OSINT_PIVOT_QUERIES
        )
        if pivots:
            logger.info("OSINT PIVOT | ค้นต่อด้วยตัวระบุที่เพิ่งเจอ: %s", pivots)
            pivot_groups, pivot_raw = await _run_search_round(
                pivots, min(OSINT_SEARCH_BUDGET_SECONDS, _left(5.0))
            )
            raw_total += pivot_raw

    if OSINT_USERNAME_ENUM and _left() > 10.0:
        username_groups, handles = await _username_round(
            identity, selectors, min(OSINT_USERNAME_BUDGET_SECONDS, _left(5.0))
        )
        raw_total += sum(len(g) for g in username_groups)

    if pivot_groups or username_groups:
        rounds = 2
        merged_ranked = osint.merge_and_rank(
            groups + pivot_groups + username_groups,
            selectors, limit=OSINT_MAX_SOURCES * 2,
        )
        if _left() > 5.0:
            sources, scraped, identity, did = await _scrape_and_assess(
                merged_ranked, selectors,
                min(OSINT_SCRAPE_BUDGET_SECONDS, _left(5.0)), scraped,
            )
            scrape_passes += 1 if did else 0
            verified = sum(1 for s in sources if s.on_target)

    ioc_index = osint.build_ioc_index(sources)
    osint.apply_corroboration(sources, ioc_index)

    stats = osint.collect_stats(sources, ioc_index)
    stats.update(osint.identity_stats(identity))
    stats["queries"] = queries
    stats["pivots"] = pivots
    stats["rounds"] = rounds
    stats["username_sources"] = sum(1 for s in sources if s.origin == "username")
    stats["username_handles"] = handles
    stats["scrape_passes"] = scrape_passes
    stats["clearnet_sources"] = sum(1 for s in sources if s.origin == "clearnet")
    stats["darkweb_sources"] = sum(1 for s in sources if s.origin == "darkweb")

    dossier = osint.build_dossier(
        question, selectors, queries + pivots, sources, ioc_index,
        max_chars=max(2000, gemini.RESEARCH_MAX_INPUT_CHARS - _DOSSIER_RESERVED_CHARS),
        engines_total=raw_total, identity=identity,
    )
    logger.info(
        "OSINT COLLECTED | rounds=%d sources=%d (clearnet=%d darkweb=%d username=%d) retrieved=%d "
        "on_target=%d identity_confirmed=%d leads=%d iocs=%d dossier_chars=%d elapsed=%.1fs",
        rounds, stats["sources"], stats["clearnet_sources"], stats["darkweb_sources"],
        stats["username_sources"],
        stats["retrieved"], stats["on_target"], stats["identity_confirmed"],
        stats["identity_leads"], stats["iocs"], len(dossier),
        OSINT_TOTAL_BUDGET_SECONDS - _left(),
    )
    return dossier, stats


_NO_EVIDENCE_BLOCK = (
    "[INTELLIGENCE DOSSIER]\n"
    "การเก็บข้อมูลรอบนี้ไม่ได้ผลลัพธ์ใดๆ — ไม่มีแหล่งข่าว ไม่มีเนื้อหา ไม่มี IOC\n"
    "สาเหตุที่เป็นไปได้: Tor ไม่ได้รันอยู่, tor2web gateway ล่ม, "
    "หรือ selector ไม่ตรงกับสิ่งที่ถูก index ไว้\n"
    "ให้รายงานตรงๆ ว่าไม่มีหลักฐาน ระบุว่านี่คือช่องว่างข่าวกรอง "
    "และเสนอขั้นตอนการเก็บข้อมูลถัดไป ห้ามสร้างข้อค้นพบขึ้นมาเองจากความรู้ทั่วไป"
)


async def handle_request(
    *,
    chat_id: int,
    user_id: int,
    is_admin: bool,
    question: str,
    preset: str = "threat_intel",
    custom_instructions: str = "",
    reply_user_id: Optional[int] = None,
    reply_text: Optional[str] = None,
    media: Optional[List[Tuple[bytes, str]]] = None,
) -> Tuple[bool, str]:
    """Drop-in replacement for `await gemini.ask_gemini(question)` — same
    (ok, text) contract. LOW complexity takes the exact pre-Coordinator
    path: one ask_gemini() call, nothing else."""
    if preset in {"personal_identity", "corporate_espionage"}:
        try:
            dossier, stats = await asyncio.wait_for(
                _collect_osint_evidence(question), timeout=OSINT_TOTAL_BUDGET_SECONDS
            )
        except asyncio.TimeoutError:
            logger.warning("OSINT COLLECTION TIMEOUT | chat=%s budget=%.0fs",
                           chat_id, OSINT_TOTAL_BUDGET_SECONDS)
            dossier, stats = None, {}
        except Exception:
            logger.exception("OSINT COLLECTION CRASHED | chat=%s", chat_id)
            dossier, stats = None, {}

        # ไม่มีหลักฐาน = ต้องบอกโมเดลว่าไม่มี ไม่ใช่ปล่อยให้ตอบจากความรู้ทั่วไป
        # (ของเดิม fallback ไป ask_gemini เปล่าๆ ซึ่งเปิดทางให้แต่งข้อค้นพบขึ้นมาเอง)
        evidence_block = dossier if dossier else _NO_EVIDENCE_BLOCK

        research_prompt = (
            f"คำสั่งงานข่าวกรอง: {question}\n\n"
            f"{evidence_block}\n\n"
            "[คำสั่งปิดท้าย] วิเคราะห์โดยใช้เฉพาะหลักฐานข้างบนเท่านั้น "
            "อ้างอิงทุกข้อเท็จจริงด้วยรหัสแหล่ง [S#] และรายงานช่องว่างข่าวกรองตามจริง"
        )
        limit = gemini.RESEARCH_MAX_INPUT_CHARS
        if len(research_prompt) > limit:
            research_prompt = research_prompt[:limit]
            logger.warning("OSINT PROMPT CLAMPED | chat=%s to %d chars", chat_id, limit)

        logger.info("OSINT REQUEST | chat=%s preset=%s stats=%s prompt_chars=%d",
                    chat_id, preset, stats, len(research_prompt))
        return await gemini.ask_gemini(
            research_prompt,
            preset=preset,
            custom_instructions=custom_instructions,
            media=media,
            max_input_chars=limit,
        )

    if media:
        return await gemini.ask_gemini(
            question,
            preset=preset,
            custom_instructions=custom_instructions,
            media=media,
        )
        
    complexity, worker_names = assess_request(question, reply_text, reply_user_id is not None)
    logger.info(f"COORDINATOR ROUTE | chat={chat_id} user={user_id} "
                f"complexity={complexity} workers={worker_names}")

    if complexity == "LOW" or not worker_names:
        return await gemini.ask_gemini(
            question,
            preset=preset,
            custom_instructions=custom_instructions,
        )

    t_start = time.monotonic()
    coros = [
        _run_worker(name, _build_worker_coro(name, chat_id, user_id, is_admin,
                                              reply_user_id, reply_text, question))
        for name in worker_names
    ]
    raw_results = await asyncio.gather(*coros, return_exceptions=True)

    results: List[WorkerResult] = []
    for name, r in zip(worker_names, raw_results):
        if isinstance(r, WorkerResult):
            results.append(r)
        else:
            logger.exception(f"COORDINATOR WORKER UNCAUGHT EXCEPTION | worker={name}")
            results.append(WorkerResult(name=name, ok=False, error=str(r)))

    successful = [r for r in results if r.ok][:MAX_CONTEXT_WORKERS_IN_PROMPT]
    failed = [r for r in results if not r.ok]
    for r in failed:
        logger.info(f"COORDINATOR WORKER SKIPPED | worker={r.name} | reason={r.error}")

    if not successful:
        # every worker failed/skipped/quota-exhausted — never fail the
        # whole request over missing enrichment, fall back to plain answer
        return await gemini.ask_gemini(question)

    context_block = "\n".join(f"- {r.summary}" for r in successful)
    enriched_prompt = (
        f"{question}\n\n"
        f"[ข้อมูลประกอบจากระบบ ใช้เสริมคำตอบถ้าเกี่ยวข้อง ไม่ต้องพูดถึงถ้าไม่เกี่ยวกับคำถาม]\n"
        f"{context_block}"
    )

    ok, draft = await gemini.ask_gemini(
        enriched_prompt,
        preset=preset,
        custom_instructions=custom_instructions,
    
    )
    if not ok:
        return ok, draft

    ai_calls = 1
    needs_verification = (
        COORDINATOR_VERIFICATION_ENABLED and complexity == "HIGH" and bool(successful)
    )
    if needs_verification:
        ai_calls += 1
        verify_prompt = (
            f"คำถามผู้ใช้: {question}\n\n"
            f"ข้อมูลประกอบ:\n{context_block}\n\n"
            f"คำตอบร่าง: {draft[:1500]}"
        )
        v_ok, v_text = await gemini.ask_gemini(verify_prompt, system_instruction=_VERIFICATION_INSTRUCTION)
        if v_ok and not v_text.strip().upper().startswith("OK"):
            logger.info(f"COORDINATOR VERIFICATION FLAGGED | chat={chat_id} | note={v_text[:200]!r}")
            draft = f"{draft}\n\n🔎 ตรวจทานเพิ่มเติม: {v_text.strip()[:300]}"

    logger.info(
        f"COORDINATOR DONE | chat={chat_id} complexity={complexity} "
        f"workers_ok={[r.name for r in successful]} workers_failed={[r.name for r in failed]} "
        f"ai_calls={ai_calls} duration_ms={int((time.monotonic() - t_start) * 1000)}"
    )
    return True, draft