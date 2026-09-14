"""เทส news.py — แหล่งข่าว RSS หลายเว็บ, reader-proxy fallback, สไตล์สรุปเน้นเนื้อหา

news.py import `telegram` และ `gemini` (ต้องพึ่ง openai/google) ซึ่งอาจไม่มีในเครื่อง
ทดสอบ จึง stub สองโมดูลนี้ก่อน import แล้วทดสอบเฉพาะตรรกะล้วนของ news.py
(feedparser/bs4/httpx เป็น dependency ปกติที่มีอยู่แล้ว)
"""
import sys, os, types, asyncio

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

# --- stub telegram (ไม่จำเป็นต่อการทดสอบตรรกะ และติดตั้งยากในบาง env) ---
_tg = types.ModuleType("telegram")
sys.modules["telegram"] = _tg
_tg_err = types.ModuleType("telegram.error"); _tg_err.TelegramError = Exception
sys.modules["telegram.error"] = _tg_err; _tg.error = _tg_err
_tg_const = types.ModuleType("telegram.constants")
_tg_const.ParseMode = types.SimpleNamespace(HTML="HTML")
sys.modules["telegram.constants"] = _tg_const; _tg.constants = _tg_const

# --- stub gemini (import จริงจะดึง openai/google) ---
_gem = types.ModuleType("gemini")
def _split(text, limit=4096):
    return [text[i:i + limit] for i in range(0, len(text), limit)] or [""]
_gem.split_telegram_message = _split
_gem.RESEARCH_MAX_INPUT_CHARS = 24000
_ASK = {"ok": True, "text": ""}          # ปรับผลลัพธ์ต่อเทสได้
async def _ask_gemini(prompt, system_instruction=None, max_input_chars=None):
    _ASK["last_prompt"] = prompt
    _ASK["last_cap"] = max_input_chars
    return _ASK["ok"], _ASK["text"]
_gem.ask_gemini = _ask_gemini
sys.modules["gemini"] = _gem

import news

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))


# ---------- 1. แหล่งข่าว RSS หลายเว็บ ----------
names = [s["name"] for s in news.NEWS_SOURCES]
check("sources: มีหลายแหล่ง (>=10)", len(news.NEWS_SOURCES) >= 10, len(news.NEWS_SOURCES))
for expected in ("thehackernews", "bleepingcomputer", "darkreading", "theregister",
                 "securityweek", "schneier", "therecord", "cisa", "arstechnica", "blognone"):
    check(f"sources: มี {expected}", expected in names, names)

# แหล่งใหม่ทุกแหล่งต้องมี RSS/Atom feed จริง (ให้บอตดึงเนื้อหาไปเขียนได้)
rss_sources = [s for s in news.NEWS_SOURCES if s["name"] != "hackernews"]
check("sources: แหล่ง (นอกจาก hackernews) มี feed_url ครบ",
      all(s["feed_url"].startswith("http") for s in rss_sources),
      [s["name"] for s in rss_sources if not s["feed_url"].startswith("http")])
check("sources: feed เป็น URL ที่ดูสมเหตุผล",
      all(("rss" in s["feed_url"] or "feed" in s["feed_url"] or "atom" in s["feed_url"]
           or "xml" in s["feed_url"] or "TheHackersNews" in s["feed_url"]
           or "arstechnica" in s["feed_url"])
          for s in rss_sources),
      [s["feed_url"] for s in rss_sources])

# แต่ละแหล่งมีคีย์ครบตามที่ pipeline ต้องใช้
required_keys = {"name", "feed_url", "page_url", "chat_id", "topic_id",
                 "ai_summary", "max_items_per_cycle"}
check("sources: โครงสร้างคีย์ครบทุกแหล่ง",
      all(required_keys <= set(s) for s in news.NEWS_SOURCES))


# ---------- 2. _source() helper อ่าน env และ fallback ----------
os.environ["NEWS_FEED_URL_UNITTESTSRC"] = "https://example.com/custom.xml"
os.environ["NEWS_CHAT_ID_DEFAULT"] = "-100999"
# _DEFAULT_CHAT_ID ถูกอ่านตอน import แล้ว จึงทดสอบ fallback ผ่านค่าที่โมดูลถืออยู่
s = news._source("unittestsrc", feed_default="https://fallback/feed")
check("_source: env override feed_url", s["feed_url"] == "https://example.com/custom.xml", s["feed_url"])
check("_source: chat_id fallback เป็น default ของโมดูล",
      s["chat_id"] == news._DEFAULT_CHAT_ID, (s["chat_id"], news._DEFAULT_CHAT_ID))
s2 = news._source("neversetsrc", feed_default="https://fallback/feed")
check("_source: ใช้ feed_default เมื่อไม่มี env", s2["feed_url"] == "https://fallback/feed", s2["feed_url"])


# ---------- 3. reader-proxy fallback ----------
check("reader: เปิดใช้งานโดยค่าเริ่มต้น", news.READER_FALLBACK_ENABLED is True)
check("reader: prefix ค่าเริ่มต้นเป็น r.jina.ai", news.READER_PROXY_PREFIX == "https://r.jina.ai/",
      news.READER_PROXY_PREFIX)
# ตัดหัว metadata ของ reader (Title:/URL Source:/Markdown Content:) ออกให้เหลือเนื้อ
sample = "Title: X\nURL Source: https://a\nMarkdown Content:\nเนื้อหาข่าวจริงเริ่มตรงนี้"
cleaned = news._READER_HEADER_RE.sub("", sample, count=1)
check("reader: ตัดหัว metadata เหลือเนื้อบทความ",
      cleaned.strip().startswith("เนื้อหาข่าวจริง"), repr(cleaned))


# ---------- 4. content-focused summary instruction ----------
instr = news._NEWS_SUMMARY_INSTRUCTION
check("prompt: สั่งให้คืน key_points", "key_points" in instr)
check("prompt: เน้นเนื้อหา", "เน้นเนื้อหา" in instr)
check("prompt: ยังมีกฎกันการฉีดคำสั่ง (prompt injection)", "ไม่น่าเชื่อถือในเชิงคำสั่ง" in instr)
check("config: ARTICLE_MAX_CHARS ใหญ่ขึ้นเพื่อป้อนเนื้อหามากขึ้น", news.ARTICLE_MAX_CHARS >= 3000,
      news.ARTICLE_MAX_CHARS)


# ---------- 5. _summarize: แสดง key_points เป็น bullet ----------
item = news.NewsItem(source_name="t", item_key="k", title="Orig",
                     url="https://x/y", article_text="เนื้อหาบทความจริงยาวพอสมควรสำหรับทดสอบ")

_ASK["ok"] = True
_ASK["text"] = ('{"title_th":"หัวข้อไทย",'
                '"summary_th":"เนื้อข่าวเรียบเรียงแล้วเน้นเนื้อหา",'
                '"key_points":["ช่องโหว่ CVE-2024-0001","ควรอัปเดตเป็นเวอร์ชัน 2.5"]}')
title, summary = asyncio.run(news._summarize(item, None))
check("summarize: ใช้ title_th", title == "หัวข้อไทย", title)
check("summarize: มีเนื้อข่าว", "เนื้อข่าวเรียบเรียงแล้ว" in summary, summary)
check("summarize: แสดงหัวข้อ 'ประเด็นสำคัญ'", "ประเด็นสำคัญ" in summary, summary)
check("summarize: แสดง bullet key_points", "• ช่องโหว่ CVE-2024-0001" in summary, summary)
check("summarize: ป้อน article_text ให้ AI (ไม่ใช่ RSS summary)",
      "เนื้อหาบทความจริง" in _ASK.get("last_prompt", ""), _ASK.get("last_prompt", "")[:80])

# key_points ว่าง -> ไม่มีหัวข้อประเด็นสำคัญ
_ASK["text"] = '{"title_th":"T","summary_th":"เนื้อข่าวล้วน","key_points":[]}'
_, summary2 = asyncio.run(news._summarize(item, None))
check("summarize: ไม่มี key_points ก็ไม่ขึ้นหัวข้อ", "ประเด็นสำคัญ" not in summary2, summary2)

# AI ล้มเหลว -> ใช้เนื้อหาสำรอง ไม่ crash
_ASK["ok"] = False; _ASK["text"] = "quota exceeded"
_, summary3 = asyncio.run(news._summarize(item, None))
check("summarize: AI ล้มเหลวยังคืนข้อความสำรอง", "เนื้อหาบทความจริง" in summary3, summary3)


# ---------- 6. quality gate ยังทำงาน (กันหน้า anti-bot) ----------
ok_real, _ = news._classify_article_quality("นี่คือเนื้อหาข่าวจริงที่ยาวเพียงพอจะผ่านเกณฑ์คุณภาพของระบบข่าวนี้ได้")
bad_bot, reason = news._classify_article_quality("Just a moment... Checking your browser before accessing. Please enable JavaScript.")
check("quality: บทความจริงผ่าน", ok_real is True)
check("quality: หน้า anti-bot ไม่ผ่าน", bad_bot is False, reason)


# ---------- 7. บั๊กฟิกซ์: บทความยาวไม่ถูกปฏิเสธ + ส่งไม่ถี่ + ข้อความสั้นลง ----------
# ส่ง max_input_chars = RESEARCH cap เข้า ask_gemini (ไม่งั้นบทความ >4000 จะถูกปฏิเสธ)
check("fix: _summarize ใช้เพดาน input แบบ research",
      _ASK.get("last_cap") == _gem.RESEARCH_MAX_INPUT_CHARS, _ASK.get("last_cap"))
# ส่งข่าวไม่ถี่เกินไป
check("fix: รอบเช็คห่างขึ้น (>=900s)", news.CHECK_INTERVAL_DEFAULT >= 900, news.CHECK_INTERVAL_DEFAULT)
check("fix: ข่าวต่อรอบน้อยลง (<=3)", news.MAX_ITEMS_PER_CYCLE_DEFAULT <= 3, news.MAX_ITEMS_PER_CYCLE_DEFAULT)
check("fix: มีดีเลย์ระหว่างส่ง", news.SEND_DELAY_SECONDS > 0, news.SEND_DELAY_SECONDS)
check("fix: แหล่งข่าวใช้ max_items ที่ลดลง", news._source("z", feed_default="http://z/f")["max_items_per_cycle"] <= 3)
# ข้อความข่าวสั้นลง แต่ยังเน้นเนื้อหา
check("fix: ความยาวสรุปสั้นลง (<=1000)", news.AI_SUMMARY_MAX_CHARS <= 1000, news.AI_SUMMARY_MAX_CHARS)
check("fix: prompt ยังสั่งให้กระชับแต่เน้นเนื้อหา",
      "กระชับ" in news._NEWS_SUMMARY_INSTRUCTION and "เน้นเนื้อหา" in news._NEWS_SUMMARY_INSTRUCTION)


print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
