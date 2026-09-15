"""เทสว่า /identity (coordinator) กู้หลักฐานได้เมื่อ scrape/pivot หมดเวลากลางคัน

บั๊กเดิม: ถ้า pipeline ถูก timeout ยกเลิก ระบบทิ้งผลค้นทั้งหมดแล้วรายงาน 'ไม่พบแหล่ง'
ทั้งที่รอบค้นหาเจอแล้ว => /identity ได้ 0 แหล่งทั้งที่ /search เจอ
เทสนี้ยืนยันว่า _salvage_partial ประกอบ dossier จากผลค้นที่มีอยู่ได้
"""
import sys, os, asyncio, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

import osint
import coordinator
import gemini

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

FAKE_GROUP = [
    {"title": "Darknet Vault", "link": "http://e5vkh6.onion", "origin": "darkweb",
     "engine": "Amnesia", "relevance": 6, "engines": 1,
     "snippet": "marketplace contact herolegend109@gmail.com cards"},
    {"title": "Passport shop", "link": "http://cavbo576.onion", "origin": "darkweb",
     "engine": "Onionway", "relevance": 6, "engines": 1,
     "snippet": "buy passport email herolegend109@gmail.com"},
]

# ---------- 1. _salvage_partial: ประกอบ dossier จาก ranked ที่ค้นเจอ (ยังไม่ทัน scrape) ----------
ranked = osint.merge_and_rank([FAKE_GROUP], osint.extract_selectors("herolegend109@gmail.com"))
state = {"selectors": osint.extract_selectors("herolegend109@gmail.com"),
         "queries": ["herolegend109@gmail.com"], "ranked": ranked, "raw_total": 2}
dossier, stats = coordinator._salvage_partial("herolegend109@gmail.com", state)
check("salvage: คืน dossier เมื่อมี ranked", bool(dossier), dossier)
check("salvage: stats นับแหล่ง > 0", stats.get("sources", 0) > 0, stats)
check("salvage: dossier อ้างถึงตัวระบุที่เจอ", dossier and "herolegend109" in dossier)

# ---------- 2. _salvage_partial: state ว่าง -> ไม่มีอะไรให้กู้ ----------
d2, s2 = coordinator._salvage_partial("x", {})
check("salvage: state ว่าง คืน (None, {})", d2 is None and s2 == {})

# ---------- 3. end-to-end: scrape ค้าง -> timeout -> ยังได้ dossier มีหลักฐาน ----------
async def _fake_search_round(queries, budget):
    return ([FAKE_GROUP], len(FAKE_GROUP))

async def _hang_scrape(*a, **k):
    await asyncio.sleep(9999)

_orig_search = coordinator._run_search_round
_orig_scrape = coordinator._scrape_and_assess
_orig_ask = gemini.ask_gemini
_orig_total = coordinator.OSINT_TOTAL_BUDGET_SECONDS
_orig_slack = coordinator.OSINT_COLLECT_TIMEOUT_SLACK

async def _fake_ask(prompt, **k):
    return True, ("NOEV" if "ไม่ได้ผลลัพธ์ใดๆ" in prompt else "HASEV") + \
        ("|HASID" if "herolegend109" in prompt else "")

async def _run_case():
    coordinator._run_search_round = _fake_search_round
    coordinator._scrape_and_assess = _hang_scrape
    gemini.ask_gemini = _fake_ask
    coordinator.OSINT_TOTAL_BUDGET_SECONDS = 1
    coordinator.OSINT_COLLECT_TIMEOUT_SLACK = 1
    try:
        return await coordinator.handle_request(
            chat_id=1, user_id=1, is_admin=True,
            question="herolegend109@gmail.com", preset="personal_identity")
    finally:
        coordinator._run_search_round = _orig_search
        coordinator._scrape_and_assess = _orig_scrape
        gemini.ask_gemini = _orig_ask
        coordinator.OSINT_TOTAL_BUDGET_SECONDS = _orig_total
        coordinator.OSINT_COLLECT_TIMEOUT_SLACK = _orig_slack

ok, text = asyncio.run(_run_case())
check("e2e: handle_request สำเร็จ", ok is True, text)
check("e2e: ไม่ตกไป NO_EVIDENCE (กู้หลักฐานได้)", "NOEV" not in text, text)
check("e2e: prompt มีหลักฐานตัวระบุที่ /search เจอ", "HASID" in text, text)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
