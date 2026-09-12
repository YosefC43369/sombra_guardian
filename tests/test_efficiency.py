"""เทสข้อ 2 (gateway config + สุขภาพเส้นทาง) และ ข้อ 3 (ความเร็ว) + ความแม่นยำ"""
import sys, os, time, asyncio, logging, threading
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.CRITICAL)

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

import nethealth, search, scrape, osint, coordinator

# ---------- ข้อ 2: env ค่าว่างต้องได้ default ----------
os.environ["TOR_GATEWAY_SUFFIXES"] = ""
check("env_list: ค่าว่างใน .env -> ใช้ default ไม่ใช่ลิสต์ว่าง",
      nethealth.env_list("TOR_GATEWAY_SUFFIXES", ".ly,.ps") == [".ly", ".ps"],
      nethealth.env_list("TOR_GATEWAY_SUFFIXES", ".ly,.ps"))
os.environ["TOR_GATEWAY_SUFFIXES"] = ".a , .b ,, .c "
check("env_list: ตัดช่องว่าง/ค่าว่างระหว่างคอมมา",
      nethealth.env_list("TOR_GATEWAY_SUFFIXES", ".ly") == [".a", ".b", ".c"])
del os.environ["TOR_GATEWAY_SUFFIXES"]
check("env_int: ค่าว่าง -> default", nethealth.env_int("__NOPE__", 7) == 7)
os.environ["__EMPTY__"] = ""
check("env_int: ตั้งไว้แต่ว่าง -> default (ต้นเหตุที่บอทเคยสตาร์ทไม่ขึ้น)",
      nethealth.env_int("__EMPTY__", 3) == 3)
check("env_float: ตั้งไว้แต่ว่าง -> default", nethealth.env_float("__EMPTY__", 1.5) == 1.5)
check("env_bool: ตั้งไว้แต่ว่าง -> default", nethealth.env_bool("__EMPTY__", "true") is True)
del os.environ["__EMPTY__"]

check(".env จริงมี gateway แล้ว (ไม่ว่างอีกต่อไป)",
      len(nethealth.TOR_GATEWAY_SUFFIXES) >= 2, nethealth.TOR_GATEWAY_SUFFIXES)
check("search กับ scrape ใช้ gateway ชุดเดียวกัน (แหล่งความจริงเดียว)",
      search.TOR_GATEWAY_SUFFIXES is scrape.TOR_GATEWAY_SUFFIXES is nethealth.TOR_GATEWAY_SUFFIXES)
check("search กับ scrape ใช้ Tor probe ร่วมกัน",
      search.is_tor_reachable() == scrape._tor_reachable() == nethealth.tor_reachable())

# ---------- circuit breaker ----------
nethealth.reset()
for _ in range(nethealth.ROUTE_FAILURE_THRESHOLD - 1):
    nethealth.record("route:.zz", False, nethealth.ROUTE_FAILURE_THRESHOLD)
check("circuit: ยังไม่ถึงเกณฑ์ = ยังไม่พัก", not nethealth.blocked("route:.zz"))
nethealth.record("route:.zz", False, nethealth.ROUTE_FAILURE_THRESHOLD)
check("circuit: ครบเกณฑ์ = พัก", nethealth.blocked("route:.zz"))
check("circuit: open_routes รายงานถูก", "route:.zz" in nethealth.open_routes())
orig_cd = nethealth.CIRCUIT_OPEN_SECONDS
nethealth.CIRCUIT_OPEN_SECONDS = 0.01
nethealth.reset()
for _ in range(nethealth.ROUTE_FAILURE_THRESHOLD):
    nethealth.record("route:.zz", False, nethealth.ROUTE_FAILURE_THRESHOLD)
time.sleep(0.05)
check("circuit: หมด cooldown = half-open ให้ลองใหม่", not nethealth.blocked("route:.zz"))
nethealth.CIRCUIT_OPEN_SECONDS = orig_cd
nethealth.reset()

# ---------- ข้อ 3: circuit breaker ต้องทำให้รอบถัดไปเร็วขึ้นจริง ----------
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Dead(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        time.sleep(1.2)                      # gateway ที่ "ตายแบบค้าง"
        self.send_response(502); self.end_headers()
srv = ThreadingHTTPServer(("127.0.0.1", 0), Dead)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

search._tor_enabled = lambda: False
search._onion_to_gateway = lambda url, suffix: f"http://127.0.0.1:{PORT}/dead"
search.SEARCH_READ_TIMEOUT = 3.0
nethealth.reset(); search.clear_search_cache()

t0 = time.monotonic(); search.get_search_results("probe one", budget_seconds=25, use_cache=False)
first = time.monotonic() - t0
t0 = time.monotonic(); search.get_search_results("probe two", budget_seconds=25, use_cache=False)
second = time.monotonic() - t0
check(f"circuit: รอบสองเร็วขึ้นเพราะข้ามเส้นทางที่ตาย ({first:.1f}s -> {second:.1f}s)",
      second < first * 0.6, f"{first:.1f}s -> {second:.1f}s")
check("circuit: มีเส้นทางถูกพักจริงหลังเจอ 502 รัวๆ",
      bool(nethealth.open_routes()), nethealth.open_routes())
srv.shutdown()

# ---------- cache ----------
nethealth.reset(); search.clear_search_cache()
calls = []
def counting_fetch(endpoint, query, deadline=None, max_results=None):
    calls.append(query)
    return [{"title": f"r{len(calls)}", "link": f"http://aaaaaaaaaaaaaaaa{len(calls)}.onion/x"}]
search.fetch_search_results = counting_fetch
r1 = search.get_search_results("cached target", budget_seconds=10)
n1 = len(calls)
t0 = time.monotonic(); r2 = search.get_search_results("cached target", budget_seconds=10)
cached_time = time.monotonic() - t0
check("cache: ยิงซ้ำไม่ไปแตะเครือข่ายอีก", len(calls) == n1, (n1, len(calls)))
check("cache: ผลเหมือนเดิม (หลักฐานชุดเดียวกันทั้ง /search และ /identity)", r1 == r2)
check(f"cache: คืนผลแทบทันที ({cached_time*1000:.0f}ms)", cached_time < 0.05, cached_time)
search.clear_search_cache()
check("cache: ล้างแล้วยิงใหม่จริง",
      (search.get_search_results("cached target", budget_seconds=10), len(calls) > n1)[1])

# ---------- early stop ----------
search.clear_search_cache(); calls.clear()
def many_fetch(endpoint, query, deadline=None, max_results=None):
    calls.append(endpoint)
    i = len(calls)
    return [{"title": f"t{i}-{j}", "link": f"http://bbbbbbbbbbbbbbbb{i}-{j}.onion/x"} for j in range(10)]
search.fetch_search_results = many_fetch
res = search.get_search_results("early", budget_seconds=20, max_results=12, use_cache=False)
check("early stop: หยุดเมื่อได้ผลครบเป้า", len(res) == 12, len(res))
check("early stop: ไม่ได้ยิงครบทั้ง 16 engine",
      len(calls) < len(search.DEFAULT_SEARCH_ENGINES), len(calls))

# ---------- ความแม่นยำ: verify_sources ----------
sel = osint.extract_selectors("acme.co.th")
ranked = [
    {"link": "http://on1.onion/a", "title": "acme.co.th dump", "relevance": 3, "engines": 1},
    {"link": "http://off1.onion/b", "title": "acme.co.th mirror", "relevance": 3, "engines": 1},
]
scraped = {
    "http://on1.onion/a": "acme.co.th dump - leaked staff of acme.co.th including hr@acme.co.th",
    "http://off1.onion/b": "acme.co.th mirror - บทความเรื่องแมวและสูตรทำอาหาร ไม่มีอะไรเกี่ยวข้อง",
}
srcs = osint.verify_sources(osint.build_sources(ranked, scraped), sel)
check("verify: หน้าที่เนื้อหาพูดถึงเป้าหมาย = on_target", srcs[0].on_target is True)
check("verify: หน้าที่ชื่อตรงแต่เนื้อหาไม่เกี่ยว = ไม่ on_target",
      srcs[1].on_target is False, (srcs[1].content_hits, srcs[1].matched_selectors))
check("verify: on_target ได้ relevance สูงกว่า", srcs[0].relevance > srcs[1].relevance,
      (srcs[0].relevance, srcs[1].relevance))
idx = osint.build_ioc_index(srcs); osint.apply_corroboration(srcs, idx)
d = osint.build_dossier("acme.co.th", sel, ["acme.co.th"], srcs, idx, max_chars=12000)
check("dossier: เนื้อหา off-target ไม่ถูกส่งเข้า prompt",
      "สูตรทำอาหาร" not in d, "off-target content leaked into prompt")
check("dossier: แต่ยังถูกบันทึกไว้ใน register ว่าไม่ตรงเป้า",
      "ไม่พบ selector ในเนื้อหา" in d and "[OFF-TARGET" in d)
check("dossier: on-target ยังอยู่ครบ", "leaked staff" in d)
check("dossier: รายงานจำนวนแหล่งที่ยืนยันตรงเป้า", "ยืนยันว่าตรงเป้าจากเนื้อหา: 1" in d, d[:600])

# fallback: ไม่มีแหล่งไหน on-target เลย ต้องไม่ส่ง dossier เปล่า
sel_th = osint.extract_selectors("บริษัทสมบูรณ์")
srcs2 = osint.verify_sources(osint.build_sources(ranked, scraped), sel_th)
d2 = osint.build_dossier("บริษัทสมบูรณ์", sel_th, ["บริษัทสมบูรณ์"], srcs2, {}, max_chars=12000)
check("dossier: ไม่มีแหล่ง on-target เลย -> ยังส่งหลักฐานที่ดึงได้ ไม่ส่งเปล่า",
      "leaked staff" in d2, d2[-400:])

# ---------- ข้อ 3: scrape สองจังหวะ + รอบ pivot ----------
BATCHES = []
def recording_scrape(urls, workers=5, budget=None, max_urls=None):
    BATCHES.append(len(urls))
    return {u["link"]: f"{u['title']} - acme.co.th leaked record hr@acme.co.th" for u in urls}
scrape.scrape_multiple = recording_scrape
search.get_combined_results = lambda q, *a, **k: [
    {"title": f"acme.co.th src {i}", "link": f"http://cccccccccccccccc{i}.onion/x",
     "origin": "darkweb"} for i in range(12)]

# ปิด pivot ก่อน เพื่อวัดพฤติกรรมสองจังหวะล้วนๆ
coordinator.OSINT_PIVOT_ENABLED = False
BATCHES.clear()
dossier, stats = asyncio.run(coordinator._collect_osint_evidence("acme.co.th"))
check("two-stage: หลักฐานพอตั้งแต่ชุดแรก -> ดึงชุดเดียว", len(BATCHES) == 1, BATCHES)
check("two-stage: ชุดแรกดึงแค่ OSINT_SCRAPE_FIRST_BATCH แหล่ง",
      BATCHES[0] == coordinator.OSINT_SCRAPE_FIRST_BATCH, BATCHES)
check("two-stage: ประหยัดการดึงได้จริงเทียบกับดึงทั้งหมด",
      BATCHES[0] < coordinator.OSINT_MAX_SOURCES, (BATCHES[0], coordinator.OSINT_MAX_SOURCES))
check("two-stage: stats บอกจำนวนรอบการดึง", stats["scrape_passes"] == 1, stats)

def useless_scrape(urls, workers=5, budget=None, max_urls=None):
    BATCHES.append(len(urls))
    return {u["link"]: f"{u['title']} - ไม่มีอะไรเกี่ยวข้องเลย" for u in urls}
scrape.scrape_multiple = useless_scrape
BATCHES.clear()
dossier, stats = asyncio.run(coordinator._collect_osint_evidence("acme.co.th"))
check("two-stage: หลักฐานไม่พอ -> ดึงต่อชุดที่สอง", len(BATCHES) == 2, BATCHES)
check("two-stage: ชุดที่สองคือแหล่งที่เหลือ", sum(BATCHES) == coordinator.OSINT_MAX_SOURCES, BATCHES)
check("two-stage: stats บอกว่าดึงสองรอบ", stats["scrape_passes"] == 2, stats)

# ---------- รอบ pivot: ค้นต่อจากตัวระบุที่เพิ่งเจอ ----------
coordinator.OSINT_PIVOT_ENABLED = True
SEARCHED = []
PIVOT_HIT = {"title": "โปรไฟล์ hr@acme.co.th", "link": "http://pivotonly11111.onion/p",
             "origin": "clearnet"}
def pivot_aware_search(q, *a, **k):
    SEARCHED.append(q)
    base = [{"title": f"acme.co.th src {i}", "link": f"http://cccccccccccccccc{i}.onion/x",
             "origin": "darkweb"} for i in range(6)]
    # แหล่งนี้จะเจอก็ต่อเมื่อค้นด้วยอีเมล ไม่ใช่ค้นด้วยชื่อโดเมน
    return base + ([PIVOT_HIT] if "hr@acme.co.th" in q else [])
search.get_combined_results = pivot_aware_search
scrape.scrape_multiple = recording_scrape
BATCHES.clear(); SEARCHED.clear()
dossier, stats = asyncio.run(coordinator._collect_osint_evidence("acme.co.th"))
check("pivot: ยิงรอบสองด้วยตัวระบุที่เพิ่งค้นเจอ", stats["rounds"] == 2, stats.get("rounds"))
check("pivot: query รอบสองคืออีเมลที่เจอในรอบแรก",
      any("hr@acme.co.th" in q for q in stats.get("pivots", [])), stats.get("pivots"))
check("pivot: ได้แหล่งที่ค้นด้วยชื่อเดิมไม่มีทางเจอ",
      PIVOT_HIT["link"] in dossier, dossier[:0])
check("pivot: แหล่งจากรอบสองถูกดึงเนื้อหาด้วย", len(BATCHES) >= 2, BATCHES)

# ---------- งบเวลาร่วม ----------
check("budget: OSINT_TOTAL เป็นเพดานร่วมของทั้งสองขั้น",
      coordinator.OSINT_TOTAL_BUDGET_SECONDS >= coordinator.OSINT_SEARCH_BUDGET_SECONDS,
      coordinator.OSINT_TOTAL_BUDGET_SECONDS)

# ---------- ความแม่นยำ: การยืนยันต้องนับ pivot ด้วย ----------
sel_email = osint.extract_selectors("hr@acme.co.th")
vals = dict(sel_email.verification_values())
check("verify values: มีอีเมลตรงตัว น้ำหนัก 5", vals.get("hr@acme.co.th") == 5, vals)
check("verify values: มีโดเมนเป็น pivot น้ำหนัก 2", vals.get("acme.co.th") == 2, vals)
check("verify values: ตัดค่าที่สั้นเกินไปทิ้ง", all(len(v) >= 4 for v in vals), vals)

ranked3 = [
    {"link": "http://exact.onion/a", "title": "listing", "relevance": 0, "engines": 1},
    {"link": "http://pivot.onion/b", "title": "listing", "relevance": 0, "engines": 1},
    {"link": "http://none.onion/c", "title": "listing", "relevance": 0, "engines": 1},
]
scraped3 = {
    "http://exact.onion/a": "listing - dump contains hr@acme.co.th and more",
    "http://pivot.onion/b": "listing - corporate records of acme.co.th employees",
    "http://none.onion/c": "listing - บทความเรื่องแมว ไม่เกี่ยวข้องใดๆ",
}
v3 = osint.verify_sources(osint.build_sources(ranked3, scraped3), sel_email)
check("verify: เจอเป้าหมายตรงตัว = on_target", v3[0].on_target is True)
check("verify: เจอแค่โดเมน (pivot) ก็ยังนับเป็นหลักฐาน ไม่ถูกตัดทิ้ง",
      v3[1].on_target is True, (v3[1].content_hits, v3[1].matched_selectors))
check("verify: ไม่เจออะไรเลย = off-target", v3[2].on_target is False)
check("verify: ตรงตัวได้คะแนนสูงกว่า pivot", v3[0].relevance > v3[1].relevance,
      (v3[0].relevance, v3[1].relevance))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
