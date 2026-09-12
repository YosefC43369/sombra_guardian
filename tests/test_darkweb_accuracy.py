"""ตรวจความแม่นของฝั่ง dark web (onion) — snippet, กรองเอนจินข้ามเอนจิน,
Ahmia clearnet index, และการจัดอันดับด้วย snippet
"""
import sys, os, threading, time
from urllib.parse import urlparse, parse_qs, quote, unquote
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT); os.chdir(_ROOT)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import search, osint, nethealth

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

TARGET_ONION = "http://victimsite7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5k.onion"
TARGET2 = "http://leakmarketplace4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4o.onion"

# ---------- 1. Ahmia markup: title anchor + snippet, ตัดลิงก์เอนจิน ----------
# หน้า Ahmia จริงมี <li class="result"> พร้อม <h4><a> และ <p> คำโปรย
# และมีลิงก์ nav ที่ชี้กลับ ahmia เอง (ต้องตัด) + ลิงก์ไปเอนจินอื่น (ต้องตัด)
AHMIA = f"""<html><body>
<nav><a href="https://ahmia.fi/">Home</a>
     <a href="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/">Ahmia onion</a></nav>
<ol class="searchResults">
  <li class="result"><h4><a href="/search/redirect?redirect_url={quote(TARGET_ONION + '/profile/thana', safe='')}">
     ข้อมูลรั่วไหล ธนาธรณ์</a></h4>
     <cite>{TARGET_ONION}</cite>
     <p>พบอีเมล thana.p@acme.co.th และเบอร์ในชุดข้อมูลนี้ เกี่ยวกับ ธนาธรณ์ ปัญญาสาร</p></li>
  <li class="result"><h4><a href="/search/redirect?redirect_url={quote(TARGET2 + '/list', safe='')}">
     ตลาดข้อมูล</a></h4>
     <cite>{TARGET2}</cite>
     <p>รายการข้อมูลทั่วไป ไม่เจาะจงบุคคล</p></li>
</ol>
<footer><a href="http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/">Tor66</a></footer>
</body></html>"""
eng = search._ENGINE_BY_URL["https://ahmia.fi/search/?q={query}"]
links = search._extract_links(AHMIA, "https://ahmia.fi/search/?q=x", 20, eng["result_selectors"])
got = [l["link"] for l in links]
check("ahmia: แกะ redirect_url เป็น .onion จริง",
      any("victimsite" in u and u.endswith("/profile/thana") for u in got), got)
check("ahmia: ได้ผลจริง 2 อัน", len(links) == 2, got)
check("ahmia: ตัดลิงก์ nav ที่ชี้กลับ ahmia เอง", not any("juhanurmi" in u for u in got), got)
check("ahmia: ตัดลิงก์ไปเอนจินอื่น (Tor66) ใน footer", not any("tor66" in u for u in got), got)
check("ahmia: เก็บ snippet ของแต่ละผล",
      any("thana.p@acme.co.th" in (l.get("snippet") or "") for l in links), links)
check("ahmia: snippet ตัดชื่อเรื่องซ้ำหัวออก",
      not any((l.get("snippet") or "").startswith("ข้อมูลรั่วไหล ธนาธรณ์") for l in links), links)

# ---------- 2. เอนจินทั่วไป: ตัดลิงก์ข้ามเอนจินแม้ไม่มี selector ----------
GENERIC = f"""<html><body>
<a href="{TARGET_ONION}/page">ผลจริง</a>
<a href="http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q=x">Kaizer engine</a>
<a href="http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/">Deep Searches</a>
</body></html>"""
links = search._extract_links(GENERIC, "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?q=x", 20)
got = [l["link"] for l in links]
check("generic: เก็บผลจริง", any("victimsite" in u for u in got), got)
check("generic: ตัดลิงก์ไปเอนจินค้นหาตัวอื่น (Kaizer, Deep Searches)",
      not any(("kaizer" in u or "searchgf7" in u) for u in got), got)

# ---------- 3. _is_engine_onion ----------
check("engine host: ตัวเอนจินถูกจำได้",
      search._is_engine_onion("http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/x"))
check("engine host: เว็บเป้าหมายไม่ใช่เอนจิน",
      not search._is_engine_onion(TARGET_ONION + "/x"))

# ---------- 4. snippet ไหลเข้า ranking ----------
sel = osint.extract_selectors("ธนาธรณ์ ปัญญาสาร")
group = [
    {"title": "หน้า A", "link": TARGET_ONION + "/a", "snippet": "ไม่เกี่ยวข้อง"},
    {"title": "หน้า B", "link": TARGET2 + "/b",
     "snippet": "ข้อมูลของ ธนาธรณ์ ปัญญาสาร รั่วที่นี่"},
]
ranked = osint.merge_and_rank([group], sel, limit=10)
check("rank: ผลที่ snippet ตรงเป้าอยู่อันดับสูงกว่า",
      ranked[0]["link"] == TARGET2 + "/b", [(r["link"], r["relevance"]) for r in ranked])
check("rank: snippet ถูกพาไปด้วย", all("snippet" in r for r in ranked))

# ---------- 5. snippet ใช้สกัด IOC ได้แม้ scrape ไม่สำเร็จ ----------
ranked2 = [{"link": TARGET_ONION + "/x", "title": "แหล่ง",
            "snippet": "ติดต่อ thana.p@acme.co.th โปรไฟล์ facebook.com/thana.pya",
            "relevance": 5}]
srcs = osint.build_sources(ranked2, {})   # scrape ไม่ได้เลย
check("snippet-ioc: ดึงอีเมลจาก snippet ได้แม้ scrape ล้มเหลว",
      "email" in srcs[0].iocs and "thana.p@acme.co.th" in srcs[0].iocs["email"], srcs[0].iocs)
check("snippet-ioc: ดึงโปรไฟล์จาก snippet ได้",
      "profile" in srcs[0].iocs, srcs[0].iocs)
check("snippet-ioc: แหล่งนี้ยังนับเป็น 'ดึงเนื้อหาไม่สำเร็จ' (snippet ไม่ใช่เนื้อหายืนยัน)",
      srcs[0].retrieved is False)

# ---------- 6. snippet ช่วยจัดอันดับใน verify_sources ----------
srcs = osint.build_sources([
    {"link": TARGET_ONION + "/a", "title": "A", "snippet": "หน้าเกี่ยวกับแมว", "relevance": 1},
    {"link": TARGET2 + "/b", "title": "B",
     "snippet": "ธนาธรณ์ ปัญญาสาร ทำงานที่นี่", "relevance": 1},
], {})
osint.verify_sources(srcs, sel)
rel = {s.url: s.relevance for s in srcs}
check("verify: snippet ตรงเป้าดัน relevance ขึ้น", rel[TARGET2 + "/b"] > rel[TARGET_ONION + "/a"], rel)

# ---------- 6b. ranking ละเอียดขึ้น: token coverage + phrase bonus ----------
selp = osint.extract_selectors("ธนาธรณ์ ปัญญาสาร thana.p@acme.co.th")
grp = [
    {"title": "หน้า A", "link": TARGET_ONION + "/a", "snippet": "พบ ธนาธรณ์ อย่างเดียว"},
    {"title": "หน้า B", "link": TARGET2 + "/b",
     "snippet": "ธนาธรณ์ ปัญญาสาร อีเมล thana.p@acme.co.th ครบ"},
    {"title": "หน้า C", "link": TARGET_ONION + "/c", "snippet": "ไม่เกี่ยวข้อง"},
]
ranked = osint.merge_and_rank([grp], selp, limit=10)
check("rank: ผลที่ครอบคลุมคำค้นครบกว่าอยู่บนสุด", ranked[0]["link"] == TARGET2 + "/b",
      [(r["link"], r["relevance"]) for r in ranked])
check("rank: ผลที่ตรงบางส่วนยังชนะผลที่ไม่เกี่ยวเลย",
      [r["link"] for r in ranked].index(TARGET_ONION + "/a")
      < [r["link"] for r in ranked].index(TARGET_ONION + "/c"),
      [(r["link"], r["relevance"]) for r in ranked])

# ---------- 6c. dedupe ตัด tracking param ----------
grp2 = [
    {"title": "เดียวกัน", "link": TARGET2 + "/p?utm_source=x&id=5", "snippet": ""},
    {"title": "เดียวกัน", "link": TARGET2 + "/p?id=5&fbclid=abc", "snippet": ""},
    {"title": "เดียวกัน", "link": TARGET2 + "/p?id=5", "snippet": ""},
]
ranked2 = osint.merge_and_rank([grp2], selp, limit=10)
check("dedupe: ลิงก์เดียวกันที่ต่างแค่ tracking param ยุบเป็นอันเดียว",
      len(ranked2) == 1, [r["link"] for r in ranked2])
check("dedupe: นับว่าพบซ้ำ 3 ครั้ง (ดัน relevance ถูกต้อง)",
      ranked2[0]["engines"] == 3, ranked2[0])
check("dedupe: param จริง (id) ไม่ถูกตัด",
      "id=5" in ranked2[0]["link"], ranked2[0]["link"])

# ---------- 7. Ahmia web index ทำงานผ่าน fetch_search_results (ยิง clearnet ตรง) ----------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        raw = AHMIA.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
nethealth.reset()
# ชี้ Ahmia web ไปเซิร์ฟเวอร์จำลอง
orig = search.CLEARNET_ENABLED
ahmia_url = "https://ahmia.fi/search/?q={query}"
search._ENGINE_BY_URL[f"http://127.0.0.1:{PORT}/?q={{query}}"] = dict(
    search._ENGINE_BY_URL[ahmia_url], url=f"http://127.0.0.1:{PORT}/?q={{query}}", name="Ahmia (web)")
res = search.fetch_search_results(f"http://127.0.0.1:{PORT}/?q={{query}}", "ธนาธรณ์")
srv.shutdown()
check("ahmia-web: ยิงตรง clearnet ได้ผล .onion โดยไม่ต้องมี Tor", bool(res), res)
check("ahmia-web: ติดป้าย origin=darkweb", all(r.get("origin") == "darkweb" for r in res), res)
check("ahmia-web: ผลเป็น .onion", all(".onion" in r["link"] for r in res), res)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
