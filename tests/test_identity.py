"""เทสความสามารถใหม่: ค้น clearnet หลายแหล่ง + เชื่อมโยงตัวตนข้ามเว็บ
และกันบั๊กที่เพิ่งแก้ไม่ให้กลับมา (NFKC ทำลายภาษาไทย, href ถูกทิ้ง)"""
import sys, os, re, time, asyncio, logging, threading, unicodedata
from urllib.parse import quote, urlparse, parse_qs, unquote
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT); os.chdir(_ROOT)
logging.basicConfig(level=logging.CRITICAL)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from bs4 import BeautifulSoup

import osint, search, scrape, coordinator, nethealth

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ---------- 1. ภาษาไทยต้องไม่เพี้ยน (บั๊ก NFKC) ----------
thai = "ทำเนียบบุคลากร บริษัท เอซีเอ็มอี จำกัด คำนำหน้า"
out = osint.sanitize_untrusted(thai)
check("ไทย: sanitize ไม่ทำลายสระอำ", out == thai, repr(out))
check("ไทย: NFKC เคยทำลาย (ยืนยันว่าเป็นบั๊กจริง)",
      unicodedata.normalize("NFKC", thai) != thai)
check("ไทย: อักขระซ่อนยังถูกล้างอยู่",
      "​" not in osint.sanitize_untrusted("ก​ข"))

# ---------- 2. ชื่อบุคคล ----------
for text, want in (
    ("ธนาธรณ์ ปัญญาสาร", ["ธนาธรณ์ ปัญญาสาร"]),
    ("นายธนาธรณ์ ปัญญาสาร", ["ธนาธรณ์ ปัญญาสาร"]),
    ("ช่วยหาข้อมูลของ ธนาธรณ์ ปัญญาสาร ให้หน่อยครับ", ["ธนาธรณ์ ปัญญาสาร"]),
    ("สมชาย และ สมหญิง", []),
    ("John Smith", ["John Smith"]),
    ("hr@acme.co.th", []),
):
    got = osint.extract_selectors(text).names
    check(f"ชื่อ: {text[:32]!r} -> {want}", got == want, got)
check("ชื่อ: เครื่องหมายคำพูดบังคับให้เป็นชื่อได้",
      osint.extract_selectors('ค้นหา "ดูรงค์ ศรีสุข"').names == ["ดูรงค์ ศรีสุข"])
q = osint.plan_queries("ธนาธรณ์ ปัญญาสาร")
check("ชื่อ: ยิงวลีตรงตัวก่อนเสมอ", q[0] == '"ธนาธรณ์ ปัญญาสาร"', q)

# ---------- 3. โปรไฟล์โซเชียล ----------
prof = osint.extract_profiles("""
  https://www.facebook.com/thanathorn.pya https://twitter.com/thana_p
  https://www.linkedin.com/in/thanathorn-p https://t.me/thanap_dev
  https://facebook.com/sharer/sharer.php?u=x https://facebook.com/login""")
check("โปรไฟล์: จับครบทุกแพลตฟอร์ม",
      {"facebook:thanathorn.pya", "x:thana_p", "linkedin:thanathorn-p",
       "telegram:thanap_dev"} <= set(prof), prof)
check("โปรไฟล์: ตัด path ที่ไม่ใช่บัญชี (sharer/login)",
      not any(p.endswith(("sharer", "login")) for p in prof), prof)
check("โปรไฟล์: โดเมนแพลตฟอร์มไม่ถูกนับเป็น IOC โดเมน",
      "domain" not in osint.extract_iocs("https://facebook.com/someone"),
      osint.extract_iocs("https://facebook.com/someone"))

# ---------- 4. scrape ต้องเก็บ href ที่ระบุตัวตน (บั๊ก get_text) ----------
html = """<html><body><p>ติดต่อ <a href="https://www.facebook.com/somchai.x">เฟซบุ๊ก</a>
 และ <a href="mailto:somchai@example.co.th">อีเมล</a>
 <a href="https://www.example.com/news">ข่าวทั่วไป</a>
 <a href="/relative/page">ลิงก์ภายใน</a></p></body></html>"""
links = scrape._identity_links(BeautifulSoup(html, "html.parser"), "https://site.test/a")
check("scrape: เก็บลิงก์โปรไฟล์", any("facebook.com/somchai.x" in l for l in links), links)
check("scrape: เก็บอีเมลจาก mailto:", "somchai@example.co.th" in links, links)
check("scrape: ไม่เก็บลิงก์ทั่วไปที่ไม่ใช่ตัวระบุตัวตน",
      not any("example.com/news" in l for l in links), links)

# ---------- 5. clearnet: แกะ URL ปลายทางจาก redirect ----------
target = "https://www.example.org/profile"
cases = [
    ("DuckDuckGo uddg=", f"/l/?uddg={quote(target, safe='')}"),
    ("Bing u=", f"/ck/a?u={quote(target, safe='')}"),
    ("ลิงก์ตรง", target),
    ("protocol-relative", "//www.example.org/profile"),
]
for label, href in cases:
    got = search._href_to_clearnet(href, "html.duckduckgo.com")
    check(f"clearnet: แกะ {label}", got and "example.org/profile" in got, got)
check("clearnet: ตัดลิงก์ที่ชี้กลับ engine เอง",
      search._href_to_clearnet("https://duckduckgo.com/about", "html.duckduckgo.com") is None)
check("clearnet: ตัดโฮสต์โครงสร้างของ engine",
      search._href_to_clearnet("https://go.microsoft.com/x", "bing.com") is None)
check("clearnet: ตัด fragment ทิ้ง",
      search._href_to_clearnet("https://a.test/p#frag", "b.test") == "https://a.test/p")
check("clearnet: คำค้นไทยขอผลภาษาไทย",
      search._accept_language_for("ธนาธรณ์").startswith("th"))
check("clearnet: คำค้นอังกฤษขอผลอังกฤษ",
      search._accept_language_for("john smith").startswith("en"))

# ---------- 6. เชื่อมโยงตัวตน ----------
sel = osint.extract_selectors("ธนาธรณ์ ปัญญาสาร")
ranked = [{"link": f"http://s{i}.test/p", "title": "หน้า", "relevance": 1,
           "engines": 1, "origin": "clearnet"} for i in range(1, 5)]
scraped = {
    "http://s1.test/p": "หน้า - ธนาธรณ์ ปัญญาสาร ติดต่อ t.p@acme.co.th https://facebook.com/thana.pya",
    "http://s2.test/p": "หน้า - ธนาธรณ์ ปัญญาสาร อีเมล t.p@acme.co.th โทร 081-234-5678",
    "http://s3.test/p": "หน้า - ธนาธรณ์ ปัญญาสาร ดูที่ https://facebook.com/thana.pya",
    # หน้านี้ไม่พูดถึงเป้าหมายเลย ตัวระบุในนี้ต้องไม่ถูกผูกกับเป้าหมาย
    "http://s4.test/p": "หน้า - สมหญิง ใจดี อีเมล somying@other.co.th",
}
srcs = osint.verify_sources(osint.build_sources(ranked, scraped), sel)
ident = osint.build_identity(srcs, sel)
conf = {(l.kind, l.value.lower()) for l in ident.confirmed()}
leads = {(l.kind, l.value.lower()) for l in ident.leads()}
check("ตัวตน: อีเมลที่พบ 2 แหล่ง = ยืนยันแล้ว", ("email", "t.p@acme.co.th") in conf, conf)
check("ตัวตน: โปรไฟล์ที่พบ 2 แหล่ง = ยืนยันแล้ว", ("profile", "facebook:thana.pya") in conf, conf)
check("ตัวตน: เบอร์ที่พบแหล่งเดียว = เบาะแส", ("phone", "081-234-5678") in leads, leads)
check("ตัวตน: หน้าที่ไม่พูดถึงเป้าหมาย ไม่ถูกนำมาผูก",
      not any("somying" in v for _, v in conf | leads), conf | leads)
check("ตัวตน: แหล่งที่ผูกกับเป้าหมายมีแค่ที่ยืนยันแล้ว",
      set(ident.linked_sources) == {"S1", "S2", "S3"}, ident.linked_sources)
check("ตัวตน: ชื่อไม่ถูกใช้เป็นตัวเชื่อม (ชื่อซ้ำกันได้)",
      "person" not in osint.IDENTITY_TYPES and "name" not in osint.IDENTITY_TYPES)

seeded = osint.build_identity(srcs, osint.extract_selectors("hr@acme.co.th"))
check("ตัวตน: ตัวระบุที่ผู้ใช้ให้มาเอง ถือว่ายืนยันแล้ว",
      any(l.seed and l.confirmed for l in seeded.links))

# ---------- 7. pivot ----------
pivots = osint.pivot_queries(ident, sel, already_used=['"ธนาธรณ์ ปัญญาสาร"'], max_queries=3)
check("pivot: ใช้ตัวระบุที่ยืนยันแล้วก่อน", pivots and pivots[0] == "t.p@acme.co.th", pivots)
check("pivot: แปลงโปรไฟล์เป็นชื่อบัญชี", "thana.pya" in pivots, pivots)
check("pivot: ไม่ยิงซ้ำ query เดิม",
      not any("ธนาธรณ์" in p for p in pivots), pivots)
check("pivot: เคารพเพดานจำนวน", len(osint.pivot_queries(ident, sel, max_queries=2)) <= 2)

# ---------- 8. ปลายทางจริง: mock internet ----------
SITES = {
 "/site/a": ("หน้าบริษัท", "พนักงาน ธนาธรณ์ ปัญญาสาร อีเมล t.p@acme.co.th "
             '<a href="https://facebook.com/thana.pya">fb</a>'),
 "/site/b": ("ข่าว", "นายธนาธรณ์ ปัญญาสาร ให้สัมภาษณ์ ติดต่อ t.p@acme.co.th"),
 "/site/c": ("กระทู้", 'ธนาธรณ์ ปัญญาสาร <a href="https://facebook.com/thana.pya">โปรไฟล์</a>'),
 "/site/secret": ("ฐานข้อมูลรั่ว", "ระเบียน t.p@acme.co.th โทร 02-111-2222"),
 "/site/other": ("สูตรอาหาร", "แกงเขียวหวาน กะทิ พริกแกง"),
}
PIVOT_ONLY = "/site/secret"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        raw = body.encode(); self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        u = urlparse(self.path); qs = parse_qs(u.query)
        q = unquote((qs.get("q") or [""])[0]).strip().strip('"').lower()
        if u.path == "/engine":
            rows = ""
            for p, (t, b) in SITES.items():
                if p == PIVOT_ONLY and "ธนาธรณ์" in q:
                    continue
                if q and (q in (t + b).lower() or all(tok in (t + b).lower() for tok in q.split())):
                    rows += f'<a href="/r?uddg={quote(f"http://localhost:{PORT}{p}", safe="")}">{t}</a>'
            return self._s(200, f"<html><body>{rows}</body></html>")
        if u.path in SITES:
            t, b = SITES[u.path]
            return self._s(200, f"<html><head><title>{t}</title></head><body>{b}</body></html>")
        self._s(404, "no")

srv = ThreadingHTTPServer(("127.0.0.1", 0), H); PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
search.CLEARNET_ENGINES = [{"name": "Mock", "url": f"http://127.0.0.1:{PORT}/engine?q={{query}}"}]
search._CLEARNET_ENGINE_NAME_BY_URL = {e["url"]: e["name"] for e in search.CLEARNET_ENGINES}
search.CLEARNET_DISABLED = set()
coordinator.OSINT_INCLUDE_DARKWEB = False
nethealth.reset(); search.clear_search_cache()

dossier, stats = asyncio.run(coordinator._collect_osint_evidence("ธนาธรณ์ ปัญญาสาร"))
srv.shutdown()

check("e2e: ค้นชื่อไทยแล้วได้แหล่งจริง", stats["sources"] >= 3, stats)
check("e2e: ดึงเนื้อหาได้จากหลายเว็บ", stats["retrieved"] >= 3, stats)
check("e2e: ยืนยันว่าตรงเป้าจากเนื้อหา", stats["on_target"] >= 3, stats)
check("e2e: ยิงรอบสองด้วยตัวระบุที่เพิ่งเจอ", stats["rounds"] == 2, stats)
check("e2e: pivot ใช้อีเมลที่เจอในรอบแรก",
      any("t.p@acme.co.th" in p for p in stats["pivots"]), stats["pivots"])
check("e2e: ได้แหล่งที่ค้นด้วยชื่อไม่มีทางเจอ", "/site/secret" in dossier, stats)
check("e2e: อีเมลถูกยืนยันข้ามเว็บ", stats["identity_confirmed"] >= 1, stats)
check("e2e: หน้าสูตรอาหารไม่ถูกนับเป็นหลักฐานของเป้าหมาย",
      "แกงเขียวหวาน" not in dossier, "off-target content leaked")
check("e2e: dossier มีกราฟตัวตน", "[IDENTITY GRAPH" in dossier)
check("e2e: ไทยไม่เพี้ยนใน dossier", "ทําเนียบ" not in dossier and "ปัญญาสาร" in dossier)
check("e2e: ระบุฝั่งที่มาของแหล่ง", "ฝั่ง=clearnet" in dossier)
check("e2e: dossier อยู่ในเพดาน prompt",
      len(dossier) <= 24000, len(dossier))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
