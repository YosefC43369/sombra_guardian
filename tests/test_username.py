"""เทส username_osint — ตัวที่มาแทน sites.py / checkings.py / maigret.py"""
import sys, os, time, asyncio, logging, threading
from urllib.parse import urlparse
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT); os.chdir(_ROOT)
logging.basicConfig(level=logging.CRITICAL)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import username_osint as uo, nethealth, osint, coordinator, search, scrape

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ---------- 1. สามไฟล์เดิมต้องไม่อยู่ที่ราก (เลิกบังแพ็กเกจจริง) ----------
for name in ("sites.py", "checkings.py", "maigret.py"):
    check(f"ราก: ไม่มี {name} แล้ว", not os.path.exists(name))
    check(f"vendor: ยังเก็บ {name} ไว้ครบ", os.path.exists(f"vendor/{name}"))

# ---------- 2. ฐานข้อมูลเว็บ ----------
sites = uo.load_sites()
check("DB: โหลดจาก resource/data.json ของโปรเจกต์", len(sites) > 1000, len(sites))
check("DB: เรียงเว็บสำคัญไว้ก่อน", sites[0].name in uo.PRIORITY_SITES, sites[0].name)
check("DB: get_site หาเจอ", uo.get_site("GitHub") is not None)
check("DB: get_site ไม่สนตัวพิมพ์", uo.get_site("github") is not None)
check("DB: get_site ที่ไม่มีคืน None", uo.get_site("__ไม่มีเว็บนี้__") is None)
check("DB: search_sites กรองตามแท็ก",
      all("social" in [t.lower() for t in s.tags] for s in uo.search_sites(["social"], 10)))
check("DB: ทุกเว็บมี {username} ใน url", all("{username}" in s.url_template for s in sites[:200]))
check("DB: แคชไว้ ไม่ parse ซ้ำ", uo.load_sites() is sites)
gh = uo.get_site("GitHub")
check("DB: platform_key เทียบกับ osint ได้", gh.platform_key == "github", gh.platform_key)
check("DB: url_for แทนชื่อบัญชี", gh.url_for("abc") == "https://github.com/abc", gh.url_for("abc"))

# ---------- 3. ตรวจรูปแบบชื่อบัญชี ----------
for value, want in (("thana_p", True), ("john.doe", True), ("ab", False), ("ธนาธรณ์", False),
                    ("12345", False), ("a b", False), ("x" * 40, False), ("Abc-123", True)):
    check(f"username: {value!r} -> {want}", uo.is_plausible_username(value) is want)

# ---------- 4. เซิร์ฟเวอร์จำลอง + ตรรกะการตัดสิน ----------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body="", loc=None):
        raw = body.encode(); self.send_response(code)
        if loc: self.send_header("Location", loc)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/ok/taken":        return self._s(200, "<h1>โปรไฟล์ผู้ใช้</h1>")
        if p == "/ok/free":         return self._s(404, "not found")
        if p == "/msg/taken":       return self._s(200, "<title>taken | Site</title>โปรไฟล์")
        if p == "/msg/free":        return self._s(200, "Sorry, this page isn't available")
        if p == "/redir/taken":     return self._s(200, "ok")
        if p == "/redir/free":      return self._s(302, "", loc="/home")
        if p == "/home":            return self._s(200, "home")
        if p == "/slow":            time.sleep(5); return self._s(200, "late")
        return self._s(404, "no")
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"

def entry(name, path, check_type, **kw):
    return uo.SiteEntry(name=name, url_template=f"{BASE}{path}",
                        url_main=BASE, check_type=check_type, **kw)

nethealth.reset()
cases = [
    ("status_code เจอ", entry("A", "/ok/taken", "status_code"), uo.FOUND),
    ("status_code ไม่เจอ", entry("B", "/ok/free", "status_code"), uo.NOT_FOUND),
    ("message เจอ (presenseStrs)", entry("C", "/msg/taken", "message",
                                         presence_strs=["| Site"]), uo.FOUND),
    ("message ไม่เจอ (absenceStrs)", entry("D", "/msg/free", "message",
                                           absence_strs=["isn't available"]), uo.NOT_FOUND),
    ("response_url เจอ", entry("E", "/redir/taken", "response_url"), uo.FOUND),
    ("response_url ไม่เจอ (ถูก redirect)", entry("F", "/redir/free", "response_url"), uo.NOT_FOUND),
]
for label, ent, want in cases:
    got = uo.check_site(ent, "someone")
    check(f"ตรวจ: {label}", got["status"] == want, got)

bad = uo.check_site(uo.SiteEntry(name="Dead", url_template="http://127.0.0.1:1/{username}",
                                 check_type="status_code"), "x")
check("ตรวจ: ต่อไม่ติด -> unknown ไม่ใช่ found", bad["status"] == uo.UNKNOWN, bad)
check("ตรวจ: บันทึก error ไว้", "error" in bad, bad)

# circuit breaker
nethealth.reset()
for _ in range(nethealth.ENGINE_FAILURE_THRESHOLD):
    nethealth.record("site:Dead", False, nethealth.ENGINE_FAILURE_THRESHOLD)
skipped = uo.check_site(uo.SiteEntry(name="Dead", url_template=f"{BASE}/ok/taken",
                                     check_type="status_code"), "x")
check("ตรวจ: เว็บที่พักอยู่ถูกข้าม", skipped.get("error") == "cooldown", skipped)
nethealth.reset()

# ---------- 5. ค้นหลายเว็บพร้อมกัน ----------
pool = [entry(f"S{i}", f"/ok/{'taken' if i % 2 == 0 else 'free'}?s={i}", "status_code")
        for i in range(10)]
hits = uo.check_username("someone", sites=pool, budget_seconds=15)
check("ค้น: คืนเฉพาะที่เจอ", len(hits) == 5, [h["site"] for h in hits])
check("ค้น: มี url เต็ม", all(h["url"].startswith(BASE) for h in hits))
check("ค้น: ชื่อบัญชีไม่ถูกรูปแบบ -> ไม่ยิงเลย", uo.check_username("ธนาธรณ์", sites=pool) == [])

slow_pool = [entry(f"T{i}", "/slow", "status_code") for i in range(6)]
t0 = time.monotonic(); uo.check_username("someone", sites=slow_pool, budget_seconds=3)
check(f"ค้น: เคารพงบเวลา ({time.monotonic()-t0:.1f}s)", time.monotonic() - t0 < 8)

# ---------- 6. รูปแบบผลลัพธ์ที่ไหลเข้าท่อเดิม ----------
uo._db_cache = pool          # บังคับให้ใช้ชุดจำลอง
rows = uo.check_username_as_results("someone", budget_seconds=10)
check("ผลลัพธ์: รูปแบบเดียวกับผลค้นหา",
      rows and set(rows[0]) == {"title", "link", "origin", "engine"}, rows[:1])
check("ผลลัพธ์: ติดป้าย origin=username", all(r["origin"] == "username" for r in rows))
merged = osint.merge_and_rank([rows], osint.extract_selectors("someone"), limit=20)
check("ผลลัพธ์: merge_and_rank รับได้ทันที", len(merged) == len(rows), (len(merged), len(rows)))

check("profiles_from_hits: แปลงเป็น platform:handle",
      uo.profiles_from_hits([{"platform": "github", "url": "https://github.com/thana_p"}])
      == ["github:thana_p"])
rep = uo.format_username_report("thana_p", [{"site": "GitHub", "url": "u", "tags": ["coding"]}])
check("รายงาน: เป็น plain text อ่านได้", "GitHub" in rep and "thana_p" in rep)
check("รายงาน: เตือนว่าชื่อตรงไม่ได้แปลว่าคนเดียวกัน", "ไม่ได้แปลว่าเป็นคนเดียวกัน" in rep)
check("รายงาน: ชื่อไทยบอกเหตุผล", "ไม่ใช่รูปแบบชื่อบัญชี" in uo.format_username_report("ธนาธรณ์", []))

# ---------- 7. coordinator เลือกชื่อบัญชีไปค้นต่อ ----------
sel = osint.extract_selectors("ธนาธรณ์ ปัญญาสาร")
ident = osint.IdentityProfile(target="ธนาธรณ์ ปัญญาสาร", links=[
    osint.IdentityLink(kind="profile", value="facebook:thana.pya", sources=["S1", "S2"]),
    osint.IdentityLink(kind="email", value="thana_p@acme.co.th", sources=["S1"]),
    osint.IdentityLink(kind="phone", value="081-234-5678", sources=["S3"]),
])
handles = coordinator._handles_to_enumerate(ident, sel, 3)
check("coordinator: ดึงชื่อบัญชีจากโปรไฟล์ก่อน", handles[0] == "thana.pya", handles)
check("coordinator: ใช้ส่วนหน้าอีเมลเป็นชื่อบัญชีด้วย", "thana_p" in handles, handles)
check("coordinator: ไม่เอาเบอร์โทรไปค้นเป็นชื่อบัญชี",
      not any(h.startswith("081") for h in handles), handles)
check("coordinator: เคารพเพดานจำนวน", len(coordinator._handles_to_enumerate(ident, sel, 1)) == 1)

srv.shutdown()
print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
