"""เทสกันบั๊กที่พบตอน deploy /search:
1. คำ "ป้ายกำกับ" (เบอร์/โทร/email/id) ต้องไม่ปนเข้าไปในชื่อบุคคล
2. ผลขยะที่ไม่ตรงเป้า (เช่น lite.ip2location.com) ต้องไม่ได้คะแนนจากการนับซ้ำ
   และต้องถูกซ่อนในผล /search เมื่อมีผลตรงเป้าอยู่แล้ว
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
import osint

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n)
    print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ---------- 1. ป้ายกำกับต้องไม่ปนเข้าไปในชื่อ ----------
cases = [
    ("วิชชา กลิ่นหอม เบอร์: 092-794-6597", ["วิชชา กลิ่นหอม"], "092-794-6597"),
    ("สมชาย ใจดี โทร 081-111-2222", ["สมชาย ใจดี"], "081-111-2222"),
    ("ธนาธรณ์ ปัญญาสาร อีเมล a@b.com", ["ธนาธรณ์ ปัญญาสาร"], None),
    ("ชื่อ วิชชา กลิ่นหอม", ["วิชชา กลิ่นหอม"], None),
]
for text, want_names, want_phone in cases:
    sel = osint.extract_selectors(text)
    check(f"name label: {text[:32]!r} -> ชื่อ={want_names}", sel.names == want_names,
          f"got {sel.names}")
    if want_phone:
        check(f"name label: ยังจับเบอร์ {want_phone} ได้", want_phone in sel.phones, sel.phones)
# query ต้องไม่มีคำว่า "เบอร์" ติดในวลีชื่อ
q = osint.plan_queries("วิชชา กลิ่นหอม เบอร์: 092-794-6597", max_queries=5)
check("name label: query ไม่มีคำว่า 'เบอร์' ปนในวลีชื่อ",
      not any("เบอร์" in x for x in q), q)
check("name label: มี query ชื่อที่สะอาด", '"วิชชา กลิ่นหอม"' in q, q)

# ---------- 2. ผลขยะไม่ได้คะแนนจากการนับซ้ำ ----------
sel = osint.extract_selectors("วิชชา กลิ่นหอม")
junk_repeated = [[
    {"title": "IP2Location", "link": "https://lite.ip2location.com/",
     "snippet": "IP geolocation lookup", "engine": "Marginalia"},
    {"title": "IP2Location", "link": "https://lite.ip2location.com/?a=1",
     "snippet": "IP geolocation lookup", "engine": "Marginalia"},
    {"title": "IP2Location", "link": "https://lite.ip2location.com/?a=2",
     "snippet": "IP geolocation lookup", "engine": "Marginalia"},
]]
ranked = osint.merge_and_rank(junk_repeated, sel, limit=10)
check("junk rank: ผลไม่ตรงเป้าที่พบซ้ำ ยังได้ relevance 0",
      ranked and ranked[0]["relevance"] == 0, ranked)

# ตรงเป้า + ขยะปนกัน — ตรงเป้าต้องมาก่อน
mixed = [[
    {"title": "IP2Location", "link": "https://lite.ip2location.com/", "snippet": "geo",
     "engine": "Marginalia"},
    {"title": "IP2Location", "link": "https://lite.ip2location.com/", "snippet": "geo",
     "engine": "Mojeek"},
    {"title": "โปรไฟล์ วิชชา กลิ่นหอม", "link": "https://example.co.th/p/wissha",
     "snippet": "วิชชา กลิ่นหอม", "engine": "Mojeek"},
]]
ranked = osint.merge_and_rank(mixed, sel, limit=10)
check("junk rank: ผลตรงเป้าอยู่บนสุด", "example.co.th" in ranked[0]["link"],
      [(r["link"], r["relevance"]) for r in ranked])

# ---------- 3. ชั้นแสดงผล /search ซ่อนผลขยะเมื่อมีผลตรงเป้า ----------
report = osint.format_search_report("วิชชา กลิ่นหอม", sel, ["วิชชา กลิ่นหอม"], ranked)
check("display: ซ่อน ip2location เมื่อมีผลตรงเป้า", "ip2location" not in report, report)
check("display: แสดงผลตรงเป้า", "example.co.th" in report, report)

# ทั้งหมดเป็นขยะ (ไม่มีผลตรงเป้า) — ต้องแสดงพร้อมคำเตือน ไม่ใช่ทำเป็นผลอันดับ 1 เฉยๆ
junk_only = osint.merge_and_rank(junk_repeated, sel, limit=10)
report2 = osint.format_search_report("วิชชา กลิ่นหอม", sel, ["วิชชา กลิ่นหอม"], junk_only)
check("display: ทั้งหมดขยะ -> เตือนว่าความเกี่ยวข้องต่ำ", "ความเกี่ยวข้องต่ำ" in report2, report2)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
