"""เทสความแม่นการค้นหาแหล่งสาธารณะ (public-source) + การปกปิด PII + ยืนยันข้ามแหล่ง

ครอบคลุมของที่เพิ่มเข้ามาเพื่อให้ /search:
1. ปกปิด PII (เบอร์/อีเมล/เลขบัตรประชาชน/เลขยาว) ก่อนแสดงผลเสมอ — เครื่องมือ
   OSINT เชิงตั้งรับต้องไม่กลายเป็นท่อส่งข้อมูลส่วนบุคคลดิบ
2. จัดอันดับด้วยน้ำหนักตามชนิด selector — หน้าที่ตรงอีเมล/เบอร์/ชื่อเป้าหมาย
   ต้องมาก่อนหน้าที่บังเอิญมีคำ keyword ทั่วไป
3. ยืนยันข้ามแหล่ง (corroboration) — ตัวระบุที่พบใน >=2 โฮสต์อิสระถูกชูขึ้นมา
   โดยไม่นับหลายหน้าของเว็บเดียวกันเป็นหลายแหล่ง
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


# ---------- 1. mask_pii ----------
m = osint.mask_pii("โทร 081-234-5678 อีเมล john.doe@acme.co.th บัตร 1-2345-67890-12-3")
check("mask: เบอร์เต็มไม่โผล่", "0812345678" not in m and "2345678" not in m, m)
check("mask: เบอร์เหลือหัว 2 + ท้าย 2", "08" in m and m.rstrip().endswith(("78", "]")) or "78" in m, m)
check("mask: อีเมล local ถูกปกปิด แต่คงโดเมนไว้",
      "john.doe@" not in m and "@acme.co.th" in m, m)
check("mask: เลขบัตรประชาชน 13 หลักถูกปกปิดทั้งหมด",
      "1234567890123" not in m and "เลขบัตร ปกปิด" in m, m)

# เลขยาว (บัญชี/บัตร) เหลือ 4 ตัวท้าย
m2 = osint.mask_pii("acct 1234567890123456 done")
check("mask: เลขยาว 16 หลักเหลือ 4 ตัวท้าย", "3456" in m2 and "123456789012" not in m2, m2)

# ปกปิดข้อความว่าง / ไม่มี PII -> ไม่พัง และไม่เปลี่ยนข้อความปกติ
check("mask: ข้อความว่างปลอดภัย", osint.mask_pii("") == "")
check("mask: ข้อความไม่มี PII ไม่ถูกแตะ", osint.mask_pii("hello world") == "hello world")

# ลิงก์: ปิด mask_phones/long เพื่อไม่กลบเลข path ปกติ แต่ยังปกปิดบัตร/อีเมล
lk = osint.mask_pii("https://site.co.th/article/12345",
                    mask_phones=False, mask_long_digits=False)
check("mask(link): เลข path ปกติยังอยู่ (คลิกต่อได้)", "12345" in lk, lk)
lk2 = osint.mask_pii("https://leak.site/u?nid=1234567890123",
                     mask_phones=False, mask_long_digits=False)
check("mask(link): เลขบัตร 13 หลักใน URL ถูกปกปิด", "1234567890123" not in lk2, lk2)

# ---------- 2. จัดอันดับด้วยน้ำหนักตามชนิด selector ----------
sel = osint.extract_selectors("target@acme.co.th somekeyword")
groups = [[
    {"title": "hit", "link": "http://a.onion/1", "snippet": "contact target@acme.co.th"},
    {"title": "somekeyword page", "link": "http://b.onion/2", "snippet": "somekeyword only"},
]]
ranked = osint.merge_and_rank(groups, sel, limit=10)
check("rank: หน้าที่ตรงอีเมลเป้าหมายมาก่อนหน้าที่ตรงแค่ keyword",
      "a.onion" in ranked[0]["link"],
      [(r["link"], r["relevance"]) for r in ranked])
check("rank: อีเมลได้คะแนนมากกว่า keyword ทั่วไป",
      ranked[0]["relevance"] > ranked[1]["relevance"],
      [(r["link"], r["relevance"]) for r in ranked])

# ไม่ส่ง selectors -> ถอยไปนับแบบเดิม ไม่พัง
nofilter = osint.merge_and_rank(groups, None, limit=10)
check("rank: ไม่มี selector ก็ยังทำงาน (ไม่พัง)", len(nofilter) == 2, nofilter)

# ---------- 3. ยืนยันข้ามแหล่ง (corroboration) ----------
disp = [
    {"link": "http://x.onion/1", "title": "A", "snippet": "email me@acme.co.th"},
    {"link": "http://y.onion/2", "title": "B", "snippet": "reach me@acme.co.th too"},
    {"link": "http://x.onion/3", "title": "C", "snippet": "same me@acme.co.th here"},
]
corr = osint.corroborated_identifiers(disp, min_sources=2)
hit = [c for c in corr if c["value"].lower() == "me@acme.co.th"]
check("corr: ตัวระบุที่พบใน 2 โฮสต์อิสระถูกชูขึ้นมา", bool(hit), corr)
check("corr: นับ 'โฮสต์อิสระ' ไม่ใช่จำนวนหน้า (x.onion นับครั้งเดียว)",
      hit and hit[0]["sources"] == 2, hit)

# เว็บเดียวพ่นอีเมลเดิมหลายหน้า -> ไม่นับเป็นการยืนยันข้ามแหล่ง
same_host = [
    {"link": "http://only.onion/1", "title": "A", "snippet": "me@acme.co.th"},
    {"link": "http://only.onion/2", "title": "B", "snippet": "me@acme.co.th"},
    {"link": "http://only.onion/3", "title": "C", "snippet": "me@acme.co.th"},
]
corr2 = osint.corroborated_identifiers(same_host, min_sources=2)
check("corr: เว็บเดียวหลายหน้าไม่ถือว่ายืนยันข้ามแหล่ง",
      not any(c["value"].lower() == "me@acme.co.th" for c in corr2), corr2)

# ---------- 4. รายงาน /search: เนื้อหาที่ scrape ถูกปกปิด, header (คำค้นของผู้ใช้) ไม่ถูกแตะ ----------
sel2 = osint.extract_selectors("me@acme.co.th")
ranked2 = osint.merge_and_rank([disp], sel2, limit=10)
rep = osint.format_search_report("me@acme.co.th", sel2, ["me@acme.co.th"], ranked2)
body = "\n".join(ln for ln in rep.splitlines()
                 if ln.strip().startswith(("คำโปรย:", "- [")))
check("report: อีเมลใน 'คำโปรย/ยืนยันข้ามแหล่ง' ถูกปกปิด",
      "me@acme.co.th" not in body, body)
check("report: มีส่วน 'ยืนยันข้ามแหล่ง'", "ยืนยันข้ามแหล่ง" in rep, rep[:120])
check("report: ระบุว่า PII ถูกปกปิดในการแสดงผล", "ปกปิด" in rep, rep[-200:])

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
