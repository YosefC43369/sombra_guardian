"""เทสชั้น Elasticsearch ของฐานข้อมูล OSINT (osint_es) — ส่วนที่ไม่ต้องมี ES จริง

ครอบคลุม: การแปลงระเบียน->เอกสาร (to_document), การค้นแบบ fallback (local_search),
การจัดข้อความผล (format_search_hits), และพฤติกรรม graceful เมื่อไม่มี/ไม่ได้ตั้งค่า ES
"""
import sys, os, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.WARNING)

import osint_db
import osint_es

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))


RECORDS = [
    {"title": "Nembutal for Sale", "link": "http://cavbo576.onion", "origin": "darkweb",
     "engine": "Amnesia", "relevance": 6, "engines": 1,
     "snippet": "buy nembutal Email: herolegend109@gmail.com"},
    {"title": "Darknet Vault", "link": "http://e5vkh6.onion", "origin": "darkweb",
     "engine": "Onionway", "relevance": 6, "engines": 1,
     "snippet": "marketplace contact herolegend109@gmail.com cards"},
    {"title": "Acme staff", "link": "https://acme.co.th/team", "origin": "clearnet",
     "engine": "Google", "relevance": 3, "engines": 2, "snippet": "team acme.co.th"},
]
rec_email = osint_db.build_finding_record("herolegend109@gmail.com leak", "email=1",
                                          RECORDS, actor=7)
rec_acme = osint_db.build_finding_record("acme.co.th corp", "domain=acme.co.th",
                                         RECORDS[2:], actor=7)
DB = [rec_email, rec_acme]

# ---------- 1. graceful เมื่อไม่มี/ไม่ตั้งค่า ES ----------
# (สภาพแวดล้อมเทสต์ไม่ได้ตั้ง OSINT_ES_URL) — ต้องไม่ throw และ search คืน None
check("es: es_configured เป็น bool", isinstance(osint_es.es_configured(), bool))
check("es: es_available เป็น bool", isinstance(osint_es.es_available(), bool))
if not osint_es.es_configured():
    check("es: search คืน None เมื่อไม่มี ES (ให้ fallback)", osint_es.search("x") is None)
    check("es: index_finding คืน False เมื่อไม่มี ES", osint_es.index_finding(rec_email) is False)

# ---------- 2. to_document ----------
doc = osint_es.to_document(rec_email)
check("doc: มีฟิลด์ค้นหาครบ",
      all(k in doc for k in ("id", "query", "text", "identifiers", "origins",
                             "hosts", "urls", "titles", "snippets")))
check("doc: origins เป็น keyword ของหมวด", set(doc["origins"]) == {"darkweb", "clearnet"}, doc["origins"])
check("doc: identifiers ยืนยันข้ามแหล่ง (email 2 โฮสต์)",
      "herolegend109@gmail.com" in doc["identifiers"], doc["identifiers"])
check("doc: text รวมคำค้น+ชื่อเรื่อง+คำโปรย", "Nembutal" in doc["text"] and "leak" in doc["text"])
check("doc: hosts เก็บโดเมนของแหล่ง", "cavbo576.onion" in doc["hosts"], doc["hosts"])

# ---------- 3. local_search (fallback) ----------
h1 = osint_es.local_search(DB, "herolegend109")
check("local: เจอระเบียนที่มีอีเมลนั้น", len(h1) == 1 and h1[0]["query"].startswith("herolegend109"), h1)
h2 = osint_es.local_search(DB, "acme")
check("local: จัดอันดับตามคะแนน (acme มาก่อน)", h2 and h2[0]["query"] == "acme.co.th corp", h2)
check("local: hit มีรูปแบบเดียวกับ ES search",
      all(k in h1[0] for k in ("id", "query", "saved_at", "score", "identifiers",
                               "hosts", "urls", "origins")))
check("local: คำค้นว่าง -> ไม่มีผล", osint_es.local_search(DB, "   ") == [])
check("local: ไม่พบ -> ลิสต์ว่าง", osint_es.local_search(DB, "zzzznotfound") == [])
check("local: เคารพ limit", len(osint_es.local_search(DB, "onion marketplace acme", limit=1)) <= 1)

# ---------- 4. format_search_hits ----------
txt = osint_es.format_search_hits(h1, "herolegend109", via="ไฟล์ JSON")
check("fmt: ระบุจำนวนที่พบ + backend", "พบ 1 ระเบียน" in txt and "ไฟล์ JSON" in txt)
check("fmt: แสดงรหัสระเบียน", rec_email["id"] in txt)
empty = osint_es.format_search_hits([], "nothing")
check("fmt: กรณีไม่พบมีข้อความแนะนำ", "ไม่พบ" in empty)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
