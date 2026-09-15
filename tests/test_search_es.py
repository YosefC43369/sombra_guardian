"""เทส telemetry การค้นหา (search_es) + สถิติฐานข้อมูล (osint.summarize_findings /
osint_es.aggregate_findings) — ส่วนที่ทดสอบได้โดยไม่ต้องมี Elasticsearch จริง

เน้นเส้นความปลอดภัย: telemetry ต้องเก็บ 'เมทาดาทาล้วน' ไม่มีเนื้อหา/PII และ
คำค้นถูกเก็บเป็นแฮชโดยดีฟอลต์
"""
import sys, os, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

import osint
import osint_db
import osint_es
import search_es

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

RECORDS = [
    {"title": "Vault", "link": "http://e5vkh6.onion", "origin": "darkweb",
     "engine": "Amnesia", "relevance": 6, "engines": 1, "snippet": "a@b.com cards"},
    {"title": "Vault2", "link": "http://cav.onion", "origin": "darkweb",
     "engine": "Onionway", "relevance": 6, "engines": 1, "snippet": "a@b.com passport"},
    {"title": "Acme", "link": "https://acme.co.th/t", "origin": "clearnet",
     "engine": "Google", "relevance": 3, "engines": 2, "snippet": "team acme.co.th"},
]
r1 = osint_db.build_finding_record("a@b.com leak", "e=1", RECORDS, actor=1)
r2 = osint_db.build_finding_record("acme.co.th", "d=1", RECORDS[2:], actor=1)

# ---------- 1. osint.summarize_findings (pure) ----------
s = osint.summarize_findings([r1, r2])
check("summary: total นับถูก", s["total"] == 2, s["total"])
check("summary: by_origin นับ sources", s["by_origin"].get("darkweb") == 2, s["by_origin"])
check("summary: by_ioc_type มี email", s["by_ioc_type"].get("email") == 1, s["by_ioc_type"])
check("summary: top_hosts เรียงตามความถี่", s["top_hosts"][0][0] == "acme.co.th", s["top_hosts"])
check("summary: corroborated_total >=1", s["corroborated_total"] >= 1, s["corroborated_total"])
check("summary: ว่างปลอดภัย", osint.summarize_findings([])["total"] == 0)

# ---------- 2. osint_es.aggregate_findings + format ----------
agg = osint_es.aggregate_findings([r1, r2])
check("aggregate: ใช้ summarize (total ตรงกัน)", agg["total"] == 2)
txt = osint_es.format_findings_stats(agg, es_on=False)
check("format: ระบุจำนวนระเบียน", "2 ระเบียน" in txt, txt[:80])
check("format: ระบุ backend เป็นไฟล์ JSON", "ไฟล์ JSON" in txt)
check("format: ฐานข้อมูลว่างมีข้อความแนะนำ",
      "ยังว่าง" in osint_es.format_findings_stats(osint.summarize_findings([])))

# ---------- 3. search_es.telemetry_doc: เมทาดาทาล้วน + คำค้นเป็นแฮช ----------
doc = search_es.telemetry_doc("john.doe@acme.co.th", {"darkweb": 2, "clearnet": 1},
                              3, 1234.5, cache_hit=True, tor_reachable=True,
                              engines=["Amnesia", "Onionway"])
check("telemetry: มี query_hash", "query_hash" in doc and len(doc["query_hash"]) == 64)
check("telemetry: ไม่เก็บคำค้นดิบโดยดีฟอลต์", "query" not in doc)
# ยืนยัน 'ไม่มีเนื้อหา/PII' — คีย์ที่อนุญาตต้องเป็นเมทาดาทาเท่านั้น
allowed = {"ts", "total", "elapsed_ms", "cache_hit", "origin_counts", "engines",
           "query_hash", "tor_reachable"}
check("telemetry: มีเฉพาะฟิลด์เมทาดาทา (ไม่มี title/snippet/url)",
      set(doc.keys()) <= allowed, set(doc.keys()) - allowed)
check("telemetry: elapsed_ms เป็น int", isinstance(doc["elapsed_ms"], int))
check("telemetry: origin_counts เป็นตัวเลขนับ",
      doc["origin_counts"] == {"darkweb": 2, "clearnet": 1})

# แฮชของคำค้นเดียวกันต้องคงที่ (dedup ได้) และ normalize ตัวพิมพ์/ช่องว่าง
d2 = search_es.telemetry_doc("  JOHN.DOE@acme.co.th ", None, 0, 0)
check("telemetry: แฮชคงที่หลัง normalize (case/trim)",
      d2["query_hash"] == doc["query_hash"], (d2["query_hash"], doc["query_hash"]))

# ---------- 4. graceful เมื่อไม่มี ES ----------
if not osint_es.es_configured():
    check("record_search: no-ES คืน False (ไม่บล็อก)", search_es.record_search("x") is False)
    check("engine_health: no-ES คืน None", search_es.engine_health(7) is None)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
