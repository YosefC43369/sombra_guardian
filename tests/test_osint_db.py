"""เทสการจัดหมวดหมู่ผลลัพธ์ (อิโมจิ) + ฐานข้อมูล OSINT ที่ยืนยันแล้ว (osint_db)"""
import sys, os, json, tempfile, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.WARNING)

import osint
import osint_db

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))


# ตัวอย่างผลค้น: darkweb 2 แหล่งอิสระ (อีเมลซ้ำ) + clearnet 1 + username 1
RECORDS = [
    {"title": "Nembutal for Sale", "link": "http://cavbo576.onion", "origin": "darkweb",
     "engine": "Amnesia", "relevance": 6, "engines": 1,
     "snippet": "buy nembutal Email: herolegend109@gmail.com"},
    {"title": "Darknet Vault", "link": "http://e5vkh6.onion", "origin": "darkweb",
     "engine": "Onionway", "relevance": 6, "engines": 1,
     "snippet": "marketplace contact herolegend109@gmail.com cards"},
    {"title": "Acme staff", "link": "https://acme.co.th/team", "origin": "clearnet",
     "engine": "Google", "relevance": 3, "engines": 2, "snippet": "john at acme.co.th"},
    {"title": "thana_p github", "link": "https://github.com/thana_p", "origin": "username",
     "engine": "db", "relevance": 0, "engines": 1, "snippet": ""},
]

# ---------- 1. Emoji maps ----------
check("emoji: origin_meta known", osint.origin_meta("darkweb")["emoji"] == "🕸️")
check("emoji: origin_meta fallback safe", osint.origin_meta("weird")["label"] == "อื่น ๆ")
check("emoji: ioc_emoji known", osint.ioc_emoji("email") == "✉️")
check("emoji: ioc_emoji unknown -> default", osint.ioc_emoji("zzz") == "🔹")

# ---------- 2. categorize_by_origin ----------
groups = osint.categorize_by_origin(RECORDS)
check("categorize: returns groups sorted by order (clearnet first)",
      [g["origin"] for g in groups] == ["clearnet", "darkweb", "username"],
      [g["origin"] for g in groups])
_dark = next(g for g in groups if g["origin"] == "darkweb")
check("categorize: darkweb has 2 items", len(_dark["items"]) == 2, _dark["items"])
# เลขอ้างอิง Sxx ต้องคงลำดับตามที่ส่งเข้ามา (S1..S4) ให้ตรงกับ corroboration
_refs = {it["ref"] for g in groups for it in g["items"]}
check("categorize: preserves S-refs by input order", _refs == {"S1", "S2", "S3", "S4"}, _refs)
check("categorize: empty input safe", osint.categorize_by_origin([]) == [])

# ---------- 3. format_search_report (อิโมจิ + หมวดหมู่) ----------
sel = osint.extract_selectors("gmail.com")
report = osint.format_search_report("gmail.com", sel, ["gmail.com"], RECORDS, limit=20)
check("report: shows dark web category header w/ emoji", "🕸️ Dark Web" in report, report[:80])
check("report: shows clearnet category header w/ emoji", "🌐 เว็บเปิด" in report)
check("report: per-source relevance line uses emoji", "🎯 relevance" in report)
check("report: corroboration grouped by IOC w/ emoji", "✉️ อีเมล" in report and "ยืนยันข้ามแหล่ง" in report)
check("report: keeps S-ref markers", "[S1]" in report)

# ---------- 4. build_finding_record ----------
rec = osint_db.build_finding_record("gmail.com", sel.summary(), RECORDS, actor=99)
check("record: has id + signature", bool(rec["id"]) and bool(rec["signature"]))
check("record: categories keyed by origin", set(rec["categories"]) == {"darkweb", "clearnet", "username"},
      list(rec["categories"]))
check("record: darkweb count == 2", rec["categories"]["darkweb"]["count"] == 2)
check("record: identifiers grouped -> email corroborated",
      "email" in rec["identifiers"] and rec["identifiers"]["email"]["values"][0]["sources"] >= 2,
      rec["identifiers"])
check("record: stores actor", rec["saved_by"] == 99)
check("record: stats sources == 4", rec["stats"]["sources"] == 4)

# ---------- 5. save_finding (สร้างไฟล์เมื่อยืนยัน / dedupe / atomic) ----------
_tmp = tempfile.mkdtemp()
_path = os.path.join(_tmp, "nested", "osint_db.json")
check("save: file absent before confirm", not os.path.exists(_path))
res1 = osint_db.save_finding(rec, _path)
check("save: created on first confirm", res1["created"] is True and res1["duplicate"] is False)
check("save: file exists after confirm", os.path.exists(_path))
check("save: total == 1", res1["total"] == 1)

# กดยืนยันซ้ำด้วยผลชุดเดิม -> ไม่บันทึกซ้ำ
rec_dup = osint_db.build_finding_record("gmail.com", sel.summary(), RECORDS, actor=99)
res2 = osint_db.save_finding(rec_dup, _path)
check("save: duplicate content not re-added", res2["duplicate"] is True and res2["total"] == 1)

# ผลชุดใหม่ (คำค้นต่างกัน) -> เพิ่มระเบียนใหม่
rec3 = osint_db.build_finding_record("acme.co.th", "domain=acme.co.th",
                                     RECORDS[2:3], actor=99)
res3 = osint_db.save_finding(rec3, _path)
check("save: new content appended", res3["duplicate"] is False and res3["total"] == 2)

# โครง JSON ที่เขียนออกมา
_data = json.load(open(_path, encoding="utf-8"))
check("json: schema tag", _data["schema"] == "sombra_guardian.osint_db")
check("json: 2 entries", len(_data["entries"]) == 2)
check("json: entries carry unique ids", len({e["id"] for e in _data["entries"]}) == 2)

# ---------- 6. load_db robustness ----------
check("load: missing file -> empty struct (no write)", osint_db.load_db(
    os.path.join(_tmp, "nope.json"))["entries"] == [])
_bad = os.path.join(_tmp, "bad.json")
open(_bad, "w").write("{ not json")
check("load: corrupt file -> empty struct (no raise)", osint_db.load_db(_bad)["entries"] == [])

# ---------- 7. format_saved_summary ----------
summary = osint_db.format_saved_summary(rec, res1)
check("summary: mentions created", "สร้างฐานข้อมูล" in summary)
check("summary: lists category emoji", "🕸️" in summary and "หมวดหมู่" in summary)
check("summary: shows record id", rec["id"] in summary)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
