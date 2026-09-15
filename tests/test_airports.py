"""เทสโมดูลค้นหาสนามบิน (airports.py) — โหลด/สกัดข้อความ/ค้น/จัดข้อความ

ใช้ fixture ชั่วคราวเป็นหลัก (ไม่พึ่งไฟล์จริง) และเช็กว่า loader รองรับทั้ง dict
(คีย์ด้วยรหัส) และ list ของ object
"""
import sys, os, json, tempfile, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

import airports

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

DICT_DB = {
    "VTBS": {"icao": "VTBS", "iata": "BKK", "name": "Suvarnabhumi Airport",
             "city": "Bangkok", "country": "TH", "lat": 13.681, "lon": 100.747, "tz": "Asia/Bangkok"},
    "RJTT": {"icao": "RJTT", "iata": "HND", "name": "Tokyo Haneda International Airport",
             "city": "Tokyo", "country": "JP"},
    "RJAA": {"icao": "RJAA", "iata": "NRT", "name": "Narita International Airport",
             "city": "Tokyo", "country": "JP"},
}
LIST_DB = [
    {"iata": "BKK", "icao": "VTBS", "name": "Suvarnabhumi Airport", "city": "Bangkok", "country": "TH"},
]
# สคีมาแบบไฟล์จริงของผู้ใช้: ห่อด้วยคีย์ "airports" เป็น list และใช้ฟิลด์ "code"
CODE_DB = {"airports": [
    {"code": "ATL", "name": "Hartsfield-Jackson Atlanta International", "city": "Atlanta", "country": "US"},
    {"code": "BKK", "name": "Suvarnabhumi Airport", "city": "Bangkok", "country": "TH"},
]}

def _write(obj):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "airports.json")
    json.dump(obj, open(p, "w", encoding="utf-8"), ensure_ascii=False)
    return p

# ---------- 1. loader: รองรับทั้ง dict และ list ----------
recs = airports.load_airports(_write(DICT_DB))
check("load: dict-คีย์-ด้วยรหัส -> 3 ระเบียน", len(recs) == 3, len(recs))
check("load: normalize ฟิลด์ครบ", all(k in recs[0] for k in ("icao", "iata", "name", "city", "country")))
recs_list = airports.load_airports(_write(LIST_DB))
check("load: list ของ object -> 1 ระเบียน", len(recs_list) == 1, len(recs_list))
check("load: ไฟล์ไม่มี -> [] (ไม่ throw)", airports.load_airports("/no/such/airports.json") == [])
# สคีมาไฟล์จริง: {"airports":[{"code":...}]} — ฟิลด์ code ต้องค้นด้วยรหัสได้
code_recs = airports.load_airports(_write(CODE_DB))
check("load: schema {'airports':[{'code'..}]} -> 2 ระเบียน", len(code_recs) == 2, len(code_recs))
check("load: ฟิลด์ code แมปเป็นรหัสค้นได้",
      airports.search_airports(code_recs, "ATL") and
      airports.search_airports(code_recs, "ATL")[0]["name"].startswith("Hartsfield"),
      code_recs)
check("load: code -> iata (3 ตัว) ในผลลัพธ์", code_recs[0].get("iata") == "ATL", code_recs[0])

# ---------- 2. extract_query: สกัดข้อความ ----------
check("extract: IATA 3 ตัว", airports.extract_query("bkk") == {"raw": "bkk", "value": "BKK", "kind": "iata"})
check("extract: ICAO 4 ตัว", airports.extract_query("VTBS")["kind"] == "icao")
check("extract: ชื่อ/เมือง = text", airports.extract_query("Bangkok")["kind"] == "text")
check("extract: ตัดช่องว่างหัวท้าย/ยุบช่องว่าง",
      airports.extract_query("  cdg  ") == {"raw": "  cdg  ", "value": "CDG", "kind": "iata"})
check("extract: ภาษาไทยเป็น text", airports.extract_query("กรุงเทพ")["kind"] == "text")

# ---------- 3. search_airports (pure) ----------
h = airports.search_airports(recs, "BKK")
check("search: IATA ตรงเป๊ะ -> Suvarnabhumi", len(h) == 1 and h[0]["name"].startswith("Suvarnabhumi"), h)
check("search: ICAO ตรงเป๊ะ", airports.search_airports(recs, "RJTT")[0]["iata"] == "HND")
multi = airports.search_airports(recs, "Tokyo")
check("search: ชื่อเมืองตรงหลายผล", len(multi) == 2, multi)
check("search: substring ในชื่อ", airports.search_airports(recs, "Haneda")[0]["icao"] == "RJTT")
check("search: ไม่พบ -> []", airports.search_airports(recs, "ZZZ") == [])
check("search: คำค้นว่าง -> []", airports.search_airports(recs, "  ") == [])

# ---------- 4. format ----------
one = airports.format_results(airports.search_airports(recs, "BKK"), "BKK", via="ไฟล์")
check("format: ผลเดียวมี ชื่อ/เมือง/ประเทศ",
      "ชื่อ:" in one and "เมือง:" in one and "ประเทศ:" in one, one)
check("format: แสดงรหัส IATA/ICAO", "BKK" in one and "VTBS" in one)
many = airports.format_results(multi, "Tokyo")
check("format: หลายผลระบุจำนวน", "พบ 2 สนามบิน" in many, many[:60])
check("format: ไม่พบมีข้อความแนะนำ", "ไม่พบ" in airports.format_results([], "ZZZ"))

# ---------- 5. es_search graceful (ไม่มี ES) ----------
if not airports.es_configured():
    check("es_search: ไม่มี ES คืน None (ให้ fallback)", airports.es_search("BKK") is None)
    check("reindex_es: ไม่มี ES คืน 0", airports.reindex_es(_write(DICT_DB)) == 0)

# ---------- 6. ไฟล์ starter จริงในโปรเจกต์ (ถ้ามี) ----------
real = airports.load_airports()
if real:
    check("starter: /airport BKK ใช้งานได้จริง",
          bool(airports.search_airports(real, "BKK")))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
