"""เทส reference_data.search_index — ชั้นค้นหา Elasticsearch ของ dataset อ้างอิง
(เฉพาะส่วนที่ทดสอบได้โดยไม่ต้องมี ES จริง: สร้างเอกสาร/คิวรี/whitelist/graceful)
"""
import sys, os, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

from reference_data import search_index as si

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

REC = {"code": "BKK", "name": "Suvarnabhumi Airport", "city": "Bangkok", "country": "TH", "lat": 13.69}

# ---------- 1. doc_from_record ----------
doc = si.doc_from_record(REC)
check("doc: คงฟิลด์เดิมครบ", all(doc[k] == REC[k] for k in REC))
check("doc: มี _all_text/_all_auto", "Suvarnabhumi" in doc["_all_text"] and doc["_all_auto"] == doc["_all_text"])
check("doc: _codes จับรหัสสั้น (BKK/TH) ไม่จับชื่อยาว",
      set(doc["_codes"]) == {"BKK", "TH"}, doc.get("_codes"))
check("doc: ตัวเลขเข้า _all_text", "13.69" in doc["_all_text"])
check("strip: ตัดฟิลด์ช่วยค้นออกเหลือ record เดิม", si._strip_helpers(doc) == REC)

# ---------- 2. index name + whitelist ----------
check("index_name: derive stem จากทุกฟอร์แมต",
      si.index_name("airports.json") == si.index_name("airports.csv") == si.index_name("airports.sql")
      == f"{si.ES_PREFIX}_airports")
check("whitelist: มี 2 stem อ้างอิง", si._allowed_stems() == {"airports", "programming-languages"})

# ---------- 3. build_query โครงหลายสัญญาณ ----------
q = si.build_query("BKK", 7)
shoulds = q["query"]["bool"]["should"]
kinds = [list(s.keys())[0] for s in shoulds]
check("query: มีสัญญาณ term/phrase_prefix/match(autocomplete)/fuzzy",
      kinds == ["term", "match_phrase_prefix", "match", "match"], kinds)
check("query: term ยิงที่ _codes (รหัสตรง) boost สูงสุด", shoulds[0]["term"]["_codes"]["boost"] == 12)
check("query: autocomplete ยิงที่ _all_auto", shoulds[2]["match"]["_all_auto"]["query"] == "BKK")
check("query: fuzzy AUTO บน _all_text", shoulds[3]["match"]["_all_text"]["fuzziness"] == "AUTO")
check("query: track_total_hits=False (เร็วขึ้น)", q["track_total_hits"] is False)
check("query: size เคารพ limit", q["size"] == 7)

# ---------- 4. graceful เมื่อไม่มี ES ----------
if not si.es_available():
    check("search: no-ES คืน None (ให้ fallback)", si.search("airports", "BKK") is None)
    check("index_dataset: no-ES คืน 0", si.index_dataset("airports.json", records=[REC]) == 0)
    check("index_dataset: นอก whitelist คืน 0", si.index_dataset("passwords.json", records=[REC]) == 0)
check("search: คำค้นว่าง -> [] (ไม่ยิง ES)", si.search("airports", "   ") == [])

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
