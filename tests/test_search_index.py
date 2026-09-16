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
    check("suggest: no-ES คืน None", si.suggest("airports", "ban") is None)
    check("did_you_mean: no-ES คืน None", si.did_you_mean("airports", "Bangkkok") is None)
    check("search_smart: no-ES คืน None", si.search_smart("airports", "x") is None)
check("search: คำค้นว่าง -> [] (ไม่ยิง ES)", si.search("airports", "   ") == [])
check("suggest: prefix ว่าง -> []", si.suggest("airports", "  ") == [])

# ---------- 5. ความฉลาดเพิ่ม: _index_body/doc/query ----------
body = si._index_body(False)
check("body: มี completion suggester (_suggest)", body["mappings"]["properties"]["_suggest"]["type"] == "completion")
check("body: มี synonym analyzer (folding_syn)", "folding_syn" in body["settings"]["analysis"]["analyzer"])
check("body: _all_text ใช้ search_analyzer synonym",
      body["mappings"]["properties"]["_all_text"]["search_analyzer"] == "folding_syn")
check("body: phonetic ปิด -> ไม่มี _all_phon", "_all_phon" not in body["mappings"]["properties"])
bp = si._index_body(True)
check("body: phonetic เปิด -> มี _all_phon + dm_filter (double_metaphone)",
      "_all_phon" in bp["mappings"]["properties"]
      and bp["settings"]["analysis"]["filter"]["dm_filter"]["encoder"] == "double_metaphone")
dd = si.doc_from_record(REC)
check("doc: _suggest.input มีชื่อ/เมือง/รหัส", dd["_suggest"]["input"] == ["Suvarnabhumi Airport", "Bangkok", "BKK", "TH"])
check("doc: default ไม่มี _all_phon (phonetic ปิด)", "_all_phon" not in dd)

# ---------- 6. parse logic ผ่าน fake ES client (ไม่ต้องมี ES จริง) ----------
class _FakeIndices:
    def exists(self, index=None): return False
    def delete(self, index=None): pass
    def create(self, index=None, body=None): pass
    def refresh(self, index=None): pass
class _FakeClient:
    def __init__(self, resp): self._resp = resp; self.indices = _FakeIndices()
    def search(self, index=None, body=None): return self._resp

_orig = si._client
try:
    # suggest: parse options -> record dict (ตัดฟิลด์ช่วยค้น)
    si._client = lambda: _FakeClient({"suggest": {"s": [{"options": [
        {"text": "Bangkok", "_source": si.doc_from_record(REC)}]}]}})
    sg = si.suggest("airports", "ban", 5)
    check("suggest(parse): คืน record ที่ตัดฟิลด์ช่วยค้นแล้ว", sg == [REC], sg)

    # did_you_mean: term suggester -> corrected string
    si._client = lambda: _FakeClient({"suggest": {"dym": [
        {"text": "bangkkok", "options": [{"text": "bangkok"}]}]}})
    check("did_you_mean(parse): แก้คำสะกดผิด", si.did_you_mean("airports", "bangkkok") == "bangkok")

    # did_you_mean: ไม่มี option -> None
    si._client = lambda: _FakeClient({"suggest": {"dym": [{"text": "bkk", "options": []}]}})
    check("did_you_mean(parse): ไม่มีคำแก้ -> None", si.did_you_mean("airports", "bkk") is None)
finally:
    si._client = _orig

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
