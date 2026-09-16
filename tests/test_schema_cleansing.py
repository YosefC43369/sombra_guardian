"""เทส reference_data.schema (Task 1: field extraction/structure mapping) และ
reference_data.cleansing (Task 2: cleansing + dedup + index) — ทำงานได้โดยไม่ต้องมี ES จริง
และยึด whitelist เดิม (airports, programming-languages) ไม่ใช่ engine ทั่วไป
"""
import sys, os, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

from reference_data import schema as sch
from reference_data import cleansing as cl
from reference_data import search_index as si

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ================= schema (Task 1) =================
# ---------- infer_type ----------
check("infer_type: None -> null", sch.infer_type(None) == "null")
check("infer_type: '' -> empty", sch.infer_type("  ") == "empty")
check("infer_type: '13' -> int (string ตัวเลข)", sch.infer_type("13") == "int")
check("infer_type: '-13.5' -> float", sch.infer_type("-13.5") == "float")
check("infer_type: 'BKK' -> str", sch.infer_type("BKK") == "str")
check("infer_type: True -> bool", sch.infer_type(True) == "bool")

# ---------- profile_records ----------
RECS = [
    {"code": "BKK", "name": "Suvarnabhumi", "city": "Bangkok", "lat": "13.69"},
    {"code": "CNX", "name": "Chiang Mai", "city": "Chiang Mai", "lat": "18.77"},
    {"code": "HKT", "name": "Phuket", "city": ""},   # city ว่าง, ไม่มี lat
]
prof = sch.profile_records(RECS)
check("profile: rows_seen/sampled = 3", prof["rows_seen"] == 3 and prof["sampled"] == 3)
check("profile: field_order คงลำดับที่พบครั้งแรก",
      prof["field_order"] == ["code", "name", "city", "lat"], prof["field_order"])
check("profile: code เห็นครบ 3 แถว", prof["fields"]["code"]["count"] == 3)
check("profile: lat เห็นแค่ 2 แถว (แถวสามไม่มี)", prof["fields"]["lat"]["count"] == 2)
check("profile: city ว่างนับเป็น non_null=2", prof["fields"]["city"]["non_null"] == 2)
check("profile: lat เดาชนิดเด่นเป็น float", sch.dominant_types(prof)["lat"] == "float")
check("profile: field_names ทางลัดตรงกับ order",
      sch.field_names(RECS) == prof["field_order"])

# ---------- sample cap (ความเร็วกับไฟล์ใหญ่) ----------
big = ({"code": f"C{i}", "n": i} for i in range(100000))
capped = sch.profile_records(big, sample_limit=50)
check("profile: หยุดที่ sample_limit (truncated) — เร็วกับไฟล์ใหญ่",
      capped["sampled"] == 50 and capped["truncated"] is True)

# ---------- whitelist gating ----------
check("profile_dataset: นอก whitelist -> None", sch.profile_dataset("passwords.json") is None)
check("sql_schema: นอก whitelist -> None", sch.sql_schema("leaks.sql") is None)
check("sql_schema: ไม่ใช่ .sql -> None", sch.sql_schema("airports.json") is None)

# ================= cleansing (Task 2) =================
# ---------- clean_record ----------
c = cl.clean_record({"  Code ": " bkk ", "Name": "  Suvarnabhumi   Airport ", "note": "  "})
check("clean: strip+lower key, ยุบช่องว่างในค่า",
      c == {"code": "bkk", "name": "Suvarnabhumi Airport"}, c)
check("clean: drop ฟิลด์ว่าง (note ถูกตัด)", "note" not in c)
check("clean: record ไม่ใช่ dict -> {}", cl.clean_record(["x"]) == {})

# ---------- dedupe: ทั้งแถว ----------
dup = [{"code": "BKK", "n": "1"}, {"code": "BKK", "n": "1"}, {"code": "CNX", "n": "2"}]
out = list(cl.dedupe(dup))
check("dedupe(ทั้งแถว): ตัดแถวซ้ำเป๊ะ", len(out) == 2, out)

# ---------- dedupe: ตามคีย์ + ไม่สนตัวพิมพ์/ช่องว่าง ----------
byk = [{"code": "BKK", "n": "1"}, {"code": " bkk ", "n": "2"}, {"code": "CNX", "n": "3"}]
outk = list(cl.dedupe(byk, keys=["code"]))
check("dedupe(คีย์): ' bkk '≈'BKK' ถือว่าซ้ำ (ตัวแรกชนะ)",
      len(outk) == 2 and outk[0]["n"] == "1", outk)

# ---------- clean_stream: clean แล้ว dedupe ----------
stream_in = [{"Code": " BKK ", "x": "a"}, {"code": "bkk", "x": "a"}, {"code": "cnx", "x": "b"}]
streamed = list(cl.clean_stream(stream_in, keys=["code"]))
check("clean_stream: clean+dedupe ทำงานร่วมกัน", len(streamed) == 2, streamed)

# ---------- clean_and_index: whitelist + graceful (ไม่มี ES) ----------
check("clean_and_index: นอก whitelist -> indexed 0, raw 0",
      cl.clean_and_index("passwords.json")["indexed"] == 0)

# index ผ่าน fake ES client (พิสูจน์ว่า pipeline ป้อน record ที่ clean+dedupe ให้ตัว index จริง)
class _FakeIndices:
    def __init__(self): self.created_body = None
    def exists(self, index=None): return False
    def delete(self, index=None): pass
    def create(self, index=None, body=None): self.created_body = body
    def refresh(self, index=None): pass
class _FakeClient:
    def __init__(self): self.docs = []; self.indices = _FakeIndices()
    def index(self, index=None, id=None, document=None): self.docs.append(document)

fake = _FakeClient()
_orig_client, _orig_helpers = si._client, si._helpers
try:
    si._client = lambda: fake
    si._helpers = lambda: None      # บังคับ path index ทีละ doc (นับง่าย)
    # ป้อน records ตรง ๆ (จำลองข้อมูลจาก .sql/.json ที่สกัดมา) ผ่าน search_index หลัง clean+dedupe
    raw = [
        {"Code": " BKK ", "City": "Bangkok"},
        {"code": "bkk", "city": "bangkok"},      # ซ้ำ (ต่างแค่รูปแบบ)
        {"code": "CNX", "city": "Chiang Mai"},
    ]
    cleaned = list(cl.clean_stream(raw, keys=["code"]))
    n = si.index_dataset("airports.json", records=cleaned)
    check("clean+index: ป้อนของที่ dedupe แล้ว -> index 2 doc", n == 2, n)
    check("clean+index: doc ผ่าน doc_from_record (มี _all_text)",
          all("_all_text" in d for d in fake.docs))
finally:
    si._client, si._helpers = _orig_client, _orig_helpers

# clean_and_index บน dataset จริงใน whitelist (airports.json มีไฟล์ในเครื่อง) — ไม่มี ES => indexed 0
# แต่ raw/cleaned ต้องเดินได้และไม่ throw
if not si.es_available():
    st = cl.clean_and_index("airports.json")
    check("clean_and_index(airports, no-ES): ไม่ throw + indexed 0",
          st["indexed"] == 0 and st["dataset"] == "airports.json")
    check("clean_and_index: อ่าน raw ได้ (>0) จากไฟล์ในเครื่อง", st["raw"] > 0, st)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
