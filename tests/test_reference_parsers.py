"""เทส multi-format parsers (JSON/CSV/SQL) ของ reference_data + get_records()

ยืนยันว่าทั้ง 3 ฟอร์แมตให้ record ที่ "เทียบเท่ากัน" และปลอดภัย/ไม่ล่มกับไฟล์เสีย
SQL ต้องถูก "parse" ไม่ใช่ "execute" (คำสั่งอันตรายถูกเพิกเฉย)
"""
import sys, os, json, tempfile, pathlib, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)
logging.basicConfig(level=logging.ERROR)

from reference_data import parsers
import reference_data.cache_manager as cache
import reference_data.dataset_manager as dm

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

D = tempfile.mkdtemp()
def _w(name, text):
    p = os.path.join(D, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p

REC = {"code": "BKK", "name": "Suvarnabhumi", "city": "Bangkok", "country": "TH"}

# ---------- 1. ความเทียบเท่าข้ามฟอร์แมต ----------
pj = _w("airports.json", json.dumps({"airports": [REC]}, ensure_ascii=False))
pc = _w("airports.csv", "code,name,city,country\nBKK,Suvarnabhumi,Bangkok,TH\n")
psql = _w("airports.sql",
          "CREATE TABLE airports (code VARCHAR(3), name TEXT, city TEXT, country TEXT);\n"
          "INSERT INTO airports (code,name,city,country) VALUES ('BKK','Suvarnabhumi','Bangkok','TH');\n")
rj = parsers.parse("airports.json", pj)
rc = parsers.parse("airports.csv", pc)
rs = parsers.parse("airports.sql", psql)
check("equiv: JSON == CSV == SQL", rj == rc == rs == [REC], (rj, rc, rs))

# ---------- 2. JSON variants ----------
check("json: bare array", parsers.parse("a.json", _w("a.json", json.dumps([REC]))) == [REC])
check("json: dict-คีย์-ด้วยรหัส", parsers.parse("b.json", _w("b.json",
      json.dumps({"BKK": {"name": "Suvarnabhumi"}})))[0]["code"] == "BKK")
check("jsonl: ทีละบรรทัด", parsers.parse("c.jsonl", _w("c.jsonl",
      json.dumps(REC) + "\n" + json.dumps({"code": "HND"}))) == [REC, {"code": "HND"}])

# ---------- 3. CSV features ----------
check("csv: delimiter ; อัตโนมัติ", parsers.parse("d.csv", _w("d.csv",
      "code;name\nBKK;Suvarnabhumi\n")) == [{"code": "BKK", "name": "Suvarnabhumi"}])
check("csv: quoted comma/newline", parsers.parse("e.csv", _w("e.csv",
      'code,name\nBKK,"Bangkok, TH"\n')) == [{"code": "BKK", "name": "Bangkok, TH"}])
check("csv: ไม่มี header -> colN", parsers.parse("f.csv", _w("f.csv", "1,2,3\n4,5,6\n"))[0]
      == {"col0": "1", "col1": "2", "col2": "3"})

# ---------- 4. SQL features + ความปลอดภัย ----------
sql2 = _w("m.sql", "CREATE TABLE t (a,b,c);\n"
                   "INSERT INTO t VALUES ('x,y','it''s',NULL),('2','b',3);\n")
rows = parsers.parse("m.sql", sql2)
check("sql: multi-row + NULL + quoted-comma + escaped-quote",
      rows == [{"a": "x,y", "b": "it's", "c": None}, {"a": "2", "b": "b", "c": "3"}], rows)
check("sql: list_tables ตรวจตาราง+คอลัมน์",
      parsers.sql_parser.list_tables(sql2) == {"t": ["a", "b", "c"]})
check("sql: with_table ห่อชื่อตาราง",
      parsers.sql_parser.parse(sql2, with_table=True)[0]["table"] == "t")
# คำสั่งอันตรายต้องถูก "เพิกเฉย" (ไม่ execute, ไม่ปรากฏเป็น record)
danger = _w("d2.sql", "DROP TABLE users;\nDELETE FROM users;\nGRANT ALL ON *.* TO 'x';\n"
                      "UPDATE users SET a=1;\nCREATE TABLE k (id);\nINSERT INTO k VALUES (7);\n")
dr = parsers.parse("d2.sql", danger)
check("sql: คำสั่งอันตรายถูกเพิกเฉย เหลือแต่ INSERT", dr == [{"id": "7"}], dr)

# ---------- 5. ไฟล์เสีย/ว่าง -> ไม่ throw, คืน [] ----------
check("bad json -> []", parsers.parse("x.json", _w("x.json", "{not valid")) == [])
check("bad csv (ยังอ่านได้บางส่วน)", isinstance(parsers.parse("y.csv", _w("y.csv", 'a,b\n"unterminated,1\n')), list))
check("bad sql -> [] (ไม่ throw)", parsers.parse("z.sql", _w("z.sql", "INSERT INTO ((( garbage")) == [])
check("empty json -> []", parsers.parse("e1.json", _w("e1.json", "")) == [])
check("empty csv -> []", parsers.parse("e2.csv", _w("e2.csv", "")) == [])
check("empty sql -> []", parsers.parse("e3.sql", _w("e3.sql", "")) == [])
check("unsupported ext -> []", parsers.parse("k.txt", _w("k.txt", "hello")) == [])

# ---------- 6. streaming เป็น iterator จริง (memory-safe) ----------
it = parsers.stream_records("airports.csv", pc)
check("stream: เป็น iterator ไม่ใช่ list", hasattr(it, "__next__"))
check("stream: ดึงทีละ record ได้", next(it) == REC)

# ---------- 7. get_records ผ่าน dataset_manager (dispatch ตามนามสกุล + whitelist) ----------
cache.CACHE_DIR = pathlib.Path(tempfile.mkdtemp())   # กันไปแตะ cache จริง
# วางไฟล์ csv/sql เป็น local fallback ของ dataset ที่อยู่ใน whitelist
dm.LOCAL_FALLBACK["airports.csv"] = pathlib.Path(pc)
dm.LOCAL_FALLBACK["airports.sql"] = pathlib.Path(psql)
check("get_records: .csv dispatch -> CSV parser", list(dm.get_records("airports.csv")) == [REC])
check("get_records: .sql dispatch -> SQL parser", list(dm.get_records("airports.sql")) == [REC])
check("get_records: ไฟล์นอก whitelist -> ว่าง", list(dm.get_records("secrets.csv")) == [])

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
