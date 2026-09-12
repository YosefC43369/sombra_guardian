"""จำลองสถานการณ์จริงบนเซิร์ฟเวอร์: app.py ใหม่ + search.py เก่า"""
import sys, os, types, asyncio, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT); os.chdir(_ROOT)
os.environ.setdefault("BOT_TOKEN", "1:dummy")
logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(message)s")
import app, search

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

app.is_admin = lambda u, c: asyncio.sleep(0, result=True)
app.check_and_use_quota = lambda *a, **k: (True, 1, 50)
app.write_audit_log = lambda *a, **k: None

class M:
    _i = [1]
    def __init__(s): s.message_id = M._i[0]; M._i[0] += 1
    async def reply_text(s, t, **k): SINK.append(t); return M()
class B:
    username = "bot"
    async def send_chat_action(s, *a, **k): return True
    async def delete_message(s, *a, **k): return True
class U:
    def __init__(s):
        s.message = M(); s.effective_message = s.message
        s.effective_chat = types.SimpleNamespace(id=-1, type="supergroup")
        s.effective_user = types.SimpleNamespace(id=1)
class C:
    def __init__(s, a): s.args, s.bot = a, B()

# --- ถอด get_combined_results_async ออก เหมือน search.py เวอร์ชันเก่า ---
saved = search.get_combined_results_async
del search.get_combined_results_async
search.get_search_results_async = lambda q, **kw: asyncio.sleep(
    0, result=[{"title": "ผลจาก dark web", "link": "http://aaaaaaaaaaaaaaaa.onion/x"}])

SINK = []
try:
    asyncio.run(app.cmd_search(U(), C(["ธนาธรณ์", "ปัญญาสาร"])))
    check("search.py เก่า: /search ไม่ระเบิด (เดิมเป็น AttributeError)", True)
except AttributeError as e:
    check("search.py เก่า: /search ไม่ระเบิด (เดิมเป็น AttributeError)", False, repr(e))
check("search.py เก่า: ยังตอบผู้ใช้ได้", any("OSINT SEARCH" in t for t in SINK), SINK)
check("search.py เก่า: ยังคืนผลจากฝั่งที่ใช้ได้", any("aaaaaaaaaaaaaaaa" in t for t in SINK), SINK)

check("ตรวจความครบ: ตรวจเจอว่าขาด", app.check_module_integrity() is False)

search.get_combined_results_async = saved
check("ตรวจความครบ: ครบแล้วรายงานผ่าน", app.check_module_integrity() is True)

SINK = []
search.get_combined_results_async = lambda q, **kw: asyncio.sleep(
    0, result=[{"title": "ผลเว็บเปิด", "link": "https://example.org/p", "origin": "clearnet"}])
asyncio.run(app.cmd_search(U(), C(["ธนาธรณ์", "ปัญญาสาร"])))
check("search.py ใหม่: ใช้ตัวรวมสองฝั่ง", any("example.org" in t for t in SINK), SINK)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
