import sys, os, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

# ทำแบบเดียวกับ app.py บรรทัด 9-10 ก่อน import โมดูลอื่น
from dotenv import load_dotenv
load_dotenv()
logging.basicConfig(level=logging.WARNING)

import requests, search, scrape

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

print("TOR_SOCKS_HOST=%r TOR_SOCKS_PORT=%r TOR_GATEWAY_SUFFIXES=%r"
      % (search.TOR_SOCKS_HOST, search.TOR_SOCKS_PORT, search.TOR_GATEWAY_SUFFIXES))
check("real .env loads without crashing search.py", isinstance(search.SEARCH_MAX_WORKERS, int))
check("real .env loads without crashing scrape.py", isinstance(scrape.MAX_RETURN_CHARS, int))
check("search/scrape agree on gateway suffixes",
      search.TOR_GATEWAY_SUFFIXES == scrape.TOR_GATEWAY_SUFFIXES)

# ---- ลำดับการลอง: Tor ก่อน แล้วค่อย gateway ----
class FakeResp:
    status_code, text, headers, encoding = 200, "<a href='http://someothervictimsite7u5odx5xbwtpnqk3edybgud5bmiagu75bnq.onion/x'>a real result title</a>", {"Content-Type": "text/html"}, "utf-8"
    def iter_content(self, chunk_size=8192): yield b"<html><body>hello world</body></html>"
    def close(self): pass

class Recorder:
    def __init__(self, fail_first=False, raise_invalid_schema=False):
        self.calls, self.fail_first, self.raise_invalid = [], fail_first, raise_invalid_schema
    def get(self, url, **kw):
        self.calls.append(url)
        if self.raise_invalid and len(self.calls) == 1:
            raise requests.exceptions.InvalidSchema("Missing dependencies for SOCKS support")
        if self.fail_first and len(self.calls) == 1:
            raise requests.exceptions.ConnectTimeout("tor down")
        return FakeResp()

# search: Tor เปิด -> ต้องยิง .onion ตรงก่อน
KAIZER = next(e["url"] for e in search.SEARCH_ENGINES if e["name"] == "Kaizer")
rec = Recorder()
search._tor_enabled = lambda: True
search._get_session = lambda use_tor=False: rec
search.fetch_search_results(KAIZER, "q")
check("search tries raw .onion first when Tor is up",
      rec.calls and rec.calls[0].endswith(".onion/search?q=q") and ".onion.ly" not in rec.calls[0], rec.calls)

# search: Tor ปิด -> ต้องข้ามไป gateway เลย
rec = Recorder(); search._tor_enabled = lambda: False
search.fetch_search_results(KAIZER, "q")
check("search skips Tor and goes straight to gateway when Tor is down",
      rec.calls and ".onion.ly" in rec.calls[0], rec.calls)

# search: Tor ล้ม -> ต้อง fallback ไป gateway ต่อ ไม่ใช่ยอมแพ้
rec = Recorder(fail_first=True); search._tor_enabled = lambda: True
out = search.fetch_search_results(KAIZER, "q")
check("search falls back to gateway after Tor fails", len(rec.calls) >= 2 and bool(out), rec.calls)

# search: PySocks หาย (InvalidSchema) -> ต้อง fallback ไม่ใช่ระเบิด
rec = Recorder(raise_invalid_schema=True); search._tor_enabled = lambda: True
out = search.fetch_search_results(KAIZER, "q")
check("search survives missing PySocks and uses gateway", len(rec.calls) >= 2 and bool(out), rec.calls)

# scrape: ลำดับเดียวกัน
rec = Recorder(); scrape._tor_enabled = lambda: True
scrape._get_session = lambda use_tor=False: rec
u, t = scrape.scrape_single({"link": "http://abcdefghijklmnop.onion/p", "title": "T"})
check("scrape tries raw .onion first when Tor is up",
      rec.calls and rec.calls[0] == "http://abcdefghijklmnop.onion/p", rec.calls)
check("scrape returns real content on the Tor hop", "hello world" in t, t)

rec = Recorder(); scrape._tor_enabled = lambda: False
scrape.scrape_single({"link": "http://abcdefghijklmnop.onion/p", "title": "T"})
check("scrape uses gateway when Tor is down", rec.calls and ".onion.ly" in rec.calls[0], rec.calls)

rec = Recorder(raise_invalid_schema=True); scrape._tor_enabled = lambda: True
u, t = scrape.scrape_single({"link": "http://abcdefghijklmnop.onion/p", "title": "T"})
check("scrape survives missing PySocks and uses gateway",
      len(rec.calls) >= 2 and "hello world" in t, (rec.calls, t))

rec = Recorder(); scrape._tor_enabled = lambda: False
scrape.scrape_single({"link": "https://example.com/p", "title": "T"})
check("scrape never routes clearnet URLs through a gateway rewrite",
      rec.calls == ["https://example.com/p"], rec.calls)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
