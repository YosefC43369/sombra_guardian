"""ทดสอบ search.py / scrape.py ตามเส้นทางที่ app.py ใช้จริง
app.py -> coordinator.handle_request -> _collect_darkweb_evidence
       -> search.get_search_results / scrape.scrape_multiple
"""
import sys, os, time, json, asyncio, threading, logging
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

os.environ.setdefault("TOR_GATEWAY_SUFFIXES", ".ly,.ps")
logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# โฮสต์ผลลัพธ์จำลอง — เจตนาไม่ใช้โฮสต์ของ search engine จริง เพราะตัวกรอง
# ข้ามเอนจิน (_is_engine_onion) จะตัดผลที่ชี้กลับหาเอนจินค้นหาทิ้ง
ONION_A = "http://dumpsitealpha0000000000000000000000000000000aaaaaad.onion/result/a"
ONION_B = "http://leakforumbeta11111111111111111111111111111bbbbbbd.onion/result/b"
_WRAP = "wrapmarketgamma2222222222222222222222222222222ccccccd"
_UPPER = "uppercasesitedelta33333333333333333333333333333dddddd"
_SEARCHWORD = "searchwordsitezeta5555555555555555555555555555ffffffd"

SEARCH_HTML = f"""<html><body>
  <a href="{ONION_A}">Leaked Credentials Dump 2024</a>
  <a href="{ONION_A}/">Leaked Credentials Dump 2024 duplicate</a>
  <a href="https://leakforumbeta11111111111111111111111111111bbbbbbd.onion.ly/result/b">Gateway rewritten link</a>
  <a href="/redirect?url=http%3A%2F%2F{_WRAP}.onion%2Fwrapped">Redirect wrapped result</a>
  <a href="http://{_UPPER.upper()}.onion/upper">UPPERCASE host result</a>
  <a href="http://shortsiteepsilon44444444444444444444444444eeeeeed.onion/x?q=x">ab</a>
  <a href="https://example.com/clearnet">Clearnet link should be ignored</a>
  <a href="http://{_SEARCHWORD}.onion/search?q=next">Result whose URL contains the word search</a>
</body></html>"""

PAGE_HTML = """<html><head><title>t</title><style>.x{color:red}</style></head>
<body><script>var a=1;</script><h1>Breach Report</h1><p>email: victim@example.com</p></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/search":
            self._send(200, SEARCH_HTML)
        elif path == "/page":
            self._send(200, PAGE_HTML)
        elif path == "/big":
            self._send(200, "<body>" + ("A" * 400_000) + "</body>")
        elif path == "/pdf":
            self._send(200, b"%PDF-1.4 binary", "application/pdf")
        elif path == "/slow":
            time.sleep(30)
            self._send(200, PAGE_HTML)
        elif path == "/empty":
            self._send(200, "<html><body></body></html>")
        else:
            self._send(404, "nope")

srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"

import search, scrape, nethealth

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))

# ---------- 1. pure helpers ----------
check("_onion_to_gateway", search._onion_to_gateway("http://abc.onion/p?q=1", ".ly")
      == "https://abc.onion.ly/p?q=1")
check("_gateway_to_onion roundtrip",
      search._gateway_to_onion(search._onion_to_gateway(ONION_A, ".ly")) == ONION_A,
      search._gateway_to_onion(search._onion_to_gateway(ONION_A, ".ly")))
check("_gateway_to_onion leaves clearnet alone",
      search._gateway_to_onion("https://example.com/a") == "https://example.com/a")
check("_onion_to_gateway keeps port",
      search._onion_to_gateway("http://abc.onion:8080/p", ".ly") == "https://abc.onion.ly:8080/p",
      search._onion_to_gateway("http://abc.onion:8080/p", ".ly"))

links = search._extract_links(SEARCH_HTML, f"{BASE}/search", limit=50)
found = [l["link"] for l in links]
check("extract: direct onion link", ONION_A in found, found)
check("extract: dedupes trailing slash", sum(1 for f in found if f.rstrip('/') == ONION_A) == 1, found)
check("extract: gateway link normalized back to .onion", ONION_B in found, found)
check("extract: redirect-wrapped link unwrapped",
      any(f.endswith("/wrapped") for f in found), found)
check("extract: uppercase host matched", any(f.lower().endswith("/upper") for f in found), found)
check("extract: clearnet ignored", not any("example.com" in f for f in found), found)
check("extract: short title dropped", not any(f.endswith("q=x") for f in found), found)
check("extract: keeps results whose URL contains 'search'",
      any("searchwordsite" in f for f in found), found)
check("extract: limit respected", len(search._extract_links(SEARCH_HTML, f"{BASE}/s", limit=2)) == 2)
check("extract: self-host links filtered",
      search._extract_links('<a href="http://127.0.0.1/x">selflink here</a>', f"{BASE}/search", 10) == [])

# ---------- 2. search over a real HTTP server ----------
search._tor_enabled = lambda: False
_real_gw = search._onion_to_gateway
search._onion_to_gateway = lambda url, suffix: f"{BASE}/search"

# เลือก engine ที่เป็น onion ผ่าน gateway (ไม่ใช่ clearnet_index อย่าง Ahmia web)
engine = next(e["url"] for e in search.SEARCH_ENGINES if not e.get("clearnet_index"))
res = search.fetch_search_results(engine, "test query")
check("fetch_search_results returns dicts", bool(res) and all(
    {"title", "link"} <= set(r) for r in res), res[:2])
check("fetch_search_results caps per engine",
      len(search.fetch_search_results(engine, "q", max_results=2)) == 2)

all_res = search.get_search_results("credential dump")
check("get_search_results dedupes across engines",
      len(all_res) == len({r["link"].rstrip('/').lower() for r in all_res}), len(all_res))
check("get_search_results shape matches coordinator expectation",
      all(isinstance(r.get("title"), str) and isinstance(r.get("link"), str) for r in all_res))
check("get_search_results empty query -> []", search.get_search_results("   ") == [])
check("get_search_results None -> []", search.get_search_results(None) == [])
check("get_search_results max_results cap",
      len(search.get_search_results("q", max_results=3)) == 3)
check("backward compat: positional max_workers still works",
      isinstance(search.get_search_results("q", 5), list))

# ---------- 3. search budget must be enforced ----------
search._onion_to_gateway = lambda url, suffix: f"{BASE}/slow"
t0 = time.monotonic()
slow = search.get_search_results("slow query", budget_seconds=6)
elapsed = time.monotonic() - t0
check("search honours total budget (no multi-minute hang)", elapsed < 12, f"{elapsed:.1f}s")
check("search returns [] instead of raising on timeout", slow == [], slow)

# engine that 404s
search._onion_to_gateway = lambda url, suffix: f"{BASE}/404"
check("search survives all-engines-fail", search.get_search_results("x") == [])
search._onion_to_gateway = _real_gw

# circuit breaker เก็บสถานะข้ามการเรียก — เฟส /slow ข้างบนทำให้เส้นทางเข้า cooldown
# ตามที่ออกแบบไว้ เฟสถัดไปจึงต้องเริ่มจากสถานะสะอาด
check("circuit breaker tripped by the slow-gateway phase (as designed)",
      bool(nethealth.open_routes()), nethealth.open_routes())
nethealth.reset()
search.clear_search_cache()

# ---------- 4. scrape against a real HTTP server ----------
url, text = scrape.scrape_single({"link": f"{BASE}/page", "title": "Breach"})
check("scrape_single returns (url, text)", url == f"{BASE}/page")
check("scrape_single strips script/style", "var a=1" not in text and "color:red" not in text, text[:120])
check("scrape_single keeps body text", "Breach Report" in text and "victim@example.com" in text, text[:120])

u, t = scrape.scrape_single({"link": f"{BASE}/pdf", "title": "Doc"})
check("scrape_single marks disallowed content-type", scrape.CONTENT_UNAVAILABLE_MARKER in t, t)
u, t = scrape.scrape_single({"link": f"{BASE}/404", "title": "Missing"})
check("scrape_single marks 404", scrape.CONTENT_UNAVAILABLE_MARKER in t, t)
u, t = scrape.scrape_single({"link": "ftp://x/y", "title": "Bad scheme"})
check("scrape_single rejects non-http scheme", scrape.CONTENT_UNAVAILABLE_MARKER in t, t)
u, t = scrape.scrape_single("just-a-string-url")
check("scrape_single accepts a bare string", u == "just-a-string-url")
check("scrape_single empty dict -> ('', 'Untitled')", scrape.scrape_single({}) == ("", "Untitled"))

u, t = scrape.scrape_single({"link": f"{BASE}/big", "title": "Big"})
check("scrape_single caps extracted chars",
      len(t) <= scrape.MAX_EXTRACTED_TEXT_CHARS + 64, len(t))

# ---------- 5. scrape_multiple, the exact coordinator call shape ----------
search_results = [
    {"title": "A", "link": f"{BASE}/page"},
    {"title": "A dup", "link": f"{BASE}/page/"},
    {"title": "B", "link": f"{BASE}/empty"},
    {"title": "C", "link": f"{BASE}/404"},
    {"title": "bad", "link": ""},
]
scraped = scrape.scrape_multiple(search_results, 5)   # <- positional, as coordinator.py calls it
check("scrape_multiple returns dict keyed by url", isinstance(scraped, dict))
check("scrape_multiple dedupes trailing slash", len(scraped) == 3, list(scraped))
check("scrape_multiple truncates to MAX_RETURN_CHARS",
      all(len(v) <= scrape.MAX_RETURN_CHARS for v in scraped.values()))
check("scrape_multiple skips empty link", not any(k == "" for k in scraped))
check("scrape_multiple non-list -> {}", scrape.scrape_multiple("notalist") == {})
check("scrape_multiple empty list -> {}", scrape.scrape_multiple([]) == {})
check("scrape_multiple max_urls cap", len(scrape.scrape_multiple(search_results, 5, max_urls=2)) == 2)

t0 = time.monotonic()
slow_scraped = scrape.scrape_multiple([{"title": "s", "link": f"{BASE}/slow"}], 5, budget_seconds=5)
elapsed = time.monotonic() - t0
check("scrape honours total budget", elapsed < 11, f"{elapsed:.1f}s")

# ---------- 6. async wrappers (how app.py handlers would call them) ----------
async def _async_checks():
    loop_blocked = []

    async def heartbeat():
        last = time.monotonic()
        while True:
            await asyncio.sleep(0.05)
            gap = time.monotonic() - last
            last = time.monotonic()
            if gap > 1.0:
                loop_blocked.append(gap)

    hb = asyncio.create_task(heartbeat())
    r = await search.get_search_results_async("async query", budget_seconds=10)
    s = await scrape.scrape_multiple_async(search_results, 5)
    one = await scrape.scrape_single_async({"link": f"{BASE}/page", "title": "One"})
    hb.cancel()
    return r, s, one, loop_blocked

nethealth.reset(); search.clear_search_cache()
search._onion_to_gateway = lambda url, suffix: f"{BASE}/search"
r, s, one, blocked = asyncio.run(_async_checks())
search._onion_to_gateway = _real_gw
check("get_search_results_async works", isinstance(r, list) and bool(r))
check("scrape_multiple_async works", isinstance(s, dict) and bool(s))
check("scrape_single_async works", one[0] == f"{BASE}/page" and "Breach Report" in one[1])
check("event loop never blocked (app.py stays responsive)", not blocked, blocked)

# ---------- 7. Telegram formatters (feed gemini.split_telegram_message) ----------
txt = search.format_search_results(r)
check("format_search_results is plain str", isinstance(txt, str) and "1." in txt)
check("format_search_results handles empty", "ไม่พบผลการค้นหา" in search.format_search_results([]))
stxt = scrape.format_scrape_results(s)
check("format_scrape_results is plain str", isinstance(stxt, str) and BASE in stxt)
check("format_scrape_results handles empty", "ไม่สำเร็จ" in scrape.format_scrape_results({}))

# ---------- 8. replay coordinator._collect_darkweb_evidence prompt assembly ----------
src_lines, ev_lines = [], []
for item in r[:20]:
    if item.get("link"):
        src_lines.append(f"- {item.get('title','Untitled')}: {item['link']}")
for u_, t_ in s.items():
    ev_lines.append(f"Source: {u_}\n{t_}")
prompt = f"[DARK WEB SEARCH RESULTS]\n{chr(10).join(src_lines)}\n\n[SCRAPED EVIDENCE]\n{chr(10).join(ev_lines)}"
check("coordinator prompt assembly works unchanged", "[SCRAPED EVIDENCE]" in prompt and src_lines and ev_lines)

# ---------- 9. bad .env values must not crash import ----------
os.environ["SEARCH_MAX_WORKERS"] = "ไม่ใช่ตัวเลข"
os.environ["SCRAPE_MAX_RETURN_CHARS"] = "abc"
import importlib
try:
    importlib.reload(search); importlib.reload(scrape)
    check("bad .env ints fall back to defaults", search.SEARCH_MAX_WORKERS == 8 and scrape.MAX_RETURN_CHARS == 2000)
except Exception as e:
    check("bad .env ints fall back to defaults", False, repr(e))
finally:
    os.environ.pop("SEARCH_MAX_WORKERS"); os.environ.pop("SCRAPE_MAX_RETURN_CHARS")
    importlib.reload(search); importlib.reload(scrape)

srv.shutdown()
print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
