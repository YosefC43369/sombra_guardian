"""ตรวจว่าตัวแกะผลลัพธ์ clearnet ไม่คืน footer/nav ของ engine อีก
เลียนหน้า HTML จริงของ Startpage / Marginalia / DuckDuckGo / Bing
"""
import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT); os.chdir(_ROOT)
import search

PASS, FAIL = [], []
def check(n, c, d=""):
    (PASS if c else FAIL).append(n); print(f"{'PASS' if c else 'FAIL'} | {n}" + (f" -> {d}" if d and not c else ""))

# ---------- 1. suffix host matching ----------
check("suffix: app.startpage.com ตรงกับ startpage.com",
      search._host_matches("app.startpage.com", {"startpage.com"}))
check("suffix: git.marginalia.nu ตรงกับ marginalia.nu",
      search._host_matches("git.marginalia.nu", {"marginalia.nu"}))
check("suffix: www ถูกตัดก่อนเทียบ",
      search._host_matches("www.bing.com", {"bing.com"}))
check("suffix: โฮสต์คนละโดเมนไม่ตรง",
      not search._host_matches("thanathorn.example.co.th", {"startpage.com"}))
check("suffix: ไม่ตรงแบบ substring หลอกๆ (notstartpage.com)",
      not search._host_matches("notstartpage.com", {"startpage.com"}))

# ---------- 2. ลิงก์โซเชียลของตัว engine เอง ----------
check("social: twitter.com/startpage = ของ engine",
      search._is_engine_social("https://twitter.com/startpage"))
check("social: facebook.com/startpagesearch = ของ engine",
      search._is_engine_social("https://www.facebook.com/startpagesearch/"))
check("social: reddit.com/r/StartpageSearch = ของ engine",
      search._is_engine_social("https://www.reddit.com/r/StartpageSearch/"))
check("social: บัญชีจริงของเป้าหมายไม่โดนตัด",
      not search._is_engine_social("https://www.facebook.com/thanathorn.pya"))
check("social: twitter บัญชีจริงไม่โดนตัด",
      not search._is_engine_social("https://twitter.com/thana_p"))

# ---------- 3. Startpage: เดิมคืน footer ล้วน ----------
STARTPAGE = """<html><body>
<header><a href="https://app.startpage.com?source=home-hamburger">Mobile Browser</a></header>
<div class="w-gl__result"><a class="result-link" href="https://www.acme.co.th/team/thanathorn">
   ทำเนียบทีมงาน acme</a></div>
<div class="w-gl__result"><a class="result-link" href="https://news.example.co.th/2024/seminar">
   งานสัมมนา</a></div>
<footer>
  <a href="https://support.startpage.com/hc/en-us">Support</a>
  <a href="https://support.startpage.com/hc/en-us/articles/4521527855636-Impressum">Imprint</a>
  <a href="https://twitter.com/startpage">twitter</a>
  <a href="https://www.facebook.com/startpagesearch/">facebook</a>
  <a href="https://www.instagram.com/startpage/">instagram</a>
  <a href="https://www.reddit.com/r/StartpageSearch/">reddit</a>
</footer></body></html>"""
eng = search._CLEARNET_ENGINE_BY_URL["https://www.startpage.com/sp/search?query={query}"]
links = search._extract_clearnet_links(
    STARTPAGE, "https://www.startpage.com/sp/search?query=x",
    20, selectors=eng["result_selectors"], own_domains=eng["own_domains"])
got = [l["link"] for l in links]
check("startpage: ได้เฉพาะผลจริง 2 อัน", len(links) == 2, got)
check("startpage: ตัด app.startpage.com (subdomain)", not any("startpage.com" in u for u in got), got)
check("startpage: ตัด twitter/facebook/reddit ของ engine",
      not any(h in u for u in got for h in ("twitter","facebook","instagram","reddit")), got)
check("startpage: เก็บ acme.co.th ไว้", any("acme.co.th" in u for u in got), got)

# ---------- 4. Marginalia: เดิมคืนลิงก์โปรเจกต์ตัวเอง ----------
MARGINALIA = """<html><body>
<nav><a href="https://about.marginalia-search.com/">About</a>
     <a href="https://git.marginalia.nu/">git</a>
     <a href="https://old-search.marginalia.nu/">old search</a></nav>
<main>
  <section class="card search-result"><h2><a href="https://blog.example.com/thanathorn">
     บล็อกของธนาธรณ์</a></h2></section>
  <section class="card search-result"><h2><a href="https://forum.example.org/u/thana">
     โปรไฟล์ฟอรัม</a></h2></section>
</main>
<footer><a href="https://chat.marginalia.nu">project discord</a>
        <a href="https://github.com/MarginaliaSearch/MarginaliaSearch/issues">issues</a></footer>
</body></html>"""
eng = search._CLEARNET_ENGINE_BY_URL["https://search.marginalia.nu/search?query={query}"]
links = search._extract_clearnet_links(
    MARGINALIA, "https://search.marginalia.nu/search?query=x",
    20, selectors=eng["result_selectors"], own_domains=eng["own_domains"])
got = [l["link"] for l in links]
check("marginalia: ได้เฉพาะผลจริง 2 อัน", len(links) == 2, got)
check("marginalia: ตัด marginalia.nu + marginalia-search.com (ทุก subdomain)",
      not any("marginalia" in u for u in got), got)
check("marginalia: เก็บ blog/forum จริงไว้",
      any("blog.example.com" in u for u in got) and any("forum.example.org" in u for u in got), got)

# ---------- 5. DuckDuckGo: uddg redirect ยังแกะได้ ----------
DDG = """<html><body>
<div class="result"><a class="result__a" href="/l/?uddg=https%3A%2F%2Fwww.acme.co.th%2Fp%2Fthana">
   ผลจริง</a></div>
<div class="nav"><a href="https://duckduckgo.com/about">About DDG</a></div>
</body></html>"""
eng = search._CLEARNET_ENGINE_BY_URL["https://html.duckduckgo.com/html/?q={query}"]
links = search._extract_clearnet_links(
    DDG, "https://html.duckduckgo.com/html/?q=x",
    20, selectors=eng["result_selectors"], own_domains=eng["own_domains"])
got = [l["link"] for l in links]
check("ddg: แกะ uddg เป็น URL จริง", got == ["https://www.acme.co.th/p/thana"], got)
check("ddg: ตัดลิงก์ about ของ engine", not any("duckduckgo" in u for u in got), got)

# ---------- 6. Bing: u= redirect + result selector ----------
BING = """<html><body><ol id="b_results">
<li class="b_algo"><h2><a href="https://acme.co.th/staff/thana">พนักงาน</a></h2></li>
<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?u=a1aHR0cHM6Ly9uZXdzLmV4YW1wbGUuY28udGgv">
   ข่าว</a></h2></li>
</ol>
<div id="b_footer"><a href="https://go.microsoft.com/privacy">Privacy</a></div></body></html>"""
eng = search._CLEARNET_ENGINE_BY_URL["https://www.bing.com/search?q={query}&setlang=th"]
links = search._extract_clearnet_links(
    BING, "https://www.bing.com/search?q=x",
    20, selectors=eng["result_selectors"], own_domains=eng["own_domains"])
got = [l["link"] for l in links]
check("bing: เก็บผลจริง acme.co.th", any("acme.co.th" in u for u in got), got)
check("bing: ตัด go.microsoft.com (footer, subdomain)", not any("microsoft" in u for u in got), got)

# ---------- 7. fallback: selector ไม่แมตช์ -> ใช้ทั้งหน้า แต่ยังกรองขยะ ----------
WEIRD = """<html><body>
<a href="https://real.example.co.th/thana">ผลจริง</a>
<a href="https://startpage.com/about">engine chrome</a>
<a href="https://twitter.com/startpage">engine social</a>
</body></html>"""
links = search._extract_clearnet_links(
    WEIRD, "https://www.startpage.com/sp/search?query=x",
    20, selectors=["div.no-such-selector a"], own_domains=["startpage.com"])
got = [l["link"] for l in links]
check("fallback: ยังกรอง engine chrome ได้แม้ selector ไม่แมตช์",
      got == ["https://real.example.co.th/thana"], got)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL: print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
