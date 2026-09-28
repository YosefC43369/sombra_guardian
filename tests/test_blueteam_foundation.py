"""
tests/test_blueteam_foundation.py — Blue Team Suite foundations:
models (explainable + monotonic scoring), textkit (skeleton/SimHash/distances),
urlkit (extraction/refang/defang/IP/eTLD+1/text_link mismatch), rules
(checksum + ReDoS lint), store (chat-scoped CRUD, retention), migration 0003.

Standalone script; prints PASS/FAIL + a "==== N passed, M failed ====" line.
Runs fully offline; does not import telegram.
"""

import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.models import Verdict, Signal, Assessment, PolicyAction, combine_score
from blueteam import textkit as tk
from blueteam import urlkit as uk
from blueteam.rules import get_registry
from blueteam.store import BlueTeamStore

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


# ---- models: explainable + monotonic ----
a = Assessment("linkguard", subject="k")
base = a.score
a.add(Signal("brand", 40, "impersonation", "paypa1≈paypal", "T1566.002"))
check("score rises when signal added", a.score >= base)
a.add(Signal("tld", 15, "lexical", ".zip"))
check("deterministic sum", a.score == 55)
check("verdict band from score", a.verdict == Verdict.SUSPICIOUS)
prev = a.score
a.add(Signal("more", 5, "lexical", "x"))
check("monotonic: adding never lowers", a.score >= prev)
check("score capped at 100", Assessment("m", signals=[Signal("a", 80, "c"), Signal("b", 80, "c")]).score == 100)
check("attack tags surfaced", a.attack_tags == ["T1566.002"])
check("top_reasons ordered by weight", [r.id for r in a.top_reasons(2)] == ["brand", "tld"])
check("negative weight clamped (no score-gaming)", combine_score([Signal("x", -50, "c")]) == 0)
check("PolicyAction parse DELETE+RESTRICT", PolicyAction.parse("DELETE+RESTRICT") == PolicyAction.DELETE_RESTRICT)
check("assessment carries a limitation line", bool(a.limitation))

# ---- textkit ----
check("skeleton folds leetspeak", tk.skeleton("p4y-p4l") == "paypal")
check("skeleton folds cyrillic homoglyph", tk.skeleton("раypal") == "paypal")
check("skeleton folds math-bold (NFKC)", tk.skeleton("\U0001d5fd\U0001d5ee\U0001d606\U0001d5fd\U0001d5ee\U0001d5f9") == "paypal")
h_near = tk.simhash("ลงทุนคริปโตกำไร 300% ต่อวัน ทักด่วน")
h_near2 = tk.simhash("ลงทุน คริปโต กำไร 300% ต่อวัน ทัก ด่วน!!")
h_far = tk.simhash("สวัสดีครับ วันนี้อากาศดีมาก")
check("simhash clusters near-dupes (thai, no spaces)", tk.hamming(h_near, h_near2) < 12, str(tk.hamming(h_near, h_near2)))
check("simhash separates unrelated text", tk.hamming(h_near, h_far) > tk.hamming(h_near, h_near2))
check("damerau-levenshtein substitution", tk.damerau_levenshtein("paypal", "paypa1") == 1)
check("damerau-levenshtein transposition", tk.damerau_levenshtein("paypal", "payapl") == 1)
check("damerau early-exit on max_distance", tk.damerau_levenshtein("abc", "abcdef", max_distance=2) == 3)
check("jaro-winkler high for near names", tk.jaro_winkler("telegram", "telegran") > 0.9)
check("jaro-winkler low for different names", tk.jaro_winkler("admin", "hacker") < 0.6)

# ---- urlkit ----
urls = uk.extract_urls("visit https://paypal.com/login and hxxp://evil[.]tk/claim")
hosts = {u.host for u in urls}
check("extracts + refangs obfuscated urls", "paypal.com" in hosts and "evil.tk" in hosts, str(hosts))
check("defang neutralises output", all("hxxp" in u.defanged() and "[.]" in u.defanged() for u in urls))
ents = [{"type": "text_link", "offset": 0, "length": 11, "url": "http://evil-phish.ru/paypal"}]
tl = uk.extract_urls("paypal.com", ents)
check("text_link display/href mismatch flagged", bool(tl) and tl[0].href_mismatch)
check("decode decimal IP", uk.decode_ip_host("2130706433") == "127.0.0.1")
check("decode hex IP", uk.decode_ip_host("0x7f000001") == "127.0.0.1")
check("decode octal dotted IP", uk.decode_ip_host("0177.0.0.1") == "127.0.0.1")
ip_u = uk.extract_urls("http://2130706433/login")
check("obfuscated IP host detected", ip_u and ip_u[0].host == "127.0.0.1" and "ip_obfuscated" in ip_u[0].obfuscations)
dz = uk.extract_urls("data:text/html,x and javascript:alert(1)")
check("dangerous schemes flagged (never executed)", any(u.is_dangerous_scheme for u in dz))
check("eTLD+1 handles multi-label suffix", uk.etld1("www.bank.co.th") == "bank.co.th")
check("eTLD+1 default two-label", uk.etld1("a.b.example.com") == "example.com")
check("punycode host classified", uk.extract_urls("https://xn--80ak6aa92e.com")[0].host_type == "punycode")

# ---- rules ----
reg = get_registry()
st = reg.status()
check("rule packs loaded", st["brands"] >= 20 and st["scam_th"] >= 10 and st["scam_en"] >= 10)
check("rule pack checksums verified", st["checksums_ok"] is True)
check("tld risk weighting", reg.tld_weight(".zip")[0] > 0 and reg.tld_weight(".zip")[1] == "high")
check("shortener + free-hosting sets", "bit.ly" in reg.shorteners and "pages.dev" in reg.free_hosting)

# ---- store + migration 0003 ----
fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
migrations.apply_startup_migrations(path)
s = BlueTeamStore(path)
s.set_policy(1, "linkguard", enabled=True, mode="DELETE", threshold=60, actor=9)
pol = s.get_policy(1, "linkguard")
check("policy persisted", pol["enabled"] == 1 and pol["mode"] == "DELETE" and pol["threshold"] == 60)
s.add_list_entry(1, "allow", "domain", "example.com", actor=9)
check("allow list add + check", s.in_list(1, "allow", "domain", "example.com"))
check("lists are chat-scoped", not s.in_list(2, "allow", "domain", "example.com"))
s.upsert_url_cache("uk1", "http://x/", 80, "HIGH", [{"id": "z", "weight": 80}], chat_id=1)
check("url cache roundtrip", s.get_url_cache("uk1")["score"] == 80)
s.log_event(1, "linkguard", user_id=7, subject="uk1", score=80, verdict="HIGH", action="DELETE")
check("event stats", s.stats(1, 3600)["total"] == 1)
sec = s.get_or_create_secret()
check("per-db secret stable", sec == s.get_or_create_secret() and len(sec) == 64)
s.save_perm_snapshot(1, {"can_send_messages": True}, None)
check("perm snapshot survives (restart-safe)", bool(BlueTeamStore(path).get_perm_snapshot(1)))
removed = s.cleanup(90)
check("retention cleanup runs", isinstance(removed, dict))
s.close()
os.remove(path)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
