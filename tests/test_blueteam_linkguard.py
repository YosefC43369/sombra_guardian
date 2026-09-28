"""
tests/test_blueteam_linkguard.py — Link Guard: offline scoring (brand impersonation,
text_link mismatch, risky TLD/shortener/free-hosting/keywords/obfuscation/dangerous
scheme), reputation (allow/deny/feed), feed parsers, and the SSRF guard + safe probe
(private-IP rejection, redirect-to-internal, DNS-rebinding, page inspection).

Standalone; fully offline (injected resolver/opener); does not import telegram.
"""

import asyncio
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.store import BlueTeamStore
from blueteam.linkguard import LinkGuard
from blueteam.models import Verdict
from blueteam import netprobe as np
from blueteam.reputation import parse_urlhaus, parse_openphish, hosts_from_urls

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


db = tempfile.mkstemp(suffix=".db")[1]
migrations.apply_startup_migrations(db)
store = BlueTeamStore(db)
lg = LinkGuard(store)


def worst(text, ents=None, chat_id=1):
    r = lg.analyze_message(chat_id, text, ents)
    w = lg.worst(r)
    return w[1] if w else None


# ---- scoring ----
check("benign link is SAFE", worst("see https://github.com/x/y").verdict <= Verdict.LOW)
a = worst("login https://paypa1.com/verify")
check("brand typosquat flagged", any("brand" in s.id for s in a.signals) and a.verdict >= Verdict.SUSPICIOUS)
ents = [{"type": "text_link", "offset": 0, "length": 12, "url": "http://free-nitro.tk/login"}]
a = worst("telegram.org", ents)
check("text_link display/href mismatch is high", any(s.id == "text_link_mismatch" for s in a.signals) and a.verdict >= Verdict.HIGH)
a = worst("claim airdrop http://wallet-verify.zip/claim")
check("risky TLD + keywords => suspicious", a.verdict >= Verdict.SUSPICIOUS)
check("benign keyworded path stays safe", worst("https://myshop.co.th/account/login").verdict <= Verdict.LOW)
check("dangerous scheme flagged", any(s.id == "dangerous_scheme" for s in worst("javascript:alert(1)").signals))
check("shortener flagged", any(s.id == "url_shortener" for s in worst("bit.ly/abc").signals))
check("obfuscated IP host flagged", any(s.id == "ip_obfuscated" for s in worst("http://2130706433/login").signals))
check("every signal explains a fact", all(s.fact for s in a.signals))
check("assessment has a limitation line", bool(a.limitation))

# ---- reputation ----
store.add_list_entry(1, "allow", "domain", "paypa1.com", actor=1)
al = worst("https://paypa1.com/verify")
check("allow-list short-circuits to SAFE", al.score == 0 and al.meta.get("allow_listed"))
store.add_list_entry(1, "deny", "domain", "evil.example", actor=1)
check("deny-list forces CRITICAL", worst("https://evil.example/").verdict == Verdict.CRITICAL)
store.feed_add_many("urlhaus", "host", ["malware-drop.com"])
check("blocklist feed hit flagged", any(s.id == "blocklist_feed" for s in worst("http://malware-drop.com/x").signals))
check("reputation is chat-scoped", not worst("https://evil.example/", chat_id=2).verdict == Verdict.CRITICAL)

# ---- feed parsers ----
uh = '#c\n"1","2024","http://bad.tld/x","online","malware"\n"2","d","http://evil.tld/y"'
check("urlhaus parser", set(parse_urlhaus(uh)) == {"http://bad.tld/x", "http://evil.tld/y"})
check("openphish parser", len(parse_openphish("#h\nhttp://a/1\nhttp://b/2")) == 2)
check("hosts_from_urls extracts registrable", "bad.tld" in hosts_from_urls(["http://bad.tld/x"]))

# ---- SSRF guard ----
cases = {"8.8.8.8": True, "1.1.1.1": True, "127.0.0.1": False, "10.0.0.1": False,
         "192.168.0.1": False, "172.16.0.1": False, "169.254.169.254": False,
         "::1": False, "100.64.0.1": False, "::ffff:10.0.0.1": False, "0.0.0.0": False}
check("is_safe_ip classifies all ranges",
      all(np.is_safe_ip(ip)[0] == exp for ip, exp in cases.items()),
      str({ip: np.is_safe_ip(ip) for ip in cases}))
check("screen_host rejects mixed public/private",
      not np.screen_host("x", lambda h: ["8.8.8.8", "10.0.0.1"])[0])
check("screen_host accepts all-public", np.screen_host("x", lambda h: ["8.8.8.8"])[0])
check("screen_host rejects unresolvable", not np.screen_host("x", lambda h: [])[0])


async def _probe_tests():
    # redirect to internal host is blocked
    async def op_redir(url, pins, timeout):
        return (302, {}, b"", "http://internal/") if "start" in url else (200, {}, b"", "")
    resolver = lambda h: {"start.com": ["8.8.8.8"], "internal": ["169.254.169.254"]}.get(h, [])
    r = await np.SafeProbe(resolver=resolver, opener=op_redir).probe("http://start.com/")
    check("redirect to internal host blocked", r.blocked and "SSRF" in r.blocked_reason)

    # DNS rebinding: opener only ever receives the pinned safe IP
    seq = {"n": 0}
    def rebind(h):
        seq["n"] += 1
        return ["8.8.8.8"] if seq["n"] == 1 else ["127.0.0.1"]
    got = {"pins": None}
    async def op_pin(url, pins, timeout):
        got["pins"] = pins
        return (302, {}, b"", "http://same.com/2")
    r = await np.SafeProbe(resolver=rebind, opener=op_pin).probe("http://same.com/")
    check("rebinding blocked at next hop", r.blocked and "SSRF" in r.blocked_reason)
    check("opener only ever got pinned safe IP", got["pins"] == ["8.8.8.8"])

    # page inspection: password + cross-domain form
    async def op_page(url, pins, timeout):
        return (200, {}, b'<html><title>Login</title><form action="http://evil.ru/x"><input type="password"></form></html>', "")
    r = await np.SafeProbe(resolver=lambda h: ["8.8.8.8"], opener=op_page).probe("http://site.com/")
    ids = {s.id for s in r.signals}
    check("probe detects password form + cross-domain form",
          "password_form" in ids and "cross_domain_form" in ids and r.title == "Login")

    # no opener => graceful unavailable, never raises
    r = await np.SafeProbe(resolver=lambda h: ["8.8.8.8"], opener=None).probe("http://x.com/")
    check("no opener degrades gracefully", not r.reachable and not r.blocked)

run(_probe_tests())

store.close()
os.remove(db)
print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
