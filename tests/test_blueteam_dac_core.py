"""
tests/test_blueteam_dac_core.py — Detection-as-Code compiler + matcher.
Verifies: NO eval/exec/compile in the engine, field-test/condition semantics,
ReDoS lint, Aho-Corasick prefilter vs brute force, aggregation/cooldown/breaker.
Offline, deterministic.
"""

import os
import random
import re
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from blueteam.dac.domain import compile_rule, parse_condition, lint_regex, RuleError
from blueteam.dac.matcher import (RuleEngine, AhoCorasick, ENABLED, SHADOW, CANARY, DISABLED)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


# ---------------- no builtin eval/exec/compile in the engine ----------------
# match a bare builtin call, not an attribute call like re.compile(...)
_BUILTIN_CALL = re.compile(r"(?<![.\w])(eval|exec|compile)\s*\(")
srcs = {}
for mod in ("domain.py", "matcher.py"):
    with open(os.path.join(_ROOT, "blueteam", "dac", mod), encoding="utf-8") as fh:
        srcs[mod] = fh.read()
offenders = {m: _BUILTIN_CALL.findall(s) for m, s in srcs.items() if _BUILTIN_CALL.search(s)}
check("no builtin eval/exec/compile in dac engine", not offenders, str(offenders))

# ---------------- field-test + condition semantics ----------------
rule = compile_rule({
    "id": "test_phish", "title": "Phishy", "level": "high",
    "detection": {
        "sel_url": {"has_url": True},
        "sel_kw": {"text|contains|all": ["verify", "account"]},
        "sel_bad": {"domain|endswith": [".ru", ".top"]},
        "condition": "sel_url and (sel_kw or sel_bad)"},
})
rec_hit = {"has_url": True, "text": "please verify your account now", "domain": ["ok.com"],
           "text_lower": "please verify your account now"}
rec_miss = {"has_url": True, "text": "hello there", "domain": ["ok.com"], "text_lower": "hello there"}
rec_bad_domain = {"has_url": True, "text": "hi", "domain": ["evil.ru"], "text_lower": "hi"}
check("rule matches keyword+url", rule.match(rec_hit))
check("rule misses benign", not rule.match(rec_miss))
check("rule matches bad tld via or", rule.match(rec_bad_domain))

# 'all' modifier requires every keyword
rec_partial = {"has_url": True, "text": "verify please", "domain": ["ok.com"], "text_lower": "verify please"}
check("all modifier needs every value", not rule.match(rec_partial))

# numeric comparator
nrule = compile_rule({"id": "flood", "title": "Flood", "level": "medium",
                      "detection": {"s": {"mention_count|gte": 5}, "condition": "s"}})
check("numeric gte matches", nrule.match({"mention_count": 7}))
check("numeric gte rejects", not nrule.match({"mention_count": 2}))

# regex modifier + ReDoS lint
rrule = compile_rule({"id": "re1", "title": "re", "level": "low",
                      "detection": {"s": {"text|re": [r"\bfree\s+money\b"]}, "condition": "s"}})
check("regex modifier matches", rrule.match({"text": "get free  money", "text_lower": "get free  money"}))
ok, _ = lint_regex(r"(a+)+")
check("redos lint rejects nested quantifier", not ok)
ok2, _ = lint_regex(r"\bfoo\b")
check("redos lint allows safe regex", ok2)

# regex with bad pattern -> fail-closed (rule compiles, never matches on that sel)
safe = compile_rule({"id": "re2", "title": "re2", "level": "low",
                     "detection": {"s": {"text|re": ["(x+)+"]}, "condition": "s"}})
check("bad regex fails closed", not safe.match({"text": "xxxx", "text_lower": "xxxx"}))

# ---------------- condition parser ----------------
check("parse handles allof them", parse_condition("all of them")[0] == "allof")
check("parse handles oneof pattern", parse_condition("1 of sel_*")[0] == "oneof")
try:
    parse_condition("a and (b or c", max_nodes=50)
    check("parse rejects unbalanced parens", False)
except RuleError:
    check("parse rejects unbalanced parens", True)
try:
    parse_condition(" and ".join(f"s{i}" for i in range(400)), max_nodes=50)
    check("parse enforces node budget", False)
except RuleError:
    check("parse enforces node budget", True)

# allof/oneof expansion in engine
multi = compile_rule({"id": "multi", "title": "m", "level": "low",
                      "detection": {"sel_a": {"text|contains": ["aaa"]},
                                    "sel_b": {"text|contains": ["bbb"]},
                                    "condition": "all of sel_*"}})
check("allof expands over glob (both needed)",
      multi.match({"text": "aaa bbb", "text_lower": "aaa bbb"}) and
      not multi.match({"text": "aaa", "text_lower": "aaa"}))

# ---------------- Aho-Corasick vs brute force ----------------
rnd = random.Random(4242)
alpha = "abcde"
pats = list({"".join(rnd.choice(alpha) for _ in range(rnd.randint(2, 4))) for _ in range(40)})
ac = AhoCorasick(pats)
mismatches = 0
for _ in range(2000):
    text = "".join(rnd.choice(alpha) for _ in range(rnd.randint(5, 30)))
    got = ac.search(text)
    want = {p for p in pats if p in text}
    if got != want:
        mismatches += 1
check("aho-corasick matches brute force", mismatches == 0, f"mismatches={mismatches}")

# ---------------- RuleEngine: modes ----------------
clock = [1000.0]
eng = RuleEngine(clock=lambda: clock[0])
r_en = compile_rule({"id": "en", "title": "en", "level": "high",
                     "detection": {"s": {"text|contains": ["danger"]}, "condition": "s"}})
r_ca = compile_rule({"id": "ca", "title": "ca", "level": "high",
                     "detection": {"s": {"text|contains": ["danger"]}, "condition": "s"}})
eng.set_rules([r_en, r_ca], {"en": ENABLED, "ca": CANARY}, canary={"ca": (555,)})
rec = {"text": "danger here", "text_lower": "danger here"}
hits_default = {h.rule_id for h in eng.evaluate(rec, chat_id=999)}
check("enabled fires everywhere, canary only in its chat", hits_default == {"en"})
hits_canary = {h.rule_id for h in eng.evaluate(rec, chat_id=555)}
check("canary fires in its chat", hits_canary == {"en", "ca"})

# shadow mode still evaluates (for backtest) but marked shadow
eng.set_rules([r_en], {"en": SHADOW})
sh = eng.evaluate(rec, chat_id=1)
check("shadow rule evaluates and is marked", len(sh) == 1 and sh[0].mode == SHADOW)

# prefilter: rule with literal not present is skipped (still correct = no hit)
eng.set_rules([r_en], {"en": ENABLED})
check("prefilter skips non-present literal", eng.evaluate({"text": "all clear", "text_lower": "all clear"}) == [])

# ---------------- aggregation: count threshold ----------------
clock[0] = 2000.0
agg_rule = compile_rule({"id": "burst", "title": "burst", "level": "medium",
                         "detection": {"s": {"text|contains": ["join"]}, "condition": "s"},
                         "aggregation": {"type": "count", "gte": 3, "window_s": 60, "group_by": "src"}})
eng.set_rules([agg_rule], {"burst": ENABLED})
r = {"text": "join", "text_lower": "join", "src": "A"}
fires = [bool(eng.evaluate(r, chat_id=1)) for _ in range(4)]
check("aggregation fires only after threshold", fires == [False, False, True, True])
# distinct grouping resets by key
r2 = {"text": "join", "text_lower": "join", "src": "B"}
check("aggregation separate per group key", not eng.evaluate(r2, chat_id=1))

# ---------------- cooldown / dedupe ----------------
clock[0] = 3000.0
cd_rule = compile_rule({"id": "cd", "title": "cd", "level": "low",
                        "detection": {"s": {"text|contains": ["spam"]}, "condition": "s"},
                        "cooldown_s": 100, "dedupe_field": "src"})
eng.set_rules([cd_rule], {"cd": ENABLED})
first = bool(eng.evaluate({"text": "spam", "text_lower": "spam", "src": "X"}, chat_id=1))
second = bool(eng.evaluate({"text": "spam", "text_lower": "spam", "src": "X"}, chat_id=1))
check("cooldown dedupes repeat within window", first and not second)
clock[0] = 3200.0
third = bool(eng.evaluate({"text": "spam", "text_lower": "spam", "src": "X"}, chat_id=1))
check("cooldown expires after window", third)

# ---------------- circuit breaker on slow rule ----------------
clock[0] = 4000.0
slow_eng = RuleEngine(clock=lambda: clock[0], per_rule_budget_us=0, slow_strikes_to_open=3,
                      breaker_cooldown_s=100)
slow_rule = compile_rule({"id": "slow", "title": "slow", "level": "low",
                          "detection": {"s": {"text|contains": ["x"]}, "condition": "s"}})
slow_eng.set_rules([slow_rule], {"slow": ENABLED})
for _ in range(4):
    slow_eng.evaluate({"text": "x", "text_lower": "x"}, chat_id=1)
check("slow rule breaker opens", "slow" in slow_eng.breaker_states())

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
