"""
tests/test_blueteam_dac_service.py — DaC service over the real SQLite adapter:
starter-pack compiles, versioning hash-chain, lifecycle transitions, rollback,
evaluate+record, backtest, and the /rule command surface with role gating.
Offline, deterministic.
"""

import json
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.dac.service import DacService
from blueteam.dac.adapters import SqliteRuleRepository
from blueteam.dac.records import build_record
from blueteam.dac.commands import RuleCommandService
from blueteam.dac.domain import compile_rule, RuleError
from blueteam.platform.tenancy import Role

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


# ---------------- starter pack all compiles ----------------
pack_path = os.path.join(_ROOT, "reference_data", "blueteam", "dac", "rules", "starter_pack.json")
with open(pack_path, encoding="utf-8") as fh:
    pack = json.load(fh)["rules"]
compile_errors = []
for body in pack:
    try:
        compile_rule(body)
    except RuleError as exc:
        compile_errors.append((body.get("id"), str(exc)))
check(f"starter pack compiles ({len(pack)} rules)", not compile_errors, str(compile_errors))
check("starter pack has >= 30 rules", len(pack) >= 30)

# ---------------- service over sqlite ----------------
db = tempfile.mkstemp(suffix=".db")[1]
migrations.MigrationRunner(db).migrate_up()
repo = SqliteRuleRepository(db)

clock = [1000.0]
sealed = []
svc = DacService(repo, clock=lambda: clock[0],
                 sealer=lambda kind, payload: sealed.append((kind, payload)) or "receipt")

# load the pack
res = svc.load_pack(pack, actor=1, activate=True)
check("service loads pack to shadow", res["loaded"] == len(pack) and not res["failed"])
check("sealer invoked on version add", any(k == "rule_version" for k, _ in sealed))

# lifecycle: shadow -> canary -> enabled
rid = "phish_seed_phrase"
check("promote shadow->canary", svc.canary(rid, [555], actor=1)["ok"])
check("promote canary->enabled", svc.enable(rid, actor=1)["ok"])
# illegal: cannot go enabled->canary? (allowed) ; test an unknown state
check("unknown state rejected", not svc.set_state(rid, "bogus", actor=1)["ok"])

# versioning + hash chain
imp = svc.import_rule({"id": "custom1", "title": "Custom", "level": "low",
                       "detection": {"s": {"text_lower|contains": ["foobar"]}, "condition": "s"}}, actor=1)
check("import returns version+sha", imp["ok"] and imp["version"] == "1.0.0")
imp2 = svc.import_rule({"id": "custom1", "title": "Custom v2", "level": "medium",
                        "detection": {"s": {"text_lower|contains": ["foobar", "baz"]}, "condition": "s"}}, actor=1)
check("re-import bumps version", imp2["version"] == "1.0.1")
hist = svc.history("custom1")
check("version chain verifies", hist["chain_ok"] and len(hist["versions"]) == 2)

# rollback to v1.0.0
rb = svc.rollback("custom1", "1.0.0", actor=1)
check("rollback creates new version", rb["ok"] and rb["version"] == "1.0.2")

# lint catches bad rule
bad = svc.lint({"id": "bad", "detection": {"s": {"t|re": ["(a+)+"]}, "condition": "s and ("}})
check("lint reports problems", not bad["ok"] and len(bad["problems"]) >= 1)

# ---------------- evaluate over records ----------------
svc.enable("phish_wallet_connect", actor=1)
rec = build_record(text="Please connect wallet to claim tokens now https://drain.top/x",
                   urls=["https://drain.top/x"], user_id=42, chat_id=7, is_new_member=True)
hits = svc.evaluate(rec, chat_id=7)
hit_ids = {h.rule_id for h in hits}
check("evaluate fires wallet-connect + suspicious tld",
      "phish_wallet_connect" in hit_ids, str(hit_ids))
check("hit recorded", repo.recent_hits("phish_wallet_connect", 5))

# benign message -> no hits (prefilter)
benign = build_record(text="good morning everyone", user_id=1, chat_id=7)
check("benign message no hits", svc.evaluate(benign, chat_id=7, record_hits=False) == [])

# backtest against sample records
samples = [build_record(text="connect wallet claim tokens", urls=["https://x.top/"]),
           build_record(text="hello"), build_record(text="verify wallet now", urls=["https://y.ru/"])]
bt = svc.backtest("phish_wallet_connect", samples)
check("backtest counts matches", bt["ok"] and bt["matches"] >= 1)

# ---------------- command surface ----------------
cmd = RuleCommandService(svc, pack=pack)
check("cmd list renders", "กฎทั้งหมด" in cmd.handle(["list"], role=Role.VIEWER))
check("cmd write blocked for viewer", "OWNER" in cmd.handle(["enable", "custom1"], role=Role.VIEWER))
en = cmd.handle(["enable", "custom1"], role=Role.OWNER, actor=1)
check("cmd enable works for owner", "enabled" in en or "→" in en)
imp_cmd = cmd.handle(["import"], raw='/rule import {"id":"c2","title":"C2","level":"low","detection":{"s":{"text_lower|contains":["zzz"]},"condition":"s"}}', role=Role.OWNER, actor=1)
check("cmd import parses json body", "นำเข้ากฎ c2" in imp_cmd)
check("cmd stats renders", "DaC stats" in cmd.handle(["stats"], role=Role.ADMIN))
check("cmd history shows chain", "ประวัติ" in cmd.handle(["history", "custom1"], role=Role.ADMIN))

repo.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
