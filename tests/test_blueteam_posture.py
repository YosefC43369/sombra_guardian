"""
tests/test_blueteam_posture.py — Posture scoring (formula, UNKNOWN exclusion,
monotonicity, gating, determinism), explain/whatif, self-contained report +
escaping, and the service over the real SQLite adapter (rollups, trend, portfolio,
report generation + tamper-evident verify). Offline, deterministic.
"""

import json
import os
import random
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import migrations
from blueteam.posture.domain import (Control, Assessment, compute_score, explain,
                                     whatif, letter_grade, load_catalog, Grade)
from blueteam.posture.report import (Branding, ReportModel, render_html, render_csv,
                                     render_json, report_sha256, escape_csv_field)
from blueteam.posture.adapters import SqlitePostureRepository
from blueteam.posture.service import PostureService
from blueteam.posture.commands import PostureCommandService
from blueteam.platform.tenancy import Role

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


# ---------------- catalog loads ----------------
cat_path = os.path.join(_ROOT, "reference_data", "blueteam", "posture", "controls.json")
with open(cat_path, encoding="utf-8") as fh:
    catalog = load_catalog(json.load(fh)["controls"])
check("catalog loads", len(catalog) >= 15)

# ---------------- formula correctness (hand-computed) ----------------
c = {"a": Control("a", "A", "cat", weight=2.0),
     "b": Control("b", "B", "cat", weight=1.0),
     "u": Control("u", "U", "cat", weight=3.0)}
a = {"a": Assessment("a", "pass"),      # s=1, w=2 -> 2
     "b": Assessment("b", "partial"),   # s=0.5,w=1 -> 0.5
     "u": Assessment("u", "unknown")}   # excluded
res = compute_score(c, a)
# num = 2*1 + 1*0.5 = 2.5 ; den = 2 + 1 = 3 ; score = 83.33
check("score formula = Σ(w·s·c)/Σ(w·c)", abs(res.score - (2.5 / 3 * 100)) < 1e-6, f"{res.score}")
check("UNKNOWN excluded from divisor", res.applicable == 3 and res.covered == 2)
check("coverage = covered/applicable", abs(res.coverage - 2/3) < 1e-6)

# adding an UNKNOWN control must not change the score
c2 = dict(c); c2["v"] = Control("v", "V", "cat", weight=5.0)
res2 = compute_score(c2, a)   # v unknown
check("adding UNKNOWN control leaves score unchanged", abs(res2.score - res.score) < 1e-6)

# determinism / order independence
import collections
shuffled = collections.OrderedDict(sorted(c.items(), reverse=True))
check("score order-independent", compute_score(shuffled, a).score == res.score)

# ---------------- monotonicity (fixed-seed property test) ----------------
rnd = random.Random(2024)
levels = ["fail", "weak", "partial", "strong", "pass"]
mono_ok = True
for _ in range(300):
    cat = {f"c{i}": Control(f"c{i}", f"C{i}", "x", weight=rnd.choice([1, 2, 3, 5]),
                            critical=rnd.random() < 0.2) for i in range(8)}
    asmt = {cid: Assessment(cid, rnd.choice(levels + ["unknown"])) for cid in cat}
    base = compute_score(cat, asmt).score
    # improve one random control by one level
    cid = rnd.choice(list(cat))
    cur = asmt[cid].status
    if cur in levels and levels.index(cur) < len(levels) - 1:
        asmt2 = dict(asmt); asmt2[cid] = Assessment(cid, levels[levels.index(cur) + 1])
        if compute_score(cat, asmt2).score < base - 1e-9:
            mono_ok = False
            break
check("score is monotonic under improvement", mono_ok)

# ---------------- gating ----------------
gc = {"crit": Control("crit", "Critical", "x", weight=1.0, critical=True),
      "ok": Control("ok", "OK", "x", weight=9.0)}
ga = {"crit": Assessment("crit", "fail"), "ok": Assessment("ok", "pass")}
gres = compute_score(gc, ga)
# raw score high (9/10=90 -> A) but critical fail gates to <= C
check("critical fail gates grade", gres.grade in (Grade.C, Grade.D, Grade.F) and "crit" in gres.gates)
check("gating does not change numeric score", gres.score == gres.raw_score)

# letter grades
check("letter grades", letter_grade(95) == Grade.A and letter_grade(65) == Grade.D and letter_grade(10) == Grade.F)

# ---------------- explain / whatif ----------------
e = explain(c, a)
check("explain lists top actions", any(x["control"] == "b" for x in e["top_actions"]))
w = whatif(c, a, {"b": "pass"})
check("whatif improves score", w["delta"] > 0)

# ---------------- report: self-contained + escaping ----------------
model = ReportModel(title="Test <script>", subject_label="grp", generated_at="2026-01-01",
                    score=83.3, grade="B", coverage=0.66,
                    contributions=[{"name": "Ctrl <b>", "status": "pass", "weight": 2, "sub_score": 1.0, "critical": True}],
                    gates=[], top_actions=[{"name": "Fix X", "potential_gain": 5, "remediation": "do <it>", "critical": False}],
                    trend=[70.0, 75.0, 83.3], categories={"Detection": 80.0}, profile="internal")
h = render_html(model, Branding(brand_name="Acme"))
check("report has no <script>", "<script" not in h.lower())
check("report escapes XSS", "<script>" not in h and "&lt;script&gt;" in h)
check("report has CSP meta", "Content-Security-Policy" in h)
check("report self-draws svg", "<svg" in h and "polyline" in h)
check("report has no external http refs", "http://" not in h and "https://" not in h)
check("csv injection guarded", escape_csv_field("=1+2").startswith("'"))
check("report sha256 stable", report_sha256(h) == report_sha256(render_html(model, Branding(brand_name="Acme"))))

# ---------------- service over sqlite ----------------
db = tempfile.mkstemp(suffix=".db")[1]
migrations.MigrationRunner(db).migrate_up()
repo = SqlitePostureRepository(db)

# a fake signals provider
STATE = {"link_guard": "pass", "scam_guard": "partial", "join_guard": "fail",
         "detection_rules": "pass", "integrity_ledger": "pass"}


class Signals:
    def assess(self, chat_id):
        return dict(STATE)


clock = [100000.0]
sealed = []
svc = PostureService(repo, catalog=catalog, signals=Signals(), clock=lambda: clock[0],
                     sealer=lambda k, p: sealed.append((k, p)))

snap = svc.record_snapshot(-100)
check("record_snapshot stores + scores", "snapshot_id" in snap and 0 <= snap["score"] <= 100)
check("join_guard fail gates grade", "join_guard" in snap["gates"])

# rollup mean across the same hour
svc.record_snapshot(-100)
rl = repo.rollups(-100, "score", 0)
check("rollup keeps running mean per hour", len(rl) == 1 and rl[0]["count"] == 2)

# trend across hours
clock[0] += 3600 * 3
svc.record_snapshot(-100)
tr = svc.trend(-100)
check("trend returns multiple points", len(tr) >= 2)

# portfolio
STATE2 = dict(STATE); STATE2["join_guard"] = "pass"
port = svc.portfolio([-100, -200])
check("portfolio aggregates groups", port["count"] == 2 and "avg_score" in port)

# report generation + tamper-evident verify
gen = svc.generate_report(-100, fmt="html", profile="client")
check("report generated + sealed", gen["sha256"] and any(k == "posture_report" for k, _ in sealed))
ver_ok = svc.verify_report(gen["report_id"], gen["content"])
check("verify passes on untampered", ver_ok["ok"])
ver_bad = svc.verify_report(gen["report_id"], gen["content"] + "x")
check("verify detects tampering", not ver_bad["ok"])

# client profile pseudonymizes subject
check("client profile pseudonymizes", "#" in gen["content"] or "กลุ่ม" in gen["content"])

# branding round-trip
svc.set_branding(-100, brand_name="ACME Security")
check("branding persists", svc.get_branding(-100).brand_name == "ACME Security")

# command surface
cmd = PostureCommandService(svc)
check("cmd status needs admin", "ADMIN" in cmd.handle(-100, ["status"], role=Role.VIEWER))
check("cmd status renders for admin", "เกรด" in cmd.handle(-100, ["status"], role=Role.ADMIN))
check("cmd report needs owner", "OWNER" in cmd.handle(-100, ["report"], role=Role.ADMIN))
check("cmd explain renders", "แก้ก่อน" in cmd.handle(-100, ["explain"], role=Role.ADMIN))

repo.close()
os.remove(db)

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
