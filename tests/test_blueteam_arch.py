"""
tests/test_blueteam_arch.py — architecture fitness tests (A2) via ast.

Enforces the dependency rules of the v0.8 layering by statically parsing imports:
  1. No blueteam module imports app.py or sg_platform.py.
  2. No import cycles among blueteam.* modules.
  3. blueteam.platform.* is the base — it must not import intel/dac/posture.
  4. domain layer (files under a */domain.py or */domain/ path) must not import
     adapters/services/handlers, telegram, or sqlite3.
Also checks event contracts stay frozen dataclasses with a schema_version.

Standalone; offline; stdlib only.
"""

import ast
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
_BT = os.path.join(_ROOT, "blueteam")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'PASS' if cond else 'FAIL'} | {name}" + (f" -> {detail}" if detail and not cond else ""))


def _iter_py():
    for root, _dirs, files in os.walk(_BT):
        if "__pycache__" in root:
            continue
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def _module_name(path: str) -> str:
    rel = os.path.relpath(path, _ROOT)[:-3]
    return rel.replace(os.sep, ".")


def _imports(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out.add(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # relative import -> resolve to a blueteam.* module prefix
                base = _module_name(path).rsplit(".", node.level)[0]
                out.add(f"{base}.{node.module}" if node.module else base)
            elif node.module:
                out.add(node.module)
    return out


graph = {}
for p in _iter_py():
    graph[_module_name(p)] = _imports(p)

# 1) no import of app.py / sg_platform
offenders = {m: (i & {"app", "sg_platform"}) for m, i in graph.items() if i & {"app", "sg_platform"}}
check("no blueteam module imports app.py/sg_platform", not offenders, str(offenders))

# 2) no cycles among blueteam.* modules
bt_graph = {m: {d for d in deps if d.startswith("blueteam")} for m, deps in graph.items()}
WHITE, GREY, BLACK = 0, 1, 2
color = {m: WHITE for m in bt_graph}
cycle = []


def dfs(node, stack):
    color[node] = GREY
    for dep in bt_graph.get(node, ()):
        if dep not in color:
            continue
        if color[dep] == GREY:
            cycle.append(stack + [dep])
            return True
        if color[dep] == WHITE and dfs(dep, stack + [dep]):
            return True
    color[node] = BLACK
    return False


has_cycle = any(dfs(m, [m]) for m in bt_graph if color[m] == WHITE)
check("no import cycles among blueteam modules", not has_cycle, str(cycle[:1]))

# 3) platform must not import intel/dac/posture
plat_off = {m: (i & set(x for x in i if x.startswith(("blueteam.intel", "blueteam.dac", "blueteam.posture"))))
            for m, i in graph.items() if m.startswith("blueteam.platform")}
plat_bad = {m: v for m, v in plat_off.items() if v}
check("platform layer does not import intel/dac/posture", not plat_bad, str(plat_bad))

# 4) domain layer purity
FORBIDDEN_IN_DOMAIN = ("telegram", "sqlite3")
domain_bad = {}
for m, deps in graph.items():
    if ".domain" not in m and not m.endswith(".domain"):
        continue
    bad = [d for d in deps
           if d in FORBIDDEN_IN_DOMAIN
           or d.endswith((".adapters", ".service", ".handlers"))
           or ".adapters." in d]
    if bad:
        domain_bad[m] = bad
check("domain layer imports no adapters/telegram/sqlite", not domain_bad, str(domain_bad))

# 5) event contracts frozen + schema_version
try:
    from blueteam.platform import events as ev
    import dataclasses
    frozen_ok = True
    for name in ("FeedSynced", "IocMatched", "RuleMatched", "PostureSnapshotCreated",
                 "ReportGenerated"):
        cls = getattr(ev, name)
        params = getattr(cls, "__dataclass_params__", None)
        inst = cls()
        if not (params and params.frozen) or not hasattr(inst, "schema_version"):
            frozen_ok = False
    check("event contracts are frozen + carry schema_version", frozen_ok)
except Exception as exc:
    check("event contracts are frozen + carry schema_version", False, str(exc))

print(f"\n==== {len(PASS)} passed, {len(FAIL)} failed ====")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
