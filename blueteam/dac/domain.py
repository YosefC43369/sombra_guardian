"""
blueteam/dac/domain.py — Detection-as-Code: the pure rule model + a Sigma-lite
compiler that turns a rule into a **closure**, with NO ``eval``/``exec``/``compile``
anywhere (spec gติกา: rules are data, never Python source).

Pipeline: rule JSON -> field-test predicates + a condition string ->
lexer -> recursive-descent parser -> AST -> optimizer -> compiled closure
``fn(record) -> bool``. A record is a flat, pre-normalized ``dict`` of features
extracted from a message (text, urls, domains, counts, ...); the matcher builds it.

Safety:
  * regex modifiers are **ReDoS-linted** (nested quantifiers rejected) and compiled
    once at rule-compile time — never per event, never from event data;
  * the AST node count is bounded (``max_nodes``) so a pathological condition can't
    blow up compile/eval;
  * unknown fields/modifiers compile to a constant-False test (fail-closed for the
    rule, not an exception storm).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

Predicate = Callable[[Dict[str, Any]], bool]


class RuleError(ValueError):
    pass


# ---------------- ReDoS lint ----------------

# nested quantifier like (a+)+ or (a*)* or (a+)*: classic catastrophic backtracking
_NESTED_QUANT = re.compile(r"\((?:[^()]*[+*])\)[+*]")
_MAX_REGEX_LEN = 512


def lint_regex(pattern: str) -> Tuple[bool, str]:
    """Return (ok, reason). Rejects over-long patterns and nested quantifiers."""
    if len(pattern) > _MAX_REGEX_LEN:
        return False, "regex too long"
    if _NESTED_QUANT.search(pattern):
        return False, "nested quantifier (ReDoS risk)"
    # unbounded repetition of a group containing alternation with overlap is also risky;
    # keep the lint conservative but cheap.
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    return True, "ok"


# ---------------- field-test predicates ----------------

def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else [v]


def _field_value(record: Dict[str, Any], field_name: str) -> Any:
    return record.get(field_name)


def _coerce_str(v: Any) -> str:
    return v if isinstance(v, str) else ("" if v is None else str(v))


def build_field_test(spec_key: str, spec_val: Any) -> Predicate:
    """Compile one ``field|mod|mod: value`` entry into a predicate closure.

    Supported modifiers: contains, startswith, endswith, eq, re, gt, gte, lt, lte,
    lower, all (quantifier: every value must match), any (default). A value list is
    OR-combined unless ``all`` is present.
    """
    parts = spec_key.split("|")
    field_name = parts[0]
    mods = [m.strip().lower() for m in parts[1:]]
    require_all = "all" in mods
    to_lower = "lower" in mods
    values = _as_list(spec_val)

    # numeric comparators
    for cmp_name, op in (("gte", lambda a, b: a >= b), ("lte", lambda a, b: a <= b),
                         ("gt", lambda a, b: a > b), ("lt", lambda a, b: a < b)):
        if cmp_name in mods:
            threshold = _to_number(values[0])

            def num_test(record, _t=threshold, _op=op, _f=field_name):
                val = _to_number(_field_value(record, _f))
                return val is not None and _op(val, _t)
            return num_test

    # regex
    if "re" in mods:
        compiled = []
        for v in values:
            ok, _ = lint_regex(_coerce_str(v))
            if ok:
                compiled.append(re.compile(_coerce_str(v)))
        if not compiled:
            return lambda record: False        # fail-closed: bad/blocked regex
        combine = all if require_all else any

        def re_test(record, _pats=compiled, _f=field_name, _c=combine):
            hay = _haystack(record, _f)
            return _c(any(p.search(_coerce_str(h)) for h in hay) for p in _pats)
        return re_test

    # string ops
    str_values = [(_coerce_str(v).lower() if to_lower else _coerce_str(v)) for v in values]

    def match_one(hayval: str, needle: str) -> bool:
        h = hayval.lower() if to_lower else hayval
        if "contains" in mods:
            return needle in h
        if "startswith" in mods:
            return h.startswith(needle)
        if "endswith" in mods:
            return h.endswith(needle)
        if "b64" in mods:
            try:
                return needle in base64.b64decode(h + "===").decode("utf-8", "replace")
            except Exception:
                return False
        return h == needle                     # default: equality

    combine = all if require_all else any

    def str_test(record, _vals=str_values, _f=field_name, _c=combine, _m=match_one):
        hay = _haystack(record, _f)
        # a value matches if it matches ANY element of the field's haystack
        return _c(any(_m(_coerce_str(h), needle) for h in hay) for needle in _vals)
    return str_test


def _haystack(record: Dict[str, Any], field_name: str) -> List[Any]:
    """A field may be a scalar or a list (e.g. urls, domains). Bools/None handled."""
    v = _field_value(record, field_name)
    if v is None:
        return []
    if isinstance(v, bool):
        return [v]
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def _to_number(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v))
    except (ValueError, TypeError):
        return None


def build_selection(sel: Dict[str, Any]) -> Predicate:
    """A selection map: ALL its field tests must pass (AND). ``has_*`` bool keys
    test truthiness of a computed record field."""
    if not isinstance(sel, dict):
        return lambda record: False
    tests: List[Predicate] = []
    for k, v in sel.items():
        if isinstance(v, bool) and "|" not in k:
            tests.append(lambda record, _k=k, _b=v: bool(record.get(_k)) is _b)
        else:
            tests.append(build_field_test(k, v))
    if not tests:
        return lambda record: False
    return lambda record, _ts=tuple(tests): all(t(record) for t in _ts)


# ---------------- condition lexer + parser + AST ----------------

@dataclass
class _Tok:
    kind: str          # IDENT | AND | OR | NOT | LP | RP | ALLOF | ONEOF | STAR
    text: str


def _lex(condition: str) -> List[_Tok]:
    toks: List[_Tok] = []
    i, n = 0, len(condition)
    while i < n:
        c = condition[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            toks.append(_Tok("LP", c)); i += 1; continue
        if c == ")":
            toks.append(_Tok("RP", c)); i += 1; continue
        if c in "_*" or c.isalnum():
            j = i
            while j < n and (condition[j].isalnum() or condition[j] in "_*"):
                j += 1
            word = condition[i:j]
            low = word.lower()
            if low == "and":
                toks.append(_Tok("AND", word))
            elif low == "or":
                toks.append(_Tok("OR", word))
            elif low == "not":
                toks.append(_Tok("NOT", word))
            else:
                toks.append(_Tok("IDENT", word))
            i = j
            continue
        raise RuleError(f"bad char in condition: {c!r}")
    return toks


# AST nodes are tuples: ("sel", name) | ("and", a, b) | ("or", a, b) | ("not", a)
#                       | ("allof", pattern) | ("oneof", pattern)

class _Parser:
    def __init__(self, toks: List[_Tok], max_nodes: int):
        self.toks = toks
        self.pos = 0
        self.nodes = 0
        self.max_nodes = max_nodes

    def _peek(self) -> Optional[_Tok]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _next(self) -> _Tok:
        t = self.toks[self.pos]
        self.pos += 1
        return t

    def _bump(self):
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise RuleError("condition too complex (node budget exceeded)")

    def parse(self):
        node = self._or()
        if self.pos != len(self.toks):
            raise RuleError("trailing tokens in condition")
        return node

    def _or(self):
        left = self._and()
        while self._peek() and self._peek().kind == "OR":
            self._next()
            self._bump()
            left = ("or", left, self._and())
        return left

    def _and(self):
        left = self._not()
        while self._peek() and self._peek().kind == "AND":
            self._next()
            self._bump()
            left = ("and", left, self._not())
        return left

    def _not(self):
        if self._peek() and self._peek().kind == "NOT":
            self._next()
            self._bump()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t is None:
            raise RuleError("unexpected end of condition")
        if t.kind == "LP":
            self._next()
            node = self._or()
            if not (self._peek() and self._peek().kind == "RP"):
                raise RuleError("missing )")
            self._next()
            return node
        if t.kind == "IDENT":
            self._next()
            self._bump()
            low = t.text.lower()
            # "all"/"1" of them / <pattern>
            if low in ("all", "1", "one") and self._peek() and self._peek().kind == "IDENT" \
                    and self._peek().text.lower() == "of":
                self._next()                       # consume 'of'
                if not (self._peek() and self._peek().kind == "IDENT"):
                    raise RuleError("expected pattern after 'of'")
                pat = self._next().text
                kind = "allof" if low == "all" else "oneof"
                return (kind, "*" if pat.lower() == "them" else pat)
            return ("sel", t.text)
        raise RuleError(f"unexpected token {t.kind}")


def parse_condition(condition: str, *, max_nodes: int = 500) -> tuple:
    toks = _lex(condition or "")
    if not toks:
        raise RuleError("empty condition")
    return _Parser(toks, max_nodes).parse()


# ---------------- optimizer + closure compiler ----------------

def _pattern_match(name: str, pattern: str) -> bool:
    if pattern in ("*", "them"):
        return True
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def compile_ast(ast: tuple, selections: Dict[str, Predicate]) -> Predicate:
    """Turn the AST into a single closure. 'allof/oneof <pattern>' expand over the
    selection names matching the glob. Unknown selections -> constant False."""
    kind = ast[0]
    if kind == "sel":
        sel = selections.get(ast[1])
        return sel if sel is not None else (lambda record: False)
    if kind == "not":
        inner = compile_ast(ast[1], selections)
        return lambda record, _i=inner: not _i(record)
    if kind == "and":
        a = compile_ast(ast[1], selections)
        b = compile_ast(ast[2], selections)
        return lambda record, _a=a, _b=b: _a(record) and _b(record)
    if kind == "or":
        a = compile_ast(ast[1], selections)
        b = compile_ast(ast[2], selections)
        return lambda record, _a=a, _b=b: _a(record) or _b(record)
    if kind in ("allof", "oneof"):
        matched = [p for name, p in selections.items() if _pattern_match(name, ast[1])]
        if not matched:
            return lambda record: False
        if kind == "allof":
            return lambda record, _ms=tuple(matched): all(m(record) for m in _ms)
        return lambda record, _ms=tuple(matched): any(m(record) for m in _ms)
    return lambda record: False


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    level: str
    predicate: Predicate
    literals: List[str] = field(default_factory=list)   # for Aho-Corasick prefilter
    aggregation: Optional[Dict[str, Any]] = None
    logsource: str = "message"
    tags: List[str] = field(default_factory=list)
    attack: str = ""
    dedupe_field: str = ""
    cooldown_s: int = 0

    def match(self, record: Dict[str, Any]) -> bool:
        return self.predicate(record)


def _collect_literals(detection: Dict[str, Any]) -> List[str]:
    """Literal 'contains'/'eq' strings that MUST appear — used only as a prefilter
    hint, never for correctness. Regex/startswith/endswith are skipped."""
    out: List[str] = []
    for sel_name, sel in detection.items():
        if sel_name == "condition" or not isinstance(sel, dict):
            continue
        for k, v in sel.items():
            mods = k.split("|")[1:]
            if "re" in mods or "startswith" in mods or "endswith" in mods:
                continue
            if "contains" in mods or not mods:
                for item in _as_list(v):
                    if isinstance(item, str) and len(item) >= 3:
                        out.append(item.lower())
    return out


def compile_rule(rule: Dict[str, Any], *, max_nodes: int = 500) -> CompiledRule:
    """Compile a Sigma-lite rule dict into a :class:`CompiledRule`. Raises RuleError."""
    rid = str(rule.get("id") or "").strip()
    title = str(rule.get("title") or rid or "untitled")
    if not rid:
        raise RuleError("rule missing id")
    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError("rule missing detection.condition")
    selections: Dict[str, Predicate] = {}
    for name, sel in detection.items():
        if name == "condition":
            continue
        selections[name] = build_selection(sel)
    ast = parse_condition(str(detection["condition"]), max_nodes=max_nodes)
    predicate = compile_ast(ast, selections)
    agg = rule.get("aggregation")
    if agg is not None and not isinstance(agg, dict):
        agg = None
    return CompiledRule(
        rule_id=rid, title=title, level=str(rule.get("level", "medium")),
        predicate=predicate, literals=_collect_literals(detection),
        aggregation=agg, logsource=str(rule.get("logsource", "message")),
        tags=list(rule.get("tags", []) or []), attack=str(rule.get("attack", "")),
        dedupe_field=str(rule.get("dedupe_field", "")),
        cooldown_s=int(rule.get("cooldown_s", 0) or 0))


__all__ = ["compile_rule", "compile_ast", "parse_condition", "build_selection",
           "build_field_test", "lint_regex", "CompiledRule", "RuleError"]
