"""
workflows/conditions.py — condition evaluation with ReDoS protection.

A workflow condition is ``(field, operator, value)`` evaluated against an
event payload. ``field`` supports dotted paths ("member.risk_level") so a
nested payload can be reached without special-casing.

Supported operators:
    equals, not_equals, contains, not_contains,
    gt, gte, lt, lte, in, not_in, exists, not_exists, regex

Regex safety
------------
Python's ``re`` has no execution timeout, so a hostile or accidental
catastrophic pattern (e.g. ``(a+)+$``) could burn CPU. Two defences:
  1. the pattern and the input are both length-capped, and
  2. a lightweight heuristic rejects patterns with nested unbounded
     quantifiers before they are ever compiled.
Workflow definitions are admin-authored, so this is defence in depth rather
than an adversarial boundary, and the caps are logged when they trip.
"""

import re
import logging
from typing import Any

logger = logging.getLogger("modbot.workflows.conditions")

MAX_REGEX_PATTERN_LEN = 200
MAX_REGEX_INPUT_LEN = 10_000

# Nested quantifier like (a+)+ , (a*)* , (a+)* — the classic ReDoS shape.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")

_compiled_cache: dict = {}


class ConditionError(ValueError):
    """Raised for a malformed or unsafe condition definition."""


def _resolve_field(payload: Any, field: str) -> Any:
    """Walk a dotted path through dicts. Missing keys yield the sentinel
    ``_MISSING`` so ``exists`` can distinguish absent from a None value."""
    current = payload
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


class _Missing:
    def __repr__(self):
        return "<missing>"


_MISSING = _Missing()


def _as_number(value: Any):
    if isinstance(value, bool):
        raise ConditionError("cannot compare a boolean numerically")
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            return float(value) if ("." in value or "e" in value.lower()) else int(value)
        except ValueError:
            raise ConditionError(f"value {value!r} is not numeric")
    raise ConditionError(f"value {value!r} is not numeric")


def safe_regex_search(pattern: str, text: str) -> bool:
    """Bounded regex search. Returns False (never raises) on an unsafe or
    invalid pattern, logging why, so a bad condition can't crash a workflow."""
    if not isinstance(pattern, str):
        return False
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        logger.warning("CONDITION regex | pattern too long (%d chars), rejected",
                       len(pattern))
        return False
    if _NESTED_QUANTIFIER_RE.search(pattern):
        logger.warning("CONDITION regex | pattern has nested quantifiers "
                       "(ReDoS risk), rejected: %r", pattern)
        return False
    compiled = _compiled_cache.get(pattern)
    if compiled is None:
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            logger.warning("CONDITION regex | invalid pattern %r: %s", pattern, exc)
            return False
        _compiled_cache[pattern] = compiled
    text = str(text)[:MAX_REGEX_INPUT_LEN]
    return compiled.search(text) is not None


def evaluate_condition(condition: dict, payload: dict) -> bool:
    """Evaluate one ``{field, operator, value}`` dict against a payload."""
    field = condition.get("field")
    operator = condition.get("operator")
    expected = condition.get("value")
    if not field or not operator:
        raise ConditionError(f"condition needs 'field' and 'operator': {condition!r}")

    actual = _resolve_field(payload, field)

    if operator == "exists":
        return actual is not _MISSING
    if operator == "not_exists":
        return actual is _MISSING

    # Every remaining operator needs the field to be present.
    if actual is _MISSING:
        return operator in ("not_equals", "not_contains", "not_in")

    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        try:
            return expected in actual
        except TypeError:
            return False
    if operator == "not_contains":
        try:
            return expected not in actual
        except TypeError:
            return True
    if operator == "in":
        try:
            return actual in expected
        except TypeError:
            return False
    if operator == "not_in":
        try:
            return actual not in expected
        except TypeError:
            return True
    if operator in ("gt", "gte", "lt", "lte"):
        a = _as_number(actual)
        b = _as_number(expected)
        if operator == "gt":
            return a > b
        if operator == "gte":
            return a >= b
        if operator == "lt":
            return a < b
        return a <= b
    if operator == "regex":
        return safe_regex_search(expected, actual)

    raise ConditionError(f"unknown operator {operator!r}")


def evaluate_all(conditions, payload: dict) -> bool:
    """AND semantics: every condition must pass. No conditions -> always
    matches. A malformed condition is treated as non-matching (and logged)
    rather than raising into the engine's hot path."""
    if not conditions:
        return True
    for condition in conditions:
        try:
            if not evaluate_condition(condition, payload):
                return False
        except ConditionError as exc:
            logger.warning("CONDITION | skipping workflow, bad condition: %s", exc)
            return False
    return True
