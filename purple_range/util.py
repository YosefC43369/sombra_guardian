"""purple_range/util.py — small dependency-free helpers."""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any, Optional

from .constants import TECHNIQUE_RE, PLAN_CODE_RE

_TECH = re.compile(TECHNIQUE_RE)
_CODE = re.compile(PLAN_CODE_RE)


def now() -> int:
    return int(time.time())


def gen_id(prefix: str = "pr") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def clean(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s[:max_len] if s else None


def normalize_technique(technique_id: Optional[str]) -> Optional[str]:
    """Return a canonical ATT&CK id (Txxxx[.xxx]) or None. Mirrors purpleteam's rule
    so plans and exercises agree on the same format."""
    if not technique_id:
        return None
    t = str(technique_id).strip().upper()
    return t if _TECH.match(t) else None


def valid_plan_code(code: Optional[str]) -> bool:
    return bool(code and _CODE.match(str(code).strip().lower()))


def json_dump(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None


def json_load(text: Optional[str]) -> Any:
    if not text:
        return {}
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return {}


def bounded_limit(limit: Optional[int], default: int, maximum: int) -> int:
    if limit is None:
        return default
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, maximum))
