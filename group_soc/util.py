"""
group_soc/util.py — small, dependency-free helpers shared across the subsystem.

Privacy note (rule §17): the SOC minimises PII. Actor/target identifiers are
stored as **salted hashes** (`actor_hash`), never as raw user ids inside content
fields, and message text is reduced to a length + content hash unless an operator
explicitly opts out. `defang` neutralises URLs so a stored/echoed indicator can
never be an accidental live link.
"""

from __future__ import annotations

import os
import re
import json
import time
import uuid
import hashlib
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Time / ids
# --------------------------------------------------------------------------- #
def now() -> int:
    """Current epoch seconds (int). Single choke point so tests can reason about it."""
    return int(time.time())


def gen_id(prefix: str = "soc") -> str:
    """A short, collision-resistant id with a human-readable prefix."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def new_correlation_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- #
# Hashing / redaction (privacy by default)
# --------------------------------------------------------------------------- #
def _salt() -> str:
    # Read at call time so an operator can rotate it without a restart-time import.
    # An empty salt still yields a stable hash; it is only weaker against a
    # dictionary attack on the (already non-sensitive) id space.
    return os.getenv("SOC_HASH_SALT", "") or ""


def hash_id(value: Any, *, salt: Optional[str] = None) -> Optional[str]:
    """Stable, salted sha256 of an identifier (e.g. a user_id), truncated to 32
    hex chars. Returns None for a None input so 'no actor' stays 'no actor'."""
    if value is None:
        return None
    s = _salt() if salt is None else salt
    digest = hashlib.sha256(f"{s}|{value}".encode("utf-8", "replace")).hexdigest()
    return digest[:32]


def content_hash(text: Optional[str]) -> Optional[str]:
    """Hash of message *content* for near-duplicate/campaign detection. Normalised
    (lowercased, whitespace-collapsed) so trivial variations still collide."""
    if not text:
        return None
    norm = re.sub(r"\s+", " ", text.strip().lower())
    if not norm:
        return None
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:32]


_URL_RE = re.compile(r"\bhttps?://\S+", re.IGNORECASE)


def defang(text: Optional[str]) -> str:
    """Neutralise URLs/schemes so stored or echoed indicators are never clickable."""
    if not text:
        return ""
    out = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace("[.]", "[.]")  # idempotent
    out = re.sub(r"\.(?=[a-zA-Z]{2,})", "[.]", out)
    return out


def redact_text(text: Optional[str], *, keep_len: bool = True) -> str:
    """Reduce free text to a non-identifying marker. Used when
    ``SOC_REDACT_MESSAGE_TEXT`` is on (the default)."""
    if not text:
        return ""
    if keep_len:
        return f"<redacted:{len(text)}>"
    return "<redacted>"


def clean_str(value: Optional[str], max_len: int) -> Optional[str]:
    """Trim + bound a string; None stays None. Never raises."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    return s[:max_len]


# --------------------------------------------------------------------------- #
# JSON helpers (never raise into a caller)
# --------------------------------------------------------------------------- #
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
    """Clamp a caller-supplied query limit into [1, maximum]."""
    if limit is None:
        return default
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, maximum))
