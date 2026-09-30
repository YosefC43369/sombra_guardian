"""
cve_tracker.utils.text — string hygiene and Telegram-safe escaping.

Everything an external string touches on its way to storage or Telegram passes
through here, so the two escaping rules (HTML and MarkdownV2) live in exactly
one place and stay consistent with the bot's existing ``ParseMode`` usage.
"""

from __future__ import annotations

import json
import re
from typing import Any, List, Optional

_WS_RE = re.compile(r"[ \t ]+")
_MULTINL_RE = re.compile(r"\n{3,}")
_TAG_RE = re.compile(r"<[^>]+>")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_ws(text: Optional[str]) -> str:
    """Collapse runs of spaces/tabs, trim each line, cap blank-line runs, and
    strip control characters. Idempotent."""
    if not text:
        return ""
    text = _CTRL_RE.sub("", str(text))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _WS_RE.sub(" ", text)
    text = _MULTINL_RE.sub("\n\n", text)
    lines = [ln.strip() for ln in text.split("\n")]
    # Preserve paragraph structure but drop trailing whitespace-only noise.
    out: List[str] = []
    for ln in lines:
        out.append(ln)
    return "\n".join(out).strip()


def truncate(text: Optional[str], limit: int, *, suffix: str = "…") -> str:
    """Truncate to ``limit`` characters on a word boundary where possible,
    never splitting in the middle of a word when a space is nearby."""
    if not text:
        return ""
    s = str(text)
    if len(s) <= limit:
        return s
    if limit <= len(suffix):
        return s[:limit]
    cut = s[: limit - len(suffix)]
    # Prefer breaking at the last whitespace within the last 25% of the cut.
    window = max(0, int(len(cut) * 0.75))
    sp = cut.rfind(" ", window)
    if sp > 0:
        cut = cut[:sp]
    return cut.rstrip() + suffix


def strip_html(html: Optional[str]) -> str:
    """Remove tags and collapse whitespace. Deliberately dependency-free (no
    BeautifulSoup) because it runs on every reference title and short
    description — a regex strip is enough for those non-structured snippets."""
    if not html:
        return ""
    text = _TAG_RE.sub(" ", str(html))
    text = (text.replace("&amp;", "&").replace("&lt;", "<")
            .replace("&gt;", ">").replace("&quot;", '"')
            .replace("&#39;", "'").replace("&nbsp;", " "))
    return normalize_ws(text)


def escape_html(text: Optional[str]) -> str:
    """Escape for Telegram ``ParseMode.HTML`` (the mode news.py uses)."""
    if text is None:
        return ""
    return (str(text).replace("&", "&amp;")
            .replace("<", "&lt;").replace(">", "&gt;"))


# MarkdownV2 requires escaping this exact set (per Telegram Bot API docs).
_MDV2_SPECIAL = r"_*[]()~`>#+-=|{}.!"
_MDV2_RE = re.compile("([" + re.escape(_MDV2_SPECIAL) + "])")


def escape_markdown_v2(text: Optional[str]) -> str:
    """Escape for Telegram ``ParseMode.MARKDOWN_V2``. Provided for templates
    that opt into MarkdownV2; the default formatter uses HTML."""
    if text is None:
        return ""
    return _MDV2_RE.sub(r"\\\1", str(text))


def safe_json_loads(text: Any, default=None):
    """json.loads that never raises. Also tolerates a model wrapping JSON in
    ```json fences or trailing prose by extracting the first balanced object."""
    if text is None:
        return default
    if isinstance(text, (dict, list)):
        return text
    s = str(text).strip()
    if not s:
        return default
    # Strip code fences a model may add.
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        pass
    # Last resort: grab the first {...} or [...] balanced span.
    start = None
    for i, ch in enumerate(s):
        if ch in "{[":
            start = i
            break
    if start is None:
        return default
    opener = s[start]
    closer = "}" if opener == "{" else "]"
    depth = 0
    for j in range(start, len(s)):
        if s[j] == opener:
            depth += 1
        elif s[j] == closer:
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:j + 1])
                except (json.JSONDecodeError, ValueError):
                    return default
    return default


def coalesce(*values, default=""):
    """First non-empty (after strip for strings) value, else ``default``."""
    for v in values:
        if v is None:
            continue
        if isinstance(v, str):
            if v.strip():
                return v
        elif isinstance(v, (list, tuple, set, dict)):
            if len(v):
                return v
        else:
            return v
    return default


def dedupe_preserve_order(items) -> List:
    """Stable de-duplication. Hashable items compared by identity of value;
    unhashable ones fall back to an equality scan."""
    seen = set()
    out: List = []
    for it in items or []:
        try:
            if it in seen:
                continue
            seen.add(it)
        except TypeError:
            if it in out:
                continue
        out.append(it)
    return out


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: Optional[str]) -> str:
    """Lowercase ascii slug for vendor/product matching keys."""
    if not text:
        return ""
    s = _SLUG_RE.sub("-", str(text).lower()).strip("-")
    return s
