"""
cve_tracker.telegram.pagination — render paged search results + inline nav.

Search results are paged (rule §19). This module renders one page as an HTML
list (using the compact formatter) and builds the inline keyboard with prev/next
buttons whose callback data encodes the query + target page, so the handler can
re-run the search for the requested page. Callback data is bounded to Telegram's
64-byte limit by storing only the page and a short query token.
"""

from __future__ import annotations

from typing import Optional, Tuple

from ..alerts.formatter import format_compact
from ..search.service import SearchResult

CALLBACK_PREFIX = "cvepg"


def render_page(result: SearchResult, *, header: str = "") -> str:
    """Render the current page of a SearchResult as an HTML message body."""
    items = result.page_items()
    if not items:
        return (header + "\n\n" if header else "") + "ไม่พบผลลัพธ์ที่ตรงกับคำค้น"
    lines = []
    if header:
        lines.append(header)
    else:
        lines.append(f"🔎 ผลการค้นหา ({result.total_fetched} รายการ)")
    lines.append("")
    start = (result.page - 1) * result.page_size
    for idx, rec in enumerate(items, start=start + 1):
        lines.append(f"{idx}. {format_compact(rec)}")
    lines.append("")
    lines.append(f"หน้า {result.page}/{result.total_pages}")
    return "\n".join(lines)


def build_keyboard(result: SearchResult, query_token: str):
    """Build an InlineKeyboardMarkup with prev/next when applicable. Imported at
    call time so the module loads without telegram installed."""
    try:
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    except Exception:
        return None
    if result.total_pages <= 1:
        return None
    row = []
    if result.has_prev:
        row.append(InlineKeyboardButton(
            "◀️ ก่อนหน้า",
            callback_data=f"{CALLBACK_PREFIX}:{result.page - 1}:{query_token}"))
    if result.has_next:
        row.append(InlineKeyboardButton(
            "ถัดไป ▶️",
            callback_data=f"{CALLBACK_PREFIX}:{result.page + 1}:{query_token}"))
    if not row:
        return None
    return InlineKeyboardMarkup([row])


def parse_callback(data: str) -> Optional[Tuple[int, str]]:
    """Parse '<prefix>:<page>:<token>' → (page, token), or None."""
    if not data or not data.startswith(CALLBACK_PREFIX + ":"):
        return None
    parts = data.split(":", 2)
    if len(parts) != 3:
        return None
    try:
        page = int(parts[1])
    except ValueError:
        return None
    return page, parts[2]
