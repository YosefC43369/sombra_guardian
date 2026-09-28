"""
news_intelligence.telegram.keyboards — inline keyboards for the /news surface.

Builds the interactive navigation the spec asks for (Overview, Timeline, Actors,
Malware, CVEs, Campaigns, Sources, Evidence, Related Reports) as callback buttons.
``python-telegram-bot`` is imported defensively; without it the builders return the
raw button spec (list of (label, callback_data) rows) so they stay unit-testable.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    HAVE_PTB = True
except Exception:  # pragma: no cover
    InlineKeyboardButton = None
    InlineKeyboardMarkup = None
    HAVE_PTB = False


NAV_TABS = ["overview", "timeline", "actors", "malware", "cves", "campaigns",
            "sources", "evidence", "related"]


def _rows_to_markup(rows: List[List[Tuple[str, str]]]):
    if not HAVE_PTB:
        return rows
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(label, callback_data=data) for label, data in row]
        for row in rows])


def nav_keyboard(subject_type: str, subject: str, *, active: str = "overview"):
    """Nine-tab navigation keyboard for a profile view."""
    def label(tab):
        return ("• " + tab.title() + " •") if tab == active else tab.title()
    rows: List[List[Tuple[str, str]]] = []
    row: List[Tuple[str, str]] = []
    for tab in NAV_TABS:
        row.append((label(tab), f"news:{subject_type}:{tab}:{subject}"))
        if len(row) == 3:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return _rows_to_markup(rows)


def brief_keyboard():
    rows = [[("Daily", "news:brief:daily:"), ("Weekly", "news:brief:weekly:"),
             ("Executive", "news:brief:exec:")]]
    return _rows_to_markup(rows)


def format_keyboard(subject_type: str, subject: str):
    rows = [[("Markdown", f"news:fmt:md:{subject_type}:{subject}"),
             ("Graph", f"news:fmt:graph:{subject_type}:{subject}")]]
    return _rows_to_markup(rows)


__all__ = ["nav_keyboard", "brief_keyboard", "format_keyboard", "NAV_TABS",
           "HAVE_PTB"]
