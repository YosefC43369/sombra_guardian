"""
behavioral_intelligence.telegram.keyboards — inline keyboard builders.

Builds the inline keyboards used by the behavioural commands: a section selector
(activity / heatmap / languages / topics / anomalies / …) and a report-format
selector (markdown / html / json / csv). ``python-telegram-bot`` is imported
defensively; the callback-data encoders/decoders are pure and testable without it.
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

CALLBACK_PREFIX = "bi"
_SECTIONS = ["activity", "heatmap", "timeline", "languages", "topics",
             "hashtags", "domains", "interactions", "anomalies", "changes",
             "baseline"]
_FORMATS = ["markdown", "html", "json", "csv"]


def encode(action: str, target: str, program: Optional[int]) -> str:
    """Encode callback data. Telegram limits callback_data to 64 bytes, so the
    target is truncated defensively."""
    prog = str(program) if program is not None else ""
    return f"{CALLBACK_PREFIX}|{action}|{target[:32]}|{prog}"


def decode(data: str) -> Tuple[str, str, Optional[int]]:
    """Decode callback data into (action, target, program_id)."""
    parts = (data or "").split("|")
    if len(parts) < 4 or parts[0] != CALLBACK_PREFIX:
        return ("", "", None)
    action, target, prog = parts[1], parts[2], parts[3]
    program = int(prog) if prog.isdigit() else None
    return (action, target, program)


def section_keyboard(target: str, program: Optional[int]):
    if not HAVE_PTB:
        return None
    rows: List[list] = []
    row: list = []
    for s in _SECTIONS:
        row.append(InlineKeyboardButton(s.title(), callback_data=encode(s, target,
                                                                        program)))
        if len(row) == 3:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton("📄 Full report",
                                      callback_data=encode("report", target, program))])
    return InlineKeyboardMarkup(rows)


def format_keyboard(target: str, program: Optional[int]):
    if not HAVE_PTB:
        return None
    row = [InlineKeyboardButton(f.upper(), callback_data=encode(f"fmt_{f}", target,
                                                                program))
           for f in _FORMATS]
    return InlineKeyboardMarkup([row])
