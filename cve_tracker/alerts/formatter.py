"""
cve_tracker.alerts.formatter — assemble and split the Telegram message.

Assembles the section templates into the final Thai alert, honouring Telegram's
4096-char limit by splitting on section boundaries (never mid-URL, never
mid-entity — rule §37) using the project's existing
``gemini.split_telegram_message``. Two message shapes: a full 'new CVE' alert
and a compact 'CVE updated' alert.

The formatter is the ONE place that decides layout, so the AI summarizer and the
deterministic fallback flow through the same renderer — the reader can't tell
which produced a given field except by the footer.
"""

from __future__ import annotations

from typing import List, Optional

from ..constants import TELEGRAM_HARD_LIMIT
from ..models import AISummary, CVERecord, ChangeSet
from . import templates


def _split(text: str, limit: int = TELEGRAM_HARD_LIMIT) -> List[str]:
    """Split respecting Telegram limits. Prefer the project's splitter; fall
    back to a safe local split if gemini isn't importable (tests)."""
    try:
        from gemini import split_telegram_message
        return split_telegram_message(text, limit=limit)
    except Exception:
        return _local_split(text, limit)


def _local_split(text: str, limit: int) -> List[str]:
    if len(text) <= limit:
        return [text]
    chunks, current = [], ""
    for para in text.split("\n\n"):
        block = (para + "\n\n")
        if len(current) + len(block) > limit and current:
            chunks.append(current.rstrip())
            current = ""
        if len(block) > limit:
            # hard-split an over-long block on newlines
            for line in block.split("\n"):
                if len(current) + len(line) + 1 > limit and current:
                    chunks.append(current.rstrip())
                    current = ""
                current += line + "\n"
        else:
            current += block
    if current.strip():
        chunks.append(current.rstrip())
    return chunks or [text[:limit]]


def format_new_cve(record: CVERecord, ai: Optional[AISummary] = None) -> List[str]:
    """Render a full 'new CVE' alert, returned as one-or-more Telegram-sized
    chunks."""
    sections: List[Optional[str]] = [
        templates.header(record),
        "",
        templates.title_line(record, ai),
        "",
        templates.id_line(record),
        templates.published_line(record),
        templates.severity_line(record),
        templates.cvss_conflict_line(record),
        templates.cwe_line(record),
        templates.vendor_line(record),
        templates.product_line(record),
        templates.kev_line(record),
        templates.exploit_line(record),
        templates.epss_line(record),
        templates.exposure_line(record),
        templates.priority_line(record),
        "",
        templates.summary_block(record, ai),
        templates.impact_block(ai),
        templates.recommendation_block(ai),
        templates.references_block(record),
        templates_detail_line(record),
        "",
        templates.footer(ai),
    ]
    body = "\n".join(s for s in sections if s is not None)
    # collapse >2 blank lines
    while "\n\n\n" in body:
        body = body.replace("\n\n\n", "\n\n")
    return _split(body)


def format_updated_cve(record: CVERecord, change_set: ChangeSet,
                       ai: Optional[AISummary] = None) -> List[str]:
    """Render a compact 'CVE updated' alert focused on what changed."""
    sections: List[Optional[str]] = [
        templates.header(record, is_update=True),
        "",
        templates.title_line(record, ai),
        "",
        templates.id_line(record),
        templates.severity_line(record),
        templates.kev_line(record),
        "",
        templates.change_block(change_set),
        "",
        templates_detail_line(record),
    ]
    body = "\n".join(s for s in sections if s is not None)
    while "\n\n\n" in body:
        body = body.replace("\n\n\n", "\n\n")
    return _split(body)


def templates_detail_line(record: CVERecord) -> str:
    from ..utils import escape_html as esc
    return f"{templates.EMOJI['references']} <b>รายละเอียดเพิ่มเติม:</b> {esc(record.primary_url)}"


def format_compact(record: CVERecord) -> str:
    """One-line compact form for search/list results (not an alert)."""
    from ..utils import escape_html as esc
    emoji = templates.severity_emoji(record.severity)
    score = f" CVSS {record.cvss_score}" if record.cvss_score is not None else ""
    kev = " 🔥KEV" if record.in_kev else ""
    title = record.title or ""
    return (f"{emoji} <b>{esc(record.cve_id)}</b>{esc(score)}{kev}\n"
            f"   {esc(title[:90])}")
