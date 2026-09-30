"""
cve_tracker.alerts.digest — periodic 'top CVEs' digest (rule §51).

A digest is a single rolled-up message summarising the most important CVEs over a
window (default 24h / 7d), ordered by the internal priority signal. It is the
low-noise counterpart to per-CVE alerts: a chat can subscribe to real-time
CRITICAL alerts AND receive a daily digest of everything above a floor. The
builder is pure (record list → text), so it is testable without a bot; the
command surface exposes it via ``/cve_digest`` and the scheduler can send it on a
cron-like cadence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..constants import EMOJI, SEVERITY_EMOJI
from ..models import CVERecord
from ..intelligence.prioritization import order_for_dispatch
from ..enrichment.epss import get_epss
from ..utils import escape_html as esc, thai_date, now_epoch


@dataclass
class DigestOptions:
    window_days: int = 1
    max_items: int = 15
    min_priority_score: int = 0
    title: str = "สรุป CVE ประจำวัน"


def build_digest(records: List[CVERecord], opts: DigestOptions) -> str:
    """Render a Thai digest from a list of records (already fetched for the
    window). Orders by priority, caps at ``max_items``, and summarises counts."""
    eligible = [r for r in records if r.priority_score >= opts.min_priority_score]
    ordered = order_for_dispatch(eligible)[: opts.max_items]

    total = len(records)
    critical = sum(1 for r in records if r.severity == "CRITICAL")
    kev = sum(1 for r in records if r.in_kev)

    lines: List[str] = []
    lines.append(f"{EMOJI['new']} <b>{esc(opts.title)}</b>")
    lines.append(f"ช่วง {opts.window_days} วันล่าสุด — ทั้งหมด {total} รายการ "
                 f"(CRITICAL {critical}, KEV {kev})")
    lines.append("")

    if not ordered:
        lines.append("ไม่มี CVE ที่ตรงเกณฑ์ในช่วงนี้")
        return "\n".join(lines)

    for i, rec in enumerate(ordered, 1):
        emoji = SEVERITY_EMOJI.get(rec.severity, EMOJI["unknown"])
        bits = [f"{i}. {emoji} <b>{esc(rec.cve_id)}</b>"]
        if rec.cvss_score is not None:
            bits.append(f"CVSS {rec.cvss_score}")
        if rec.in_kev:
            bits.append("🔥KEV")
        e = get_epss(rec)
        if e is not None and e.is_high:
            bits.append(f"EPSS {e.probability_pct}%")
        bits.append(f"[{rec.priority}]")
        lines.append(" ".join(bits))
        title = (rec.title or "")[:80]
        if title:
            lines.append(f"    {esc(title)}")
    return "\n".join(lines)


class DigestBuilder:
    """Fetches the window from the repository and builds the digest."""

    def __init__(self, repo):
        self.repo = repo

    def build(self, opts: DigestOptions) -> str:
        since = now_epoch() - opts.window_days * 86400
        records = self.repo.published_since(since, limit=500)
        return build_digest(records, opts)

    def build_default(self, *, window_days: int = 1) -> str:
        title = "สรุป CVE ประจำวัน" if window_days <= 1 else "สรุป CVE ประจำสัปดาห์"
        return self.build(DigestOptions(window_days=window_days, title=title))
