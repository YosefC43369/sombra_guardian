"""
cve_tracker.monitoring.reporting — operational reports (rule §51).

Beyond the per-CVE alert and the digest, operators want *aggregate* views: how
many CVEs this week vs last, the severity mix, the busiest vendors/products/CWEs,
which sources are contributing, and the AI/delivery success rates. This module
builds those reports from index-friendly repository aggregates (never a
full-table scan) and renders a compact Thai summary for ``/cve_stats`` deep view.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..constants import SEVERITY_EMOJI
from ..utils import now_epoch, escape_html as esc


@dataclass
class StatsReport:
    window_days: int
    total: int = 0
    total_window: int = 0
    critical_window: int = 0
    kev_total: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    top_vendors: List[dict] = field(default_factory=list)
    top_products: List[dict] = field(default_factory=list)
    top_cwes: List[dict] = field(default_factory=list)
    source_distribution: Dict[str, int] = field(default_factory=dict)
    ai_success_rate: float = 0.0
    delivery: Dict[str, int] = field(default_factory=dict)


class ReportBuilder:
    def __init__(self, repo):
        self.repo = repo

    def build(self, *, window_days: int = 7) -> StatsReport:
        since = now_epoch() - window_days * 86400
        base = self.repo.stats(since_epoch=since)
        rep = StatsReport(
            window_days=window_days,
            total=base.get("total", 0),
            total_window=base.get("since", 0),
            critical_window=base.get("critical_since", 0),
            kev_total=base.get("kev", 0),
            by_severity=base.get("by_severity", {}),
            top_vendors=base.get("top_vendors", []),
            top_cwes=base.get("top_cwes", []),
        )
        rep.top_products = self._top_products()
        rep.source_distribution = self._source_distribution()
        rep.delivery = self.repo.notification_stats(since_epoch=since)
        rep.ai_success_rate = self._ai_success_rate()
        return rep

    def _top_products(self) -> List[dict]:
        conn = self.repo._conn()
        try:
            rows = conn.execute(
                """SELECT product, COUNT(DISTINCT cve_id) n FROM cve_products
                   WHERE product != '' GROUP BY product_key ORDER BY n DESC LIMIT 8""").fetchall()
            return [{"product": r["product"], "count": r["n"]} for r in rows]
        finally:
            conn.close()

    def _source_distribution(self) -> Dict[str, int]:
        conn = self.repo._conn()
        try:
            rows = conn.execute(
                "SELECT source, COUNT(*) n FROM cve_source_records GROUP BY source").fetchall()
            return {r["source"]: r["n"] for r in rows}
        finally:
            conn.close()

    def _ai_success_rate(self) -> float:
        """Share of stored AI summaries that were validated (not fallback)."""
        conn = self.repo._conn()
        try:
            total = conn.execute("SELECT COUNT(*) n FROM cve_ai_summaries").fetchone()["n"]
            if not total:
                return 0.0
            fb = conn.execute(
                "SELECT COUNT(*) n FROM cve_ai_summaries WHERE fallback=1").fetchone()["n"]
            return round((total - fb) / total, 3)
        finally:
            conn.close()

    def render_thai(self, rep: StatsReport) -> str:
        lines = ["📈 <b>รายงาน CVE</b>", ""]
        lines.append(f"ทั้งหมด: {rep.total} | ใน {rep.window_days} วัน: {rep.total_window} "
                     f"(CRITICAL {rep.critical_window}) | KEV: {rep.kev_total}")
        if rep.by_severity:
            mix = " ".join(f"{SEVERITY_EMOJI.get(k,'')}{k}:{v}"
                           for k, v in sorted(rep.by_severity.items(),
                                              key=lambda kv: -_rank(kv[0])))
            lines.append(f"ระดับ: {mix}")
        if rep.top_vendors:
            lines.append("ผู้ผลิตเด่น: " + ", ".join(
                f"{esc(v['vendor'])}({v['count']})" for v in rep.top_vendors[:5]))
        if rep.top_products:
            lines.append("ผลิตภัณฑ์เด่น: " + ", ".join(
                f"{esc(p['product'])}({p['count']})" for p in rep.top_products[:5]))
        if rep.top_cwes:
            lines.append("CWE เด่น: " + ", ".join(
                f"{esc(c['cwe'])}({c['count']})" for c in rep.top_cwes[:5]))
        if rep.source_distribution:
            lines.append("แหล่งข้อมูล: " + ", ".join(
                f"{esc(k)}={v}" for k, v in sorted(
                    rep.source_distribution.items(), key=lambda kv: -kv[1])))
        lines.append(f"อัตราสำเร็จ AI: {round(rep.ai_success_rate * 100, 1)}%")
        if rep.delivery:
            lines.append("การส่ง: " + ", ".join(f"{k}={v}" for k, v in rep.delivery.items()))
        return "\n".join(lines)


def _rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
