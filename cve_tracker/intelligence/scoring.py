"""
cve_tracker.intelligence.scoring — the internal prioritization signal.

**This is not a CVSS score and must never be presented as one** (rule §17). It
is an *operational* 0–100 signal that blends several factual indicators to help
a blue team decide what to look at first. Every point it adds is attributable to
a named, visible fact (the underlying CVSS, KEV status, exploit references,
exposure, recency, source agreement), and those facts always remain visible in
the alert — the signal never replaces them.

The weights are explicit and summed; there is no opaque model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..enums import ExploitMaturity, Severity
from ..models import CVERecord
from ..utils import now_epoch

# Weight budget (sums to 100 at the theoretical max).
W_CVSS = 40          # scaled from the CVSS base score (score/10 * 40)
W_KEV = 30           # CISA-confirmed exploitation in the wild
W_MATURITY = 20      # exploit code maturity (confirmed/poc/referenced)
W_EXPLOIT_REFS = 6   # count of exploit/PoC references (capped)
W_RECENCY = 10       # freshly published gets attention
W_EXPOSURE = 8       # network-reachable, no-auth, no-UI ("wormable-ish")
W_SOURCES = 4        # corroborated by multiple sources
W_EPSS = 12          # FIRST.org exploit-probability (factual, not invented)


@dataclass
class ScoreBreakdown:
    """Transparent breakdown of the priority score — every component is shown
    so the number is never a black box."""

    total: int = 0
    components: List[tuple] = field(default_factory=list)  # (label, points)
    reasons: List[str] = field(default_factory=list)

    def add(self, label: str, points: float, reason: str = "") -> None:
        pts = int(round(points))
        if pts <= 0:
            return
        self.components.append((label, pts))
        self.total += pts
        if reason:
            self.reasons.append(reason)


def _cvss_points(record: CVERecord) -> float:
    if record.cvss_score is None:
        return 0.0
    return max(0.0, min(record.cvss_score, 10.0)) / 10.0 * W_CVSS


def _maturity_points(record: CVERecord) -> float:
    return {
        ExploitMaturity.CONFIRMED.value: W_MATURITY,
        ExploitMaturity.PUBLIC_POC.value: W_MATURITY * 0.6,
        ExploitMaturity.REFERENCED.value: W_MATURITY * 0.25,
    }.get(record.exploit_maturity, 0.0)


def _exposure_points(record: CVERecord) -> float:
    """Reward the classic 'network / no privileges / no user interaction'
    profile, read from the primary CVSS metrics when present."""
    from ..enrichment.cvss import pick_primary
    primary = pick_primary(record.cvss_scores)
    if primary is None:
        return 0.0
    pts = 0.0
    if primary.attack_vector == "Network":
        pts += W_EXPOSURE * 0.5
    if primary.privileges_required == "None":
        pts += W_EXPOSURE * 0.3
    if primary.user_interaction == "None":
        pts += W_EXPOSURE * 0.2
    return pts


def _recency_points(record: CVERecord) -> float:
    ref = record.published_at or record.first_seen_at
    if not ref:
        return 0.0
    age_days = (now_epoch() - ref) / 86400.0
    if age_days <= 7:
        return W_RECENCY
    if age_days <= 30:
        return W_RECENCY * 0.5
    if age_days <= 90:
        return W_RECENCY * 0.2
    return 0.0


def compute_breakdown(record: CVERecord) -> ScoreBreakdown:
    from ..enrichment.exploit_status import exploit_reference_count

    bd = ScoreBreakdown()

    if record.cvss_score is not None:
        bd.add("CVSS", _cvss_points(record),
               f"CVSS {record.cvss_score} ({record.severity})")
    if record.in_kev:
        bd.add("KEV", W_KEV, "อยู่ใน CISA KEV (ถูกใช้โจมตีจริง)")
    mp = _maturity_points(record)
    if mp:
        label = {
            ExploitMaturity.CONFIRMED.value: "ยืนยัน exploit",
            ExploitMaturity.PUBLIC_POC.value: "พบ public PoC",
            ExploitMaturity.REFERENCED.value: "พบ reference exploit",
        }.get(record.exploit_maturity, "exploit")
        bd.add("ExploitMaturity", mp, label)
    ref_count = exploit_reference_count(record)
    if ref_count:
        bd.add("ExploitRefs", min(ref_count, 3) / 3.0 * W_EXPLOIT_REFS,
               f"พบ {ref_count} reference ที่เกี่ยวกับ exploit/PoC")
    rp = _recency_points(record)
    if rp:
        bd.add("Recency", rp, "เพิ่งเผยแพร่")
    ep = _exposure_points(record)
    if ep:
        bd.add("Exposure", ep, "โจมตีผ่านเครือข่ายได้โดยไม่ต้องมีสิทธิ์/ปฏิสัมพันธ์")
    if len(record.source_names) >= 2:
        bd.add("SourceAgreement", W_SOURCES,
               f"ยืนยันจาก {len(record.source_names)} แหล่ง")

    # EPSS — factual exploit probability (0..1) scaled into the budget.
    from ..enrichment.epss import get_epss
    epss = get_epss(record)
    if epss is not None and epss.probability > 0:
        bd.add("EPSS", epss.probability * W_EPSS,
               f"EPSS โอกาสถูกใช้โจมตี ≈ {epss.probability_pct}%")

    bd.total = min(bd.total, 100)
    return bd


def compute_score(record: CVERecord) -> int:
    return compute_breakdown(record).total
