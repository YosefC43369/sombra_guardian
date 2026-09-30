"""
cve_tracker.enrichment.epss — EPSS (Exploit Prediction Scoring System) signal.

EPSS is a FIRST.org data product that estimates the probability (0–1) a CVE will
be exploited in the next 30 days, plus a percentile ranking among all CVEs. It is
a *factual, published* signal — not an AI judgement and not a CVSS score — so it
slots cleanly into the intelligence layer alongside KEV and exploit references
(rule §17: expose separate indicators, never invent a score).

This module parses an EPSS record, attaches it to a :class:`CVERecord` (stored in
the record's provenance map under ``epss``), and renders the Thai line the
formatter shows. The EPSS *source adapter* that fetches the daily CSV/JSON lives
in ``sources/epss.py``; this module is the pure parse/attach/render half so it is
testable without the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..models import CVERecord, ProvenancedValue
from ..utils import normalize_cve_id, now_epoch


@dataclass
class EPSSScore:
    cve_id: str
    probability: float          # 0.0–1.0 chance of exploitation in 30 days
    percentile: float           # 0.0–1.0 rank among all CVEs
    date: str = ""              # EPSS model date (YYYY-MM-DD)
    source: str = "epss"

    @property
    def probability_pct(self) -> float:
        return round(self.probability * 100, 2)

    @property
    def percentile_pct(self) -> float:
        return round(self.percentile * 100, 1)

    @property
    def is_high(self) -> bool:
        # FIRST.org commonly treats >= 0.10 (10%) as notable; >= 0.5 as high.
        return self.probability >= 0.10

    def to_dict(self) -> Dict[str, Any]:
        return {"cve_id": self.cve_id, "probability": self.probability,
                "percentile": self.percentile, "date": self.date, "source": self.source}


def parse_epss(entry: Dict[str, Any]) -> Optional[EPSSScore]:
    """Parse one EPSS API/CSV row into an :class:`EPSSScore`, or None.

    Accepts the FIRST.org API shape ({cve, epss, percentile, date}) and the raw
    CSV shape ({cve, epss, percentile}). Values are clamped to [0,1]; a row with
    a bad id or unparseable probability is dropped."""
    if not isinstance(entry, dict):
        return None
    cve_id = normalize_cve_id(entry.get("cve") or entry.get("cveID") or entry.get("cve_id"))
    if not cve_id:
        return None
    try:
        prob = float(entry.get("epss", entry.get("probability", "")))
        pct = float(entry.get("percentile", 0.0) or 0.0)
    except (TypeError, ValueError):
        return None
    prob = max(0.0, min(prob, 1.0))
    pct = max(0.0, min(pct, 1.0))
    return EPSSScore(cve_id=cve_id, probability=prob, percentile=pct,
                     date=str(entry.get("date", "") or ""))


def apply_epss(record: CVERecord, epss: EPSSScore) -> bool:
    """Attach an EPSS score to a record (stored in provenance). Returns True if
    this is new or changed. Idempotent."""
    if not epss or epss.cve_id != record.cve_id:
        return False
    prev = record.provenance.get("epss")
    record.provenance["epss"] = ProvenancedValue(
        value=epss.to_dict(), source="epss", trust=75, observed_at=now_epoch())
    if prev is None:
        return True
    try:
        return abs(float(prev.value.get("probability", -1)) - epss.probability) > 1e-6
    except Exception:
        return True


def get_epss(record: CVERecord) -> Optional[EPSSScore]:
    """Read back the EPSS score attached to a record, or None."""
    pv = record.provenance.get("epss")
    if pv is None or not isinstance(pv.value, dict):
        return None
    d = pv.value
    try:
        return EPSSScore(cve_id=record.cve_id,
                         probability=float(d.get("probability", 0.0)),
                         percentile=float(d.get("percentile", 0.0)),
                         date=str(d.get("date", "")))
    except (TypeError, ValueError):
        return None


def epss_line_thai(record: CVERecord) -> Optional[str]:
    """The Thai '🔮 EPSS: X% (เปอร์เซ็นไทล์ Y%)' line, or None if no EPSS data."""
    e = get_epss(record)
    if e is None:
        return None
    note = " — โอกาสถูกใช้โจมตีสูง" if e.is_high else ""
    return (f"โอกาสถูกใช้โจมตีใน 30 วัน ≈ {e.probability_pct}% "
            f"(เปอร์เซ็นไทล์ {e.percentile_pct}%){note}")
