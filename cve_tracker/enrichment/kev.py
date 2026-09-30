"""
cve_tracker.enrichment.kev — CISA Known Exploited Vulnerabilities integration.

The KEV catalogue is the one *authoritative factual signal* that a vulnerability
is being exploited in the wild. This module parses a single KEV entry into a
:class:`KEVInfo`, and applies it to a :class:`CVERecord` — adding a timeline
milestone and raising exploit maturity to CONFIRMED. KEV presence is never an AI
judgement; it is a fact stamped with its source (rule §11).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..enums import ExploitMaturity, EventType
from ..models import CVERecord, KEVInfo, TimelineEntry
from ..utils import normalize_cve_id, to_epoch, now_epoch


def parse_kev_entry(entry: Dict[str, Any]) -> Optional[KEVInfo]:
    """Parse one object from CISA's ``vulnerabilities`` array into KEVInfo, or
    None if it has no usable CVE id."""
    if not isinstance(entry, dict):
        return None
    cve_id = normalize_cve_id(entry.get("cveID") or entry.get("cve_id"))
    if not cve_id:
        return None
    return KEVInfo(
        in_kev=True,
        date_added=to_epoch(entry.get("dateAdded")),
        due_date=to_epoch(entry.get("dueDate")),
        vendor_project=str(entry.get("vendorProject", "") or ""),
        product=str(entry.get("product", "") or ""),
        vulnerability_name=str(entry.get("vulnerabilityName", "") or ""),
        required_action=str(entry.get("requiredAction", "") or ""),
        known_ransomware=str(entry.get("knownRansomwareCampaignUse", "") or ""),
        notes=str(entry.get("notes", "") or ""),
    )


def cve_id_of_kev_entry(entry: Dict[str, Any]) -> Optional[str]:
    if not isinstance(entry, dict):
        return None
    return normalize_cve_id(entry.get("cveID") or entry.get("cve_id"))


def apply_kev(record: CVERecord, kev: KEVInfo, *, emit=None) -> bool:
    """Attach KEV info to a record. Returns True if this newly marked the record
    as KEV (so the caller can emit CVE_KEV_ADDED). Idempotent."""
    if not kev or not kev.in_kev:
        return False
    was_in_kev = record.in_kev
    record.kev = kev
    # KEV is a confirmed in-the-wild exploitation signal.
    record.exploit_maturity = ExploitMaturity.CONFIRMED.value
    if kev.date_added:
        _add_timeline(record, kev.date_added, "kev_added",
                      "CISA KEV: เพิ่มเข้าแคตตาล็อกช่องโหว่ที่ถูกใช้โจมตีจริง")
    if not was_in_kev and emit is not None:
        try:
            emit(EventType.CVE_KEV_ADDED.value, {"cve_id": record.cve_id})
        except Exception:
            pass
    return not was_in_kev


def _add_timeline(record: CVERecord, at: int, kind: str, label: str) -> None:
    for t in record.timeline:
        if t.kind == kind:
            return
    record.timeline.append(TimelineEntry(at=at, kind=kind, label=label, source="cisa_kev"))
    record.timeline.sort(key=lambda t: t.at)


def kev_badge_thai(record: CVERecord) -> str:
    """The Thai 'CISA KEV: YES/NO' line, with ransomware note when present."""
    if not record.in_kev:
        return "CISA KEV: NO"
    line = "CISA KEV: YES"
    known = (record.kev.known_ransomware or "").strip().lower()
    if known == "known":
        line += " — เกี่ยวข้องกับแคมเปญ ransomware ที่ทราบแล้ว"
    return line
