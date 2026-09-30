"""
cve_tracker.intelligence.change_detection — diff two versions of a CVE.

When an already-stored CVE is re-ingested, this computes the field-level
difference into a :class:`ChangeSet`. The engine uses it to decide whether to
emit a 'CVE Updated' alert and which internal events to fire (rules §39, §40).
Insignificant drift (a whitespace change in the description) is recorded but not
flagged significant, so subscribers aren't spammed for trivia unless they opt in.
"""

from __future__ import annotations

from typing import List, Optional

from ..enums import ChangeKind, EventType
from ..models import CVERecord, ChangeSet, FieldChange


def diff(old: CVERecord, new: CVERecord) -> ChangeSet:
    """Return the ChangeSet describing how ``new`` differs from ``old``."""
    cs = ChangeSet(cve_id=new.cve_id)

    if _norm_text(old.title) != _norm_text(new.title) and new.title:
        cs.changes.append(FieldChange(
            kind=ChangeKind.TITLE.value, before=old.title, after=new.title))

    if _desc_changed(old.description, new.description):
        cs.changes.append(FieldChange(
            kind=ChangeKind.DESCRIPTION.value,
            before=_snippet(old.description), after=_snippet(new.description),
            note="description updated"))

    if (old.cvss_score or None) != (new.cvss_score or None):
        cs.changes.append(FieldChange(
            kind=ChangeKind.CVSS.value, before=old.cvss_score, after=new.cvss_score,
            note=f"{old.cvss_score} → {new.cvss_score}"))

    if (old.severity or "") != (new.severity or "") and new.severity:
        cs.changes.append(FieldChange(
            kind=ChangeKind.SEVERITY.value, before=old.severity, after=new.severity,
            note=f"{old.severity} → {new.severity}"))

    if old.in_kev != new.in_kev:
        cs.changes.append(FieldChange(
            kind=ChangeKind.KEV_STATUS.value, before=old.in_kev, after=new.in_kev,
            note="added to CISA KEV" if new.in_kev else "removed from KEV"))

    if old.exploit_maturity != new.exploit_maturity:
        cs.changes.append(FieldChange(
            kind=ChangeKind.EXPLOIT_STATUS.value,
            before=old.exploit_maturity, after=new.exploit_maturity))

    old_cwes, new_cwes = set(old.cwe_ids), set(new.cwe_ids)
    if old_cwes != new_cwes:
        cs.changes.append(FieldChange(
            kind=ChangeKind.CWE.value, before=sorted(old_cwes), after=sorted(new_cwes)))

    old_refs = {r.url for r in old.references}
    new_refs = {r.url for r in new.references}
    added = new_refs - old_refs
    if added:
        cs.changes.append(FieldChange(
            kind=ChangeKind.REFERENCES.value, before=len(old_refs), after=len(new_refs),
            note=f"+{len(added)} references"))

    old_prod = {p.key for p in old.products}
    new_prod = {p.key for p in new.products}
    if old_prod != new_prod:
        cs.changes.append(FieldChange(
            kind=ChangeKind.PRODUCTS.value, before=len(old_prod), after=len(new_prod)))

    return cs


def events_for(change_set: ChangeSet) -> List[str]:
    """Map a ChangeSet to the internal event types it should emit."""
    events: List[str] = [EventType.CVE_UPDATED.value]
    for c in change_set.changes:
        if c.kind == ChangeKind.SEVERITY.value:
            events.append(EventType.CVE_SEVERITY_CHANGED.value)
        elif c.kind == ChangeKind.CVSS.value:
            events.append(EventType.CVE_CVSS_CHANGED.value)
        elif c.kind == ChangeKind.KEV_STATUS.value and c.after:
            events.append(EventType.CVE_KEV_ADDED.value)
        elif c.kind == ChangeKind.REFERENCES.value:
            events.append(EventType.CVE_REFERENCE_ADDED.value)
        elif c.kind == ChangeKind.EXPLOIT_STATUS.value:
            events.append(EventType.CVE_EXPLOIT_STATUS_CHANGED.value)
    return events


def should_notify_update(change_set: ChangeSet, *, include_minor: bool = False) -> bool:
    """A significant change always notifies; minor drift only when a subscriber
    opted into updates and asked for minor ones."""
    if change_set is None or not change_set.changes:
        return False
    if change_set.has_significant:
        return True
    return include_minor


# ---------------- helpers ----------------

def _norm_text(s: Optional[str]) -> str:
    return " ".join((s or "").split()).strip().lower()


def _desc_changed(a: Optional[str], b: Optional[str]) -> bool:
    na, nb = _norm_text(a), _norm_text(b)
    if na == nb:
        return False
    # Ignore trivial length-1 edits / pure whitespace churn.
    if not nb:
        return False
    return True


def _snippet(s: Optional[str], n: int = 160) -> str:
    s = s or ""
    return s[:n] + ("…" if len(s) > n else "")
