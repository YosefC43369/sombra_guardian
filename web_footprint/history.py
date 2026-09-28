"""
web_footprint.history — historical attack-surface analysis and change detection.

Passive recon is far more useful over time than at a single instant. This module
compares a current :class:`AttackSurfaceInventory` against a prior snapshot and
classifies what moved (spec §29):

    ADDED       — present now, absent before
    REMOVED     — present before, absent now
    CHANGED     — present in both, but an observed attribute differs
    REAPPEARED  — present now, absent in the immediately prior snapshot but seen
                  in an earlier one (needs the prior snapshot's own history)
    UNCHANGED   — present in both, no observed difference

It also builds a technology timeline (spec §30, §42): for each technology, when
it was first and last seen and by which sources, so an authorized researcher can
see how the public stack evolved.

Discipline from the spec: a REMOVED asset means "no longer observed in our
sources", NOT "deleted" — removal is not interpreted as deletion unless verified
(spec §29). Snapshots are plain serializable dicts so the blue-team monitor can
persist and re-load them. Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .assets import Asset, AttackSurfaceInventory


class ChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    REAPPEARED = "reappeared"
    UNCHANGED = "unchanged"


@dataclass
class Change:
    kind: ChangeKind
    asset_key: str
    asset_type: str
    value: str
    detail: str = ""
    before: Dict[str, Any] = field(default_factory=dict)
    after: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "asset_key": self.asset_key,
                "asset_type": self.asset_type, "value": self.value,
                "detail": self.detail, "before": self.before, "after": self.after}


def snapshot(inventory: AttackSurfaceInventory) -> Dict[str, Any]:
    """A compact, serializable snapshot of an inventory for later comparison.

    Stores only the comparison-relevant fields per asset (keyed by ``asset.key``)
    plus the technologies and first/last-seen, so a diff is cheap and stable."""
    assets: Dict[str, Any] = {}
    for a in inventory:
        assets[a.key] = {
            "asset_type": a.asset_type.value,
            "value": a.value,
            "subdomain_role": a.subdomain_role,
            "signal_state": a.signal_state.value,
            "technologies": sorted({str(t.get("name", "")).lower()
                                    for t in a.technologies if t.get("name")}),
            "sources": a.sources,
            "first_seen": round(a.first_seen, 3),
            "last_seen": round(a.last_seen, 3),
        }
    return {"target": inventory.target, "count": len(assets), "assets": assets}


def _diff_attrs(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    diffs: List[str] = []
    for key in ("signal_state", "subdomain_role"):
        if before.get(key) != after.get(key):
            diffs.append(f"{key}: {before.get(key)!r} -> {after.get(key)!r}")
    b_tech = set(before.get("technologies", []))
    a_tech = set(after.get("technologies", []))
    if b_tech != a_tech:
        added = sorted(a_tech - b_tech)
        removed = sorted(b_tech - a_tech)
        if added:
            diffs.append(f"tech added: {', '.join(added)}")
        if removed:
            diffs.append(f"tech removed: {', '.join(removed)}")
    return diffs


def diff_snapshots(current: Dict[str, Any], previous: Dict[str, Any],
                   earlier_keys: Optional[set] = None) -> List[Change]:
    """Classify changes from ``previous`` to ``current`` (both from
    :func:`snapshot`). ``earlier_keys`` optionally supplies keys seen in an even
    older snapshot, enabling REAPPEARED classification."""
    cur = current.get("assets", {}) if current else {}
    prev = previous.get("assets", {}) if previous else {}
    earlier_keys = earlier_keys or set()
    changes: List[Change] = []

    for key, after in cur.items():
        if key not in prev:
            kind = ChangeKind.REAPPEARED if key in earlier_keys else ChangeKind.ADDED
            changes.append(Change(kind, key, after.get("asset_type", ""),
                                  after.get("value", ""),
                                  detail="seen again after earlier snapshot"
                                  if kind is ChangeKind.REAPPEARED else "newly observed",
                                  after=after))
        else:
            diffs = _diff_attrs(prev[key], after)
            if diffs:
                changes.append(Change(ChangeKind.CHANGED, key,
                                      after.get("asset_type", ""), after.get("value", ""),
                                      detail="; ".join(diffs),
                                      before=prev[key], after=after))
            else:
                changes.append(Change(ChangeKind.UNCHANGED, key,
                                      after.get("asset_type", ""), after.get("value", ""),
                                      before=prev[key], after=after))

    for key, before in prev.items():
        if key not in cur:
            changes.append(Change(ChangeKind.REMOVED, key, before.get("asset_type", ""),
                                  before.get("value", ""),
                                  detail="no longer observed (not confirmed deleted)",
                                  before=before))
    order = {ChangeKind.ADDED: 0, ChangeKind.REAPPEARED: 1, ChangeKind.CHANGED: 2,
             ChangeKind.REMOVED: 3, ChangeKind.UNCHANGED: 4}
    changes.sort(key=lambda c: (order[c.kind], c.asset_type, c.value.lower()))
    return changes


def diff_inventories(current: AttackSurfaceInventory,
                     previous: AttackSurfaceInventory) -> List[Change]:
    return diff_snapshots(snapshot(current), snapshot(previous))


def technology_timeline(inventory: AttackSurfaceInventory) -> List[Dict[str, Any]]:
    """Per-technology first/last-seen and sources across the inventory (spec §30)."""
    timeline: Dict[str, Dict[str, Any]] = {}
    for a in inventory:
        for t in a.technologies:
            name = str(t.get("name", "")).strip()
            if not name:
                continue
            key = name.lower()
            entry = timeline.setdefault(key, {
                "technology": name, "first_seen": a.first_seen,
                "last_seen": a.last_seen, "versions": set(), "sources": set(),
                "assets": set(),
            })
            entry["first_seen"] = min(entry["first_seen"], a.first_seen)
            entry["last_seen"] = max(entry["last_seen"], a.last_seen)
            if t.get("version"):
                entry["versions"].add(str(t["version"]))
            entry["sources"].update(a.sources)
            entry["assets"].add(a.value)
    out = []
    for entry in timeline.values():
        out.append({
            "technology": entry["technology"],
            "first_seen": round(entry["first_seen"], 3),
            "last_seen": round(entry["last_seen"], 3),
            "versions": sorted(entry["versions"]),
            "sources": sorted(entry["sources"]),
            "asset_count": len(entry["assets"]),
        })
    out.sort(key=lambda e: e["technology"].lower())
    return out


def summarize_changes(changes: List[Change]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for c in changes:
        out[c.kind.value] = out.get(c.kind.value, 0) + 1
    return out
