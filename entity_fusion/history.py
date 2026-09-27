"""
entity_fusion.history — the temporal engine: track how an identity evolves over
time (renamed handles, changed bios/avatars, transferred domains, renewed
certificates) and render a chronological timeline.

An investigation is often about *change*: a handle that was abandoned and
reused, an avatar swapped the day an account went quiet, a domain that changed
registrant. This module records typed, timestamped change events and folds them
into an ordered timeline. It is storage-agnostic — events can be built from the
SQLite ``entity_history`` table, from two snapshots of an entity, or appended
directly by an enricher that observed a change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from .entity import Entity


class ChangeKind(str, Enum):
    IDENTITY_CHANGE = "identity_change"
    BIO_CHANGE = "bio_change"
    USERNAME_CHANGE = "username_change"
    AVATAR_CHANGE = "avatar_change"
    WEBSITE_CHANGE = "website_change"
    ORG_CHANGE = "org_change"
    DOMAIN_OWNERSHIP_CHANGE = "domain_ownership_change"
    CERTIFICATE_RENEWAL = "certificate_renewal"
    FIRST_SEEN = "first_seen"
    LAST_SEEN = "last_seen"
    OTHER = "other"


# Which metadata key maps to which change kind when diffing two snapshots.
_FIELD_KIND = {
    "bio": ChangeKind.BIO_CHANGE,
    "description": ChangeKind.BIO_CHANGE,
    "display_name": ChangeKind.IDENTITY_CHANGE,
    "name": ChangeKind.IDENTITY_CHANGE,
    "avatar_sha256": ChangeKind.AVATAR_CHANGE,
    "avatar_phash": ChangeKind.AVATAR_CHANGE,
    "website": ChangeKind.WEBSITE_CHANGE,
    "organization": ChangeKind.ORG_CHANGE,
    "org": ChangeKind.ORG_CHANGE,
    "registrant": ChangeKind.DOMAIN_OWNERSHIP_CHANGE,
    "cert_not_after": ChangeKind.CERTIFICATE_RENEWAL,
}


@dataclass
class TimelineEvent:
    at: float
    kind: ChangeKind
    entity_id: str = ""
    field: str = ""
    old_value: str = ""
    new_value: str = ""
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"at": self.at, "kind": self.kind.value, "entity_id": self.entity_id,
                "field": self.field, "old_value": self.old_value,
                "new_value": self.new_value, "note": self.note}


class HistoryEngine:
    """Accumulate change events and produce an ordered timeline."""

    def __init__(self) -> None:
        self.events: List[TimelineEvent] = []

    def record(self, event: TimelineEvent) -> None:
        self.events.append(event)

    def observe_entity(self, entity: Entity) -> None:
        """Seed first/last-seen anchors from a single entity snapshot."""
        self.record(TimelineEvent(entity.first_seen, ChangeKind.FIRST_SEEN,
                                  entity.id, note=entity.summary()))
        if entity.last_seen > entity.first_seen:
            self.record(TimelineEvent(entity.last_seen, ChangeKind.LAST_SEEN,
                                      entity.id, note=entity.summary()))

    def diff_snapshots(self, before: Entity, after: Entity, *,
                       at: Optional[float] = None) -> List[TimelineEvent]:
        """Compare two snapshots of the same entity and emit change events for
        every differing tracked field. ``at`` defaults to the later last_seen."""
        when = at if at is not None else max(before.last_seen, after.last_seen)
        events: List[TimelineEvent] = []
        if before.value != after.value:
            events.append(TimelineEvent(when, ChangeKind.USERNAME_CHANGE,
                                        after.id, "value", before.value, after.value))
        for key, kind in _FIELD_KIND.items():
            ov, nv = before.metadata.get(key), after.metadata.get(key)
            if ov is not None and nv is not None and str(ov) != str(nv):
                events.append(TimelineEvent(when, kind, after.id, key,
                                            str(ov), str(nv)))
        for e in events:
            self.record(e)
        return events

    def ingest_history_rows(self, rows: Iterable[Dict[str, Any]],
                            entity_id: str = "") -> None:
        """Load rows from ``SQLiteStore.history_for`` into the timeline."""
        for r in rows:
            field = str(r.get("field", ""))
            kind = _FIELD_KIND.get(field, ChangeKind.OTHER)
            self.record(TimelineEvent(
                at=float(r.get("changed_at", 0.0)), kind=kind,
                entity_id=entity_id, field=field,
                old_value=str(r.get("old_value", "")),
                new_value=str(r.get("new_value", ""))))

    def timeline(self, *, ascending: bool = True) -> List[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.at, reverse=not ascending)

    def render_markdown(self, *, title: str = "Timeline") -> str:
        import datetime as _dt
        lines = [f"## {title}", ""]
        for ev in self.timeline():
            when = (_dt.datetime.utcfromtimestamp(ev.at).strftime("%Y-%m-%d %H:%M")
                    if ev.at else "unknown")
            change = (f"{ev.field}: {ev.old_value!r} → {ev.new_value!r}"
                      if ev.new_value or ev.old_value else ev.note)
            lines.append(f"- **{when}** · `{ev.kind.value}` · {change}")
        if len(lines) == 2:
            lines.append("_no recorded change events_")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"events": [e.to_dict() for e in self.timeline()]}
