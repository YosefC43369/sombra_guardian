"""
geo_osint.correlation.timeline — map geographic observations over time (spec §28).

Turns a set of :class:`~geo_osint.models.observation.GeoObservation` into an
ordered timeline: events sorted by time, each with its location, source and
confidence; per-entity movement of the *record* (first_seen -> last_seen) across
places; and detection of a changed location signal (e.g. an organization whose
public records reference city A earlier and city B later — spec §41).

SCOPE (spec §48): this is a timeline of *public observations about places*, not a
movement track of a person. It never asserts that an individual was physically
present anywhere; it records when a public source referenced a place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..models.observation import GeoObservation


@dataclass
class TimelineEvent:
    timestamp: float
    entity_id: str
    label: str
    location_type: str
    source: str
    confidence: float
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    city: str = ""
    country_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        import time as _t
        return {
            "timestamp": self.timestamp,
            "iso": _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(self.timestamp)),
            "entity_id": self.entity_id, "label": self.label,
            "location_type": self.location_type, "source": self.source,
            "confidence": round(self.confidence, 4),
            "latitude": self.latitude, "longitude": self.longitude,
            "city": self.city, "country_code": self.country_code,
        }


@dataclass
class LocationChange:
    entity_id: str
    from_place: str
    to_place: str
    from_ts: float
    to_ts: float

    def to_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id, "from": self.from_place,
                "to": self.to_place, "from_ts": self.from_ts, "to_ts": self.to_ts}


class TimelineEngine:
    def build(self, observations: Sequence[GeoObservation]) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []
        for obs in observations:
            label = obs.city or obs.region or obs.country_code or obs.location_type.value
            events.append(TimelineEvent(
                timestamp=obs.first_seen or obs.observation_timestamp,
                entity_id=obs.entity_id, label=label,
                location_type=obs.location_type.value, source=obs.source,
                confidence=obs.confidence,
                latitude=obs.coordinate.latitude if obs.coordinate else None,
                longitude=obs.coordinate.longitude if obs.coordinate else None,
                city=obs.city, country_code=obs.country_code))
        events.sort(key=lambda e: e.timestamp)
        return events

    def location_changes(self, observations: Sequence[GeoObservation]) -> List[LocationChange]:
        """Detect ordered place changes per entity (headquarters moves, §41)."""
        by_entity: Dict[str, List[GeoObservation]] = {}
        for obs in observations:
            place = obs.city or obs.country_code
            if place:
                by_entity.setdefault(obs.entity_id, []).append(obs)
        changes: List[LocationChange] = []
        for entity, obs_list in by_entity.items():
            obs_list.sort(key=lambda o: o.first_seen or o.observation_timestamp)
            last_place = None
            last_ts = 0.0
            for obs in obs_list:
                place = obs.city or obs.country_code
                if last_place is not None and place != last_place:
                    changes.append(LocationChange(entity, last_place, place,
                                                  last_ts,
                                                  obs.first_seen or obs.observation_timestamp))
                last_place = place
                last_ts = obs.first_seen or obs.observation_timestamp
        return changes

    def summary(self, observations: Sequence[GeoObservation]) -> Dict[str, Any]:
        events = self.build(observations)
        if not events:
            return {"events": 0, "span_start": None, "span_end": None}
        return {
            "events": len(events),
            "span_start": events[0].to_dict()["iso"],
            "span_end": events[-1].to_dict()["iso"],
            "entities": sorted({e.entity_id for e in events}),
            "countries": sorted({e.country_code for e in events if e.country_code}),
            "changes": [c.to_dict() for c in self.location_changes(observations)],
        }
