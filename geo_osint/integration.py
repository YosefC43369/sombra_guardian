"""
geo_osint.integration — adapters to the other Sombra Guardian subsystems (spec §47-49).

Thin, duck-typed adapters so Geo-OSINT feeds and is fed by its siblings without a
hard import dependency on any of them (each subsystem stays independently testable):

  * **Entity Fusion (§47)** — `to_entity_fusion_evidence` exports geo observations as
    neutral corroborating-evidence records, and `shared_geography_signal` returns a
    co-location signal that is **always** `merge_safe=False`: geography corroborates,
    it never merges identities.
  * **Behavioral Intelligence (§48)** — `to_behavioral_timeline` exports the
    geographic timeline as events for temporal visualisation, each carrying the note
    that NO behavioural inference is drawn from location alone.
  * **Web Footprint (§49)** — `import_web_footprint_targets` extracts the geolocatable
    targets (domains, subdomains, websites, IPs) from a Web Footprint inventory so the
    geo engine can enrich them.

Everything here works on plain dict/attr shapes and degrades to empty on anything
unexpected — no subsystem is imported at module load.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .engine import GeoResult

# Web Footprint asset types that carry a geolocatable identifier.
_GEO_ASSET_TYPES = {"domain", "subdomain", "website", "ip", "api", "portal",
                    "cloud_reference"}


# --------------------------------------------------------------------------
# Web Footprint -> Geo-OSINT (§49)
# --------------------------------------------------------------------------
def import_web_footprint_targets(inventory: Any, *, limit: int = 200) -> List[str]:
    """Extract geolocatable target strings from a Web Footprint inventory.

    Accepts anything iterable of assets that expose ``asset_type`` (with a
    ``.value`` or being a string) and ``value`` — including
    ``web_footprint.assets.AttackSurfaceInventory`` — or a plain list of dicts.
    Returns a de-duplicated list of domain/IP strings to hand to the geo engine.
    """
    out: List[str] = []
    seen = set()
    for asset in _iter(inventory):
        atype = _attr(asset, "asset_type")
        atype = getattr(atype, "value", atype)
        if str(atype).lower() not in _GEO_ASSET_TYPES:
            continue
        value = str(_attr(asset, "value") or "").strip()
        if value and value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------
# Geo-OSINT -> Entity Fusion (§47)
# --------------------------------------------------------------------------
def to_entity_fusion_evidence(result: GeoResult) -> List[Dict[str, Any]]:
    """Export geo observations as neutral evidence records for Entity Fusion.

    Each record is corroborating geographic evidence for ``result.entity`` — a
    location claim with its source, confidence and limitations. It is explicitly
    NOT an identity-merge instruction.
    """
    records: List[Dict[str, Any]] = []
    for obs in result.observations.observations:
        for ev in obs.evidence:
            records.append({
                "entity_id": obs.entity_id,
                "kind": "geo",
                "relation": obs.location_type.value,
                "value": obs.city or obs.country_code or "",
                "country_code": obs.country_code,
                "latitude": obs.coordinate.latitude if obs.coordinate else None,
                "longitude": obs.coordinate.longitude if obs.coordinate else None,
                "confidence": round(ev.confidence, 4),
                "source": ev.source,
                "source_url": ev.source_url,
                "claim": ev.claim,
                "limitations": ev.limitations,
                "merge_safe": False,
            })
    return records


def shared_geography_signal(result_a: GeoResult, result_b: GeoResult) -> Dict[str, Any]:
    """A co-location signal between two entities for Entity Fusion — never a merge.

    Per spec §47, two entities are NEVER merged solely because they share a city or
    country; this returns the overlap tagged ``merge_safe=False`` for use only as
    corroboration alongside independent identity evidence.
    """
    from .correlation.geo_entity_correlation import GeoEntityCorrelator
    sg = GeoEntityCorrelator().shared_geography(
        result_a.entity, result_a.observations.observations,
        result_b.entity, result_b.observations.observations)
    return sg.to_dict()


# --------------------------------------------------------------------------
# Geo-OSINT -> Behavioral Intelligence (§48)
# --------------------------------------------------------------------------
def to_behavioral_timeline(result: GeoResult) -> Dict[str, Any]:
    """Export the geographic timeline for Behavioral Intelligence visualisation.

    Provides time-ordered geographic reference events. It carries an explicit note
    that these are observations *about places over time* and that NO behavioural
    inference is drawn from location alone (spec §48).
    """
    return {
        "entity": result.entity,
        "events": [e.to_dict() for e in result.timeline],
        "note": ("Geographic reference events over time (public observations about "
                 "places). No behavioural inference is drawn from location alone; "
                 "these are for temporal visualisation only."),
    }


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _iter(inventory: Any) -> Iterable[Any]:
    if inventory is None:
        return []
    if hasattr(inventory, "__iter__") and not isinstance(inventory, (str, bytes, dict)):
        return inventory
    for attr in ("assets", "all", "of_type"):
        member = getattr(inventory, attr, None)
        if callable(member):
            try:
                return member()
            except TypeError:
                continue
        if member is not None:
            return member
    return []


def _attr(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
