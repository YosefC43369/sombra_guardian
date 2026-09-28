"""
geo_osint.correlation — the analytical core (spec §12–14, §25–29).

Distance, proximity, clustering and timeline analysis over geographic
observations, plus the IP / ASN / domain geolocation engines and the entity<->
geography correlation and infrastructure-graph builders. The pure-analytic
modules (distance, cluster, proximity, timeline, graph, correlation) are fully
offline and dependency-free; the geolocation engines add optional public-network
enrichment and always carry honest, explicit limitations on what a geo signal
proves.
"""

from .distance import DistanceEngine
from .cluster import ClusterEngine, Cluster, ClusterResult
from .proximity import ProximityEngine, ProximityHit, ProximityResult
from .timeline import TimelineEngine, TimelineEvent, LocationChange
from .ip_geolocation import IPGeolocationEngine, IPGeoResult
from .asn_geolocation import ASNGeolocationEngine, ASNGeoResult
from .domain_geolocation import DomainGeolocationEngine, DomainGeoResult
from .geo_entity_correlation import (
    GeoEntityCorrelator, EntityGeoProfile, GeoCorrelation, SharedGeography,
)
from .infrastructure_graph import InfrastructureGraph, GraphNode, GraphEdge

__all__ = [
    "DistanceEngine",
    "ClusterEngine", "Cluster", "ClusterResult",
    "ProximityEngine", "ProximityHit", "ProximityResult",
    "TimelineEngine", "TimelineEvent", "LocationChange",
    "IPGeolocationEngine", "IPGeoResult",
    "ASNGeolocationEngine", "ASNGeoResult",
    "DomainGeolocationEngine", "DomainGeoResult",
    "GeoEntityCorrelator", "EntityGeoProfile", "GeoCorrelation", "SharedGeography",
    "InfrastructureGraph", "GraphNode", "GraphEdge",
]
