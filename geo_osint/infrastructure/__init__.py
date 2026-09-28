"""
geo_osint.infrastructure — public physical-infrastructure intelligence (spec §9-13, §36-40).

  * :class:`CloudRegionEngine` — public cloud region mapping from provider docs (§11);
  * :class:`DataCenterEngine` — data centres & IXPs via public PeeringDB (§10, §37);
  * :class:`FacilityEngine` — generic public-facility inventory (OSM/injected) (§9);
  * :class:`GovernmentFacilityEngine` — publicly-listed government facilities (§39);
  * :class:`TelecomInfrastructureEngine` — public telecom metadata only (§38);
  * :class:`SubmarineCableEngine` — public submarine-cable references (§36).

Public datasets only; no private-infrastructure discovery; no internal layouts.
"""

from .cloud_region_engine import CloudRegionEngine
from .datacenter_engine import DataCenterEngine
from .facility_engine import FacilityEngine
from .government_engine import GovernmentFacilityEngine
from .telecom_engine import TelecomInfrastructureEngine
from .submarine_cable_engine import SubmarineCableEngine

__all__ = [
    "CloudRegionEngine", "DataCenterEngine", "FacilityEngine",
    "GovernmentFacilityEngine", "TelecomInfrastructureEngine",
    "SubmarineCableEngine",
]
