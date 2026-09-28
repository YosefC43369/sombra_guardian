"""
geo_osint.data.cloud_regions — public cloud region locations (spec §11).

Cloud providers publish the geographic location (city/region) of their regions in
their own public documentation. This is a curated table of those published
locations for the major providers. Coordinates are the region's stated
metropolitan area, exposed at city precision — a region spans multiple physical
data centres whose exact locations providers do not publish, so this never claims
a rooftop fix (spec §10 "never infer sensitive internal layouts").

Not exhaustive (providers add regions continually) but every row is a documented
public fact; the cloud-region engine can be extended at runtime from a provider's
current public region list.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..models.coordinate import Coordinate
from ..models.infrastructure import CloudRegion

# (provider, region_code, city, country_code, lat, lon)
_ROWS = [
    # ---- AWS ----
    ("aws", "us-east-1", "Ashburn", "US", 39.04, -77.49),
    ("aws", "us-east-2", "Columbus", "US", 39.96, -83.00),
    ("aws", "us-west-1", "San Jose", "US", 37.34, -121.89),
    ("aws", "us-west-2", "Boardman", "US", 45.84, -119.70),
    ("aws", "af-south-1", "Cape Town", "ZA", -33.92, 18.42),
    ("aws", "ap-east-1", "Hong Kong", "HK", 22.32, 114.17),
    ("aws", "ap-south-1", "Mumbai", "IN", 19.08, 72.88),
    ("aws", "ap-south-2", "Hyderabad", "IN", 17.39, 78.49),
    ("aws", "ap-northeast-1", "Tokyo", "JP", 35.68, 139.69),
    ("aws", "ap-northeast-2", "Seoul", "KR", 37.57, 126.98),
    ("aws", "ap-northeast-3", "Osaka", "JP", 34.69, 135.50),
    ("aws", "ap-southeast-1", "Singapore", "SG", 1.35, 103.82),
    ("aws", "ap-southeast-2", "Sydney", "AU", -33.87, 151.21),
    ("aws", "ap-southeast-3", "Jakarta", "ID", -6.21, 106.85),
    ("aws", "ap-southeast-4", "Melbourne", "AU", -37.81, 144.96),
    ("aws", "ca-central-1", "Montreal", "CA", 45.50, -73.57),
    ("aws", "eu-central-1", "Frankfurt", "DE", 50.11, 8.68),
    ("aws", "eu-central-2", "Zurich", "CH", 47.37, 8.54),
    ("aws", "eu-west-1", "Dublin", "IE", 53.35, -6.26),
    ("aws", "eu-west-2", "London", "GB", 51.51, -0.13),
    ("aws", "eu-west-3", "Paris", "FR", 48.85, 2.35),
    ("aws", "eu-north-1", "Stockholm", "SE", 59.33, 18.07),
    ("aws", "eu-south-1", "Milan", "IT", 45.46, 9.19),
    ("aws", "me-south-1", "Manama", "BH", 26.23, 50.59),
    ("aws", "me-central-1", "Abu Dhabi", "AE", 24.47, 54.37),
    ("aws", "sa-east-1", "São Paulo", "BR", -23.55, -46.63),
    ("aws", "il-central-1", "Tel Aviv", "IL", 32.08, 34.78),
    # ---- GCP ----
    ("gcp", "us-central1", "Council Bluffs", "US", 41.26, -95.86),
    ("gcp", "us-east1", "Moncks Corner", "US", 33.20, -79.98),
    ("gcp", "us-east4", "Ashburn", "US", 39.04, -77.49),
    ("gcp", "us-west1", "The Dalles", "US", 45.60, -121.18),
    ("gcp", "us-west2", "Los Angeles", "US", 34.05, -118.24),
    ("gcp", "europe-west1", "St. Ghislain", "BE", 50.45, 3.82),
    ("gcp", "europe-west2", "London", "GB", 51.51, -0.13),
    ("gcp", "europe-west3", "Frankfurt", "DE", 50.11, 8.68),
    ("gcp", "europe-west4", "Eemshaven", "NL", 53.43, 6.83),
    ("gcp", "europe-north1", "Hamina", "FI", 60.57, 27.19),
    ("gcp", "asia-east1", "Changhua County", "TW", 24.05, 120.52),
    ("gcp", "asia-east2", "Hong Kong", "HK", 22.32, 114.17),
    ("gcp", "asia-northeast1", "Tokyo", "JP", 35.68, 139.69),
    ("gcp", "asia-northeast3", "Seoul", "KR", 37.57, 126.98),
    ("gcp", "asia-south1", "Mumbai", "IN", 19.08, 72.88),
    ("gcp", "asia-southeast1", "Jurong West", "SG", 1.35, 103.71),
    ("gcp", "asia-southeast2", "Jakarta", "ID", -6.21, 106.85),
    ("gcp", "australia-southeast1", "Sydney", "AU", -33.87, 151.21),
    ("gcp", "southamerica-east1", "São Paulo", "BR", -23.55, -46.63),
    # ---- Azure ----
    ("azure", "eastus", "Boydton", "US", 36.66, -78.38),
    ("azure", "eastus2", "Boydton", "US", 36.66, -78.38),
    ("azure", "westus2", "Quincy", "US", 47.23, -119.85),
    ("azure", "westus3", "Phoenix", "US", 33.45, -112.07),
    ("azure", "centralus", "Des Moines", "US", 41.59, -93.62),
    ("azure", "southcentralus", "San Antonio", "US", 29.42, -98.49),
    ("azure", "northeurope", "Dublin", "IE", 53.35, -6.26),
    ("azure", "westeurope", "Amsterdam", "NL", 52.37, 4.90),
    ("azure", "uksouth", "London", "GB", 51.51, -0.13),
    ("azure", "francecentral", "Paris", "FR", 48.85, 2.35),
    ("azure", "germanywestcentral", "Frankfurt", "DE", 50.11, 8.68),
    ("azure", "switzerlandnorth", "Zurich", "CH", 47.37, 8.54),
    ("azure", "swedencentral", "Gävle", "SE", 60.67, 17.14),
    ("azure", "southeastasia", "Singapore", "SG", 1.35, 103.82),
    ("azure", "eastasia", "Hong Kong", "HK", 22.32, 114.17),
    ("azure", "japaneast", "Tokyo", "JP", 35.68, 139.69),
    ("azure", "koreacentral", "Seoul", "KR", 37.57, 126.98),
    ("azure", "centralindia", "Pune", "IN", 18.52, 73.86),
    ("azure", "australiaeast", "Sydney", "AU", -33.87, 151.21),
    ("azure", "brazilsouth", "São Paulo", "BR", -23.55, -46.63),
    ("azure", "uaenorth", "Dubai", "AE", 25.20, 55.27),
    ("azure", "southafricanorth", "Johannesburg", "ZA", -26.20, 28.05),
    # ---- Oracle Cloud (OCI) ----
    ("oracle", "us-ashburn-1", "Ashburn", "US", 39.04, -77.49),
    ("oracle", "us-phoenix-1", "Phoenix", "US", 33.45, -112.07),
    ("oracle", "uk-london-1", "London", "GB", 51.51, -0.13),
    ("oracle", "eu-frankfurt-1", "Frankfurt", "DE", 50.11, 8.68),
    ("oracle", "ap-tokyo-1", "Tokyo", "JP", 35.68, 139.69),
    ("oracle", "ap-singapore-1", "Singapore", "SG", 1.35, 103.82),
    ("oracle", "ap-mumbai-1", "Mumbai", "IN", 19.08, 72.88),
    ("oracle", "ap-sydney-1", "Sydney", "AU", -33.87, 151.21),
    ("oracle", "sa-saopaulo-1", "São Paulo", "BR", -23.55, -46.63),
    # ---- Cloudflare (representative anycast PoP cities, keyed by IATA) ----
    ("cloudflare", "SIN", "Singapore", "SG", 1.35, 103.82),
    ("cloudflare", "LHR", "London", "GB", 51.51, -0.13),
    ("cloudflare", "FRA", "Frankfurt", "DE", 50.11, 8.68),
    ("cloudflare", "IAD", "Ashburn", "US", 39.04, -77.49),
    ("cloudflare", "NRT", "Tokyo", "JP", 35.68, 139.69),
    ("cloudflare", "BKK", "Bangkok", "TH", 13.75, 100.52),
    # ---- DigitalOcean ----
    ("digitalocean", "nyc1", "New York", "US", 40.71, -74.01),
    ("digitalocean", "sfo3", "San Francisco", "US", 37.77, -122.42),
    ("digitalocean", "ams3", "Amsterdam", "NL", 52.37, 4.90),
    ("digitalocean", "sgp1", "Singapore", "SG", 1.35, 103.82),
    ("digitalocean", "lon1", "London", "GB", 51.51, -0.13),
    ("digitalocean", "fra1", "Frankfurt", "DE", 50.11, 8.68),
    ("digitalocean", "tor1", "Toronto", "CA", 43.65, -79.38),
    ("digitalocean", "blr1", "Bengaluru", "IN", 12.97, 77.59),
    ("digitalocean", "syd1", "Sydney", "AU", -33.87, 151.21),
    # ---- Linode / Akamai ----
    ("linode", "us-east", "Newark", "US", 40.74, -74.17),
    ("linode", "us-central", "Dallas", "US", 32.78, -96.80),
    ("linode", "eu-west", "London", "GB", 51.51, -0.13),
    ("linode", "eu-central", "Frankfurt", "DE", 50.11, 8.68),
    ("linode", "ap-south", "Singapore", "SG", 1.35, 103.82),
    ("linode", "ap-northeast", "Tokyo", "JP", 35.68, 139.69),
    ("linode", "ap-southeast", "Sydney", "AU", -33.87, 151.21),
    ("linode", "ap-west", "Mumbai", "IN", 19.08, 72.88),
    # ---- Vultr ----
    ("vultr", "ewr", "Newark", "US", 40.74, -74.17),
    ("vultr", "lax", "Los Angeles", "US", 34.05, -118.24),
    ("vultr", "fra", "Frankfurt", "DE", 50.11, 8.68),
    ("vultr", "lhr", "London", "GB", 51.51, -0.13),
    ("vultr", "nrt", "Tokyo", "JP", 35.68, 139.69),
    ("vultr", "sgp", "Singapore", "SG", 1.35, 103.82),
    ("vultr", "syd", "Sydney", "AU", -33.87, 151.21),
    ("vultr", "icn", "Seoul", "KR", 37.57, 126.98),
]

_REGIONS: List[CloudRegion] = []
_BY_PROVIDER: Dict[str, List[CloudRegion]] = {}
_DOCS = {
    "aws": "https://aws.amazon.com/about-aws/global-infrastructure/regions_az/",
    "gcp": "https://cloud.google.com/about/locations",
    "azure": "https://datacenters.microsoft.com/globe/explore/",
    "oracle": "https://www.oracle.com/cloud/public-cloud-regions/",
    "cloudflare": "https://www.cloudflare.com/network/",
    "digitalocean": "https://docs.digitalocean.com/platform/regional-availability/",
    "linode": "https://www.linode.com/global-infrastructure/",
    "vultr": "https://www.vultr.com/features/datacenter-locations/",
}


def _build() -> None:
    if _REGIONS:
        return
    for (provider, code, city, cc, lat, lon) in _ROWS:
        reg = CloudRegion(
            name=f"{provider}:{code}", provider=provider, region_code=code,
            city=city, country_code=cc,
            coordinate=Coordinate(lat, lon, precision=2, source="cloud-docs"),
            source="cloud-provider-docs", source_url=_DOCS.get(provider, ""))
        _REGIONS.append(reg)
        _BY_PROVIDER.setdefault(provider, []).append(reg)


def all_regions() -> List[CloudRegion]:
    _build()
    return list(_REGIONS)


def by_provider(provider: str) -> List[CloudRegion]:
    _build()
    return list(_BY_PROVIDER.get((provider or "").strip().lower(), []))


def by_code(code: str) -> Optional[CloudRegion]:
    _build()
    c = (code or "").strip().lower()
    for r in _REGIONS:
        if r.region_code.lower() == c:
            return r
    return None


def providers() -> List[str]:
    _build()
    return sorted(_BY_PROVIDER)
