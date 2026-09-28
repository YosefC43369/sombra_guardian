"""
geo_osint.data.seaports — a curated public-domain table of major world seaports.

Real, well-known ports with public coordinates (the port/terminal area), country
and a coarse type. Used for offline seaport intelligence and proximity. Coordinates
are the port area at ~2 decimals; not exhaustive (there are thousands of ports) but
every row is a public fact and the seaport engine can be extended at runtime from
OSM (``harbour``/``industrial=port`` tags) or public port authority data.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..models.coordinate import Coordinate

# (name, country_code, lat, lon, type, unlocode)
_ROWS = [
    ("Port of Shanghai", "CN", 31.34, 121.65, "container", "CNSHA"),
    ("Port of Singapore", "SG", 1.26, 103.82, "container", "SGSIN"),
    ("Port of Ningbo-Zhoushan", "CN", 29.87, 121.55, "container", "CNNBO"),
    ("Port of Shenzhen", "CN", 22.50, 113.90, "container", "CNSZN"),
    ("Port of Guangzhou", "CN", 23.10, 113.40, "container", "CNGZG"),
    ("Port of Busan", "KR", 35.10, 129.05, "container", "KRPUS"),
    ("Port of Hong Kong", "HK", 22.32, 114.13, "container", "HKHKG"),
    ("Port of Qingdao", "CN", 36.09, 120.30, "container", "CNTAO"),
    ("Port of Rotterdam", "NL", 51.95, 4.14, "container", "NLRTM"),
    ("Port of Antwerp", "BE", 51.28, 4.32, "container", "BEANR"),
    ("Port of Hamburg", "DE", 53.53, 9.93, "container", "DEHAM"),
    ("Port of Los Angeles", "US", 33.74, -118.26, "container", "USLAX"),
    ("Port of Long Beach", "US", 33.75, -118.20, "container", "USLGB"),
    ("Port of New York and New Jersey", "US", 40.66, -74.05, "container", "USNYC"),
    ("Port Klang", "MY", 3.00, 101.39, "container", "MYPKG"),
    ("Tanjung Pelepas", "MY", 1.36, 103.55, "container", "MYTPP"),
    ("Laem Chabang", "TH", 13.08, 100.88, "container", "THLCH"),
    ("Bangkok Port (Khlong Toei)", "TH", 13.70, 100.57, "passenger", "THBKK"),
    ("Jebel Ali (Dubai)", "AE", 25.01, 55.06, "container", "AEJEA"),
    ("Port of Piraeus", "GR", 37.94, 23.63, "container", "GRPIR"),
    ("Port of Colombo", "LK", 6.95, 79.84, "container", "LKCMB"),
    ("Port of Valencia", "ES", 39.44, -0.32, "container", "ESVLC"),
    ("Port of Algeciras", "ES", 36.13, -5.44, "container", "ESALG"),
    ("Port of Tanjung Priok (Jakarta)", "ID", -6.10, 106.88, "container", "IDJKT"),
    ("Port of Santos", "BR", -23.96, -46.30, "container", "BRSSZ"),
    ("Port of Salalah", "OM", 16.94, 54.00, "container", "OMSLL"),
    ("Port Said", "EG", 31.25, 32.30, "container", "EGPSD"),
    ("Port of Felixstowe", "GB", 51.95, 1.31, "container", "GBFXT"),
    ("Port of Yokohama", "JP", 35.45, 139.66, "container", "JPYOK"),
    ("Port of Kaohsiung", "TW", 22.61, 120.28, "container", "TWKHH"),
]

_PORTS: List[Dict] = []
_BY_COUNTRY: Dict[str, List[Dict]] = {}


def _build() -> None:
    if _PORTS:
        return
    for (name, cc, lat, lon, ptype, unlocode) in _ROWS:
        rec = {"name": name, "country_code": cc,
               "coordinate": Coordinate(lat, lon, precision=2, source="curated:port"),
               "type": ptype, "unlocode": unlocode}
        _PORTS.append(rec)
        _BY_COUNTRY.setdefault(cc, []).append(rec)


def all_ports() -> List[Dict]:
    _build()
    return list(_PORTS)


def by_country(country_code: str) -> List[Dict]:
    _build()
    return list(_BY_COUNTRY.get((country_code or "").strip().upper(), []))
