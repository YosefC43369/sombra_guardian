"""
geo_osint.models.coordinate — the WGS84 coordinate primitive and the exact,
dependency-free math that surrounds it.

WHY THIS EXISTS
---------------
Every geographic observation in the engine reduces to a point (or a set of
points) on the WGS84 ellipsoid. If coordinates are handled loosely — mixed
formats, lost precision, silent axis swaps — every downstream conclusion
(distance, proximity, clustering, correlation) inherits the error. This module
is the single, audited place where a coordinate is:

  * validated (latitude in [-90, 90], longitude normalised to [-180, 180]),
  * carried with an explicit *precision* (how many decimals are real — never
    invented), and
  * converted between the formats an OSINT analyst actually meets in public
    sources: Decimal Degrees, DMS, UTM, MGRS, Open Location Code (plus codes),
    WKT ``POINT`` and GeoJSON ``Point``.

DESIGN RULES (enforced here, relied on everywhere else)
-------------------------------------------------------
  * **WGS84 internally, always.** Parsers convert *into* WGS84 decimal degrees;
    formatters convert *out*. Nothing else in the package speaks another datum.
  * **Never invent precision.** :class:`Coordinate` records ``precision`` — the
    number of significant decimal places the source actually provided. A city
    centroid known to 0.01° must not masquerade as a rooftop-accurate fix. The
    reverse geocoder and evidence model read this field.
  * **Pure stdlib.** Only :mod:`math`. No numpy, no pyproj — the UTM/MGRS/OLC
    math is implemented from the published, public specifications so the whole
    module is unit-testable with zero third-party dependencies, exactly like the
    rest of ``geo_osint``.

The algorithms are the standard public ones: the transverse-Mercator series for
UTM (Karney / USGS coefficients truncated to sub-millimetre terms), the NGA
MGRS grid-square lettering, Google's Open Location Code, and the Haversine and
Vincenty-inverse formulae for distance. Sources are cited inline at each block.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "Coordinate",
    "WGS84_A",
    "WGS84_F",
    "haversine_km",
    "geodesic_km",
    "initial_bearing_deg",
    "destination_point",
    "parse_dms",
    "format_dms",
    "latlon_to_utm",
    "utm_to_latlon",
    "latlon_to_mgrs",
    "mgrs_to_latlon",
    "encode_plus_code",
    "decode_plus_code",
    "parse_wkt_point",
    "CoordinateParseError",
]

# ---------------------------------------------------------------------------
# WGS84 ellipsoid constants (the datum the whole engine standardises on).
# ---------------------------------------------------------------------------
WGS84_A = 6378137.0                     # semi-major axis, metres
WGS84_F = 1.0 / 298.257223563           # flattening
WGS84_B = WGS84_A * (1.0 - WGS84_F)     # semi-minor axis
WGS84_E2 = WGS84_F * (2.0 - WGS84_F)    # first eccentricity squared
WGS84_EP2 = WGS84_E2 / (1.0 - WGS84_E2)  # second eccentricity squared
_MEAN_EARTH_RADIUS_KM = 6371.0088       # IUGG mean radius, for Haversine


class CoordinateParseError(ValueError):
    """Raised when a textual coordinate cannot be parsed into WGS84."""


def _clamp_lat(lat: float) -> float:
    return max(-90.0, min(90.0, lat))


def _wrap_lon(lon: float) -> float:
    """Normalise any longitude into the half-open range (-180, 180]."""
    lon = math.fmod(lon, 360.0)
    if lon > 180.0:
        lon -= 360.0
    elif lon <= -180.0:
        lon += 360.0
    return lon


def _decimals(value: float) -> int:
    """Count the significant decimal places in a float's shortest repr.

    Used to *infer* precision when a caller supplies a raw float without an
    explicit precision. ``13.7563`` -> 4. Never over-reports beyond 12.
    """
    text = repr(float(value))
    if "e" in text or "E" in text:      # scientific notation -> treat as high
        return 12
    if "." not in text:
        return 0
    return min(12, len(text.split(".", 1)[1].rstrip("0")))


@dataclass(frozen=True)
class Coordinate:
    """A single WGS84 point with explicit, never-invented precision.

    ``precision`` is the count of *real* decimal places behind the latitude and
    longitude — the resolution the source actually asserted. It drives the
    ``coordinate_precision`` field of an observation and the honesty of every
    reverse-geocoding and distance statement made about the point.

    ``precision_m`` is a convenience: a coarse metres-on-the-ground estimate of
    that decimal resolution near the equator (1e-4° ~= 11 m). It is an *upper
    bound on confidence*, not a measurement.
    """

    latitude: float
    longitude: float
    precision: int = -1                 # decimals; -1 => infer from the values
    altitude_m: Optional[float] = None
    source: str = ""
    meta: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        lat = float(self.latitude)
        lon = float(self.longitude)
        if math.isnan(lat) or math.isnan(lon):
            raise CoordinateParseError("latitude/longitude is NaN")
        if not (-90.0 <= lat <= 90.0):
            raise CoordinateParseError(f"latitude {lat} out of range [-90, 90]")
        # Longitude is wrapped rather than rejected: 190° is a legal way to
        # write 170°W and appears in real feeds.
        object.__setattr__(self, "latitude", lat)
        object.__setattr__(self, "longitude", _wrap_lon(lon))
        if self.precision is None or self.precision < 0:
            inferred = max(_decimals(lat), _decimals(lon))
            object.__setattr__(self, "precision", inferred)

    # -- basic accessors ---------------------------------------------------
    @property
    def lat(self) -> float:
        return self.latitude

    @property
    def lon(self) -> float:
        return self.longitude

    @property
    def precision_m(self) -> float:
        """Coarse ground resolution implied by ``precision`` (metres)."""
        # One degree of latitude ~= 111_320 m; each decimal place divides by 10.
        return 111_320.0 / (10.0 ** max(0, self.precision))

    @property
    def is_null_island(self) -> bool:
        """(0, 0) is almost always a geocoding failure, not a real fix."""
        return abs(self.latitude) < 1e-9 and abs(self.longitude) < 1e-9

    def rounded(self, decimals: Optional[int] = None) -> Tuple[float, float]:
        """Return (lat, lon) rounded to ``decimals`` (default: real precision)."""
        d = self.precision if decimals is None else decimals
        d = max(0, min(12, d))
        return (round(self.latitude, d), round(self.longitude, d))

    # -- format conversions (out of WGS84) --------------------------------
    def to_dict(self) -> Dict[str, object]:
        out: Dict[str, object] = {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "precision": self.precision,
            "precision_m": round(self.precision_m, 3),
        }
        if self.altitude_m is not None:
            out["altitude_m"] = self.altitude_m
        if self.source:
            out["source"] = self.source
        if self.meta:
            out["meta"] = dict(self.meta)
        return out

    def to_geojson(self) -> Dict[str, object]:
        """RFC 7946 Point. GeoJSON axis order is [longitude, latitude]."""
        coords: List[float] = [round(self.longitude, 7), round(self.latitude, 7)]
        if self.altitude_m is not None:
            coords.append(float(self.altitude_m))
        return {"type": "Point", "coordinates": coords}

    def to_wkt(self) -> str:
        """OGC Well-Known Text. WKT axis order is (longitude latitude)."""
        return f"POINT ({self.longitude:.7f} {self.latitude:.7f})"

    def to_dms(self, seconds_decimals: int = 2) -> str:
        return format_dms(self.latitude, self.longitude, seconds_decimals)

    def to_utm(self) -> "UTMRef":
        return latlon_to_utm(self.latitude, self.longitude)

    def to_mgrs(self, precision: int = 5) -> str:
        return latlon_to_mgrs(self.latitude, self.longitude, precision)

    def to_plus_code(self, code_length: int = 10) -> str:
        return encode_plus_code(self.latitude, self.longitude, code_length)

    # -- geometry ----------------------------------------------------------
    def distance_km(self, other: "Coordinate", *, method: str = "geodesic") -> float:
        if method == "haversine":
            return haversine_km(self.latitude, self.longitude,
                                other.latitude, other.longitude)
        return geodesic_km(self.latitude, self.longitude,
                           other.latitude, other.longitude)

    def bearing_to(self, other: "Coordinate") -> float:
        return initial_bearing_deg(self.latitude, self.longitude,
                                   other.latitude, other.longitude)

    # -- constructors (into WGS84) ----------------------------------------
    @classmethod
    def from_any(cls, value: object, *, source: str = "") -> "Coordinate":
        """Best-effort parse of the coordinate shapes seen in public data.

        Accepts: an existing :class:`Coordinate`; ``(lat, lon)`` tuples/lists;
        ``{"lat":..,"lon":..}`` / ``{"latitude":..,"longitude":..}`` dicts;
        GeoJSON Point dicts; WKT ``POINT`` strings; ``"lat, lon"`` decimal
        strings; DMS strings; MGRS; and Open Location Codes.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, (tuple, list)) and len(value) >= 2:
            return cls(float(value[0]), float(value[1]), source=source)
        if isinstance(value, dict):
            return cls._from_dict(value, source=source)
        if isinstance(value, str):
            return cls.from_string(value, source=source)
        raise CoordinateParseError(f"cannot interpret {type(value).__name__} as a coordinate")

    @classmethod
    def _from_dict(cls, d: Dict[str, object], *, source: str = "") -> "Coordinate":
        if d.get("type") == "Point" and isinstance(d.get("coordinates"), (list, tuple)):
            lon, lat = float(d["coordinates"][0]), float(d["coordinates"][1])
            alt = float(d["coordinates"][2]) if len(d["coordinates"]) > 2 else None
            return cls(lat, lon, altitude_m=alt, source=source or "geojson")
        lat = d.get("latitude", d.get("lat"))
        lon = d.get("longitude", d.get("lon", d.get("lng", d.get("long"))))
        if lat is None or lon is None:
            raise CoordinateParseError("dict has no lat/lon keys")
        prec = d.get("precision")
        return cls(float(lat), float(lon),
                   precision=int(prec) if prec is not None else -1,
                   source=source or str(d.get("source", "")))

    @classmethod
    def from_string(cls, text: str, *, source: str = "") -> "Coordinate":
        """Parse the common textual coordinate encodings, tried in order."""
        s = (text or "").strip()
        if not s:
            raise CoordinateParseError("empty coordinate string")
        upper = s.upper()

        # WKT POINT
        if upper.startswith("POINT"):
            lat, lon = parse_wkt_point(s)
            return cls(lat, lon, source=source or "wkt")

        # Open Location Code (contains '+', 8-11 base-20 chars)
        if "+" in s and _looks_like_plus_code(s):
            lat, lon = decode_plus_code(s)
            return cls(lat, lon, source=source or "plus_code")

        # MGRS (starts with 1-2 digits + band letter + two square letters)
        if _looks_like_mgrs(upper):
            lat, lon = mgrs_to_latlon(upper)
            return cls(lat, lon, source=source or "mgrs")

        # DMS (contains N/S/E/W or degree/minute marks)
        if re.search(r"[NSEWnsew°'\"]", s):
            lat, lon = parse_dms(s)
            return cls(lat, lon, source=source or "dms")

        # Plain "lat, lon" or "lat lon"
        parts = re.split(r"[,\s]+", s)
        nums = [p for p in parts if p not in ("",)]
        if len(nums) >= 2:
            try:
                lat = float(nums[0])
                lon = float(nums[1])
            except ValueError as exc:
                raise CoordinateParseError(f"not a decimal pair: {s!r}") from exc
            prec = max(_decimals(lat), _decimals(lon))
            return cls(lat, lon, precision=prec, source=source or "decimal")
        raise CoordinateParseError(f"unrecognised coordinate format: {s!r}")


# ===========================================================================
# Distance / bearing (public formulae)
# ===========================================================================
def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance on a sphere (fast; ~0.5% error vs the ellipsoid)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * _MEAN_EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def geodesic_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Vincenty inverse solution on the WGS84 ellipsoid (millimetre accuracy).

    Falls back to Haversine for the near-antipodal case where Vincenty fails to
    converge, so the function always returns a usable distance.
    """
    if abs(lat1 - lat2) < 1e-12 and abs(lon1 - lon2) < 1e-12:
        return 0.0
    a, f, b = WGS84_A, WGS84_F, WGS84_B
    L = math.radians(lon2 - lon1)
    U1 = math.atan((1 - f) * math.tan(math.radians(lat1)))
    U2 = math.atan((1 - f) * math.tan(math.radians(lat2)))
    sinU1, cosU1 = math.sin(U1), math.cos(U1)
    sinU2, cosU2 = math.sin(U2), math.cos(U2)
    lam = L
    for _ in range(200):
        sin_lam, cos_lam = math.sin(lam), math.cos(lam)
        sin_sigma = math.sqrt((cosU2 * sin_lam) ** 2
                              + (cosU1 * sinU2 - sinU1 * cosU2 * cos_lam) ** 2)
        if sin_sigma == 0:
            return 0.0
        cos_sigma = sinU1 * sinU2 + cosU1 * cosU2 * cos_lam
        sigma = math.atan2(sin_sigma, cos_sigma)
        sin_alpha = cosU1 * cosU2 * sin_lam / sin_sigma
        cos2_alpha = 1 - sin_alpha ** 2
        cos_2sigma_m = (cos_sigma - 2 * sinU1 * sinU2 / cos2_alpha
                        if cos2_alpha != 0 else 0.0)
        C = f / 16 * cos2_alpha * (4 + f * (4 - 3 * cos2_alpha))
        lam_prev = lam
        lam = L + (1 - C) * f * sin_alpha * (
            sigma + C * sin_sigma * (cos_2sigma_m + C * cos_sigma
                                     * (-1 + 2 * cos_2sigma_m ** 2)))
        if abs(lam - lam_prev) < 1e-12:
            break
    else:
        return haversine_km(lat1, lon1, lat2, lon2)   # antipodal fallback
    u2 = cos2_alpha * WGS84_EP2
    A = 1 + u2 / 16384 * (4096 + u2 * (-768 + u2 * (320 - 175 * u2)))
    B = u2 / 1024 * (256 + u2 * (-128 + u2 * (74 - 47 * u2)))
    delta_sigma = B * sin_sigma * (cos_2sigma_m + B / 4 * (
        cos_sigma * (-1 + 2 * cos_2sigma_m ** 2)
        - B / 6 * cos_2sigma_m * (-3 + 4 * sin_sigma ** 2)
        * (-3 + 4 * cos_2sigma_m ** 2)))
    return (b * A * (sigma - delta_sigma)) / 1000.0


def initial_bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Forward azimuth from point 1 to point 2, degrees clockwise from north."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def destination_point(lat: float, lon: float, bearing_deg: float,
                      distance_km: float) -> Tuple[float, float]:
    """Point reached from (lat, lon) travelling ``distance_km`` on ``bearing``."""
    d_r = distance_km / _MEAN_EARTH_RADIUS_KM
    br = math.radians(bearing_deg)
    p1 = math.radians(lat)
    l1 = math.radians(lon)
    p2 = math.asin(math.sin(p1) * math.cos(d_r)
                   + math.cos(p1) * math.sin(d_r) * math.cos(br))
    l2 = l1 + math.atan2(math.sin(br) * math.sin(d_r) * math.cos(p1),
                         math.cos(d_r) - math.sin(p1) * math.sin(p2))
    return (_clamp_lat(math.degrees(p2)), _wrap_lon(math.degrees(l2)))


# ===========================================================================
# DMS  (degrees / minutes / seconds)
# ===========================================================================
_DMS_TOKEN = re.compile(
    r"""(?P<deg>[-+]?\d+(?:\.\d+)?)\s*[°d:\s]\s*
        (?:(?P<min>\d+(?:\.\d+)?)\s*['m:\s]\s*)?
        (?:(?P<sec>\d+(?:\.\d+)?)\s*(?:["s]?)\s*)?
        (?P<hemi>[NSEWnsew])?""",
    re.VERBOSE,
)


def _dms_component(match: "re.Match[str]") -> Tuple[float, Optional[str]]:
    deg = float(match.group("deg"))
    minutes = float(match.group("min")) if match.group("min") else 0.0
    seconds = float(match.group("sec")) if match.group("sec") else 0.0
    sign = -1.0 if deg < 0 else 1.0
    value = abs(deg) + minutes / 60.0 + seconds / 3600.0
    hemi = match.group("hemi")
    if hemi:
        hemi = hemi.upper()
        if hemi in ("S", "W"):
            sign = -1.0
        else:
            sign = 1.0
    return sign * value, (hemi.upper() if hemi else None)


def parse_dms(text: str) -> Tuple[float, float]:
    """Parse a DMS latitude/longitude pair into decimal degrees.

    Handles the messy real forms: ``13°45'12.3"N 100°30'00"E``,
    ``13 45 12N, 100 30 00E``, ``N13.7 E100.5``, hemisphere before or after.
    """
    matches = [m for m in _DMS_TOKEN.finditer(text) if m.group("deg") is not None
               and (m.group(0).strip())]
    comps: List[Tuple[float, Optional[str]]] = []
    for m in matches:
        if not m.group(0).strip():
            continue
        comps.append(_dms_component(m))
    if len(comps) < 2:
        raise CoordinateParseError(f"need two DMS components, got {len(comps)}: {text!r}")
    lat = lon = None
    for value, hemi in comps[:2] if len(comps) == 2 else comps:
        if hemi in ("N", "S") and lat is None:
            lat = value
        elif hemi in ("E", "W") and lon is None:
            lon = value
    if lat is None or lon is None:
        (v1, _), (v2, _) = comps[0], comps[1]        # positional fallback
        lat = lat if lat is not None else v1
        lon = lon if lon is not None else v2
    if not (-90.0 <= lat <= 90.0):
        raise CoordinateParseError(f"DMS latitude {lat} out of range")
    return lat, _wrap_lon(lon)


def format_dms(lat: float, lon: float, seconds_decimals: int = 2) -> str:
    def one(value: float, positive: str, negative: str) -> str:
        hemi = positive if value >= 0 else negative
        value = abs(value)
        deg = int(value)
        rem = (value - deg) * 60
        minutes = int(rem)
        seconds = (rem - minutes) * 60
        return f"{deg}°{minutes:02d}'{seconds:0{seconds_decimals + 3}.{seconds_decimals}f}\"{hemi}"
    return f"{one(lat, 'N', 'S')} {one(lon, 'E', 'W')}"


# ===========================================================================
# UTM  (Universal Transverse Mercator, WGS84)
# ===========================================================================
@dataclass(frozen=True)
class UTMRef:
    zone: int
    hemisphere: str          # 'N' or 'S'
    easting: float
    northing: float

    def __str__(self) -> str:
        return f"{self.zone}{self.hemisphere} {self.easting:.1f}E {self.northing:.1f}N"

    def to_dict(self) -> Dict[str, object]:
        return {"zone": self.zone, "hemisphere": self.hemisphere,
                "easting": round(self.easting, 3), "northing": round(self.northing, 3)}


_UTM_K0 = 0.9996
_UTM_FALSE_EASTING = 500000.0
_UTM_FALSE_NORTHING = 10000000.0     # for the southern hemisphere


def _utm_zone(lat: float, lon: float) -> int:
    """Standard UTM zone, including the Norway/Svalbard exceptions."""
    zone = int((lon + 180) / 6) + 1
    if 56.0 <= lat < 64.0 and 3.0 <= lon < 12.0:
        return 32
    if 72.0 <= lat < 84.0:
        if 0.0 <= lon < 9.0:
            return 31
        if 9.0 <= lon < 21.0:
            return 33
        if 21.0 <= lon < 33.0:
            return 35
        if 33.0 <= lon < 42.0:
            return 37
    return max(1, min(60, zone))


def latlon_to_utm(lat: float, lon: float) -> UTMRef:
    """Forward projection using the Karney/USGS series (sub-mm accuracy)."""
    if not (-80.0 <= lat <= 84.0):
        raise CoordinateParseError(f"UTM undefined for latitude {lat} (use UPS)")
    zone = _utm_zone(lat, lon)
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    phi = math.radians(lat)
    lam = math.radians(lon) - lon0
    n = WGS84_F / (2 - WGS84_F)
    n2, n3, n4 = n * n, n ** 3, n ** 4
    A = (WGS84_A / (1 + n)) * (1 + n2 / 4 + n4 / 64)
    alpha = [
        n / 2 - 2 / 3 * n2 + 5 / 16 * n3,
        13 / 48 * n2 - 3 / 5 * n3,
        61 / 240 * n3,
    ]
    t = math.sinh(math.atanh(math.sin(phi))
                  - 2 * math.sqrt(n) / (1 + n) * math.atanh(2 * math.sqrt(n) / (1 + n) * math.sin(phi)))
    xi_prime = math.atan2(t, math.cos(lam))
    eta_prime = math.asinh(math.sin(lam) / math.hypot(t, math.cos(lam)))
    xi = xi_prime + sum(alpha[j] * math.sin(2 * (j + 1) * xi_prime)
                        * math.cosh(2 * (j + 1) * eta_prime) for j in range(3))
    eta = eta_prime + sum(alpha[j] * math.cos(2 * (j + 1) * xi_prime)
                          * math.sinh(2 * (j + 1) * eta_prime) for j in range(3))
    easting = _UTM_K0 * A * eta + _UTM_FALSE_EASTING
    northing = _UTM_K0 * A * xi
    hemi = "N"
    if lat < 0:
        northing += _UTM_FALSE_NORTHING
        hemi = "S"
    return UTMRef(zone=zone, hemisphere=hemi, easting=easting, northing=northing)


def utm_to_latlon(zone: int, hemisphere: str, easting: float,
                  northing: float) -> Tuple[float, float]:
    """Inverse projection (Karney/USGS series)."""
    hemisphere = hemisphere.upper()
    n = WGS84_F / (2 - WGS84_F)
    n2, n3, n4 = n * n, n ** 3, n ** 4
    A = (WGS84_A / (1 + n)) * (1 + n2 / 4 + n4 / 64)
    beta = [
        n / 2 - 2 / 3 * n2 + 37 / 96 * n3,
        1 / 48 * n2 + 1 / 15 * n3,
        17 / 480 * n3,
    ]
    delta = [
        2 * n - 2 / 3 * n2 - 2 * n3,
        7 / 3 * n2 - 8 / 5 * n3,
        56 / 15 * n3,
    ]
    x = easting - _UTM_FALSE_EASTING
    y = northing - (_UTM_FALSE_NORTHING if hemisphere == "S" else 0.0)
    xi = y / (_UTM_K0 * A)
    eta = x / (_UTM_K0 * A)
    xi_prime = xi - sum(beta[j] * math.sin(2 * (j + 1) * xi)
                        * math.cosh(2 * (j + 1) * eta) for j in range(3))
    eta_prime = eta - sum(beta[j] * math.cos(2 * (j + 1) * xi)
                          * math.sinh(2 * (j + 1) * eta) for j in range(3))
    chi = math.asin(math.sin(xi_prime) / math.cosh(eta_prime))
    lat = chi + sum(delta[j] * math.sin(2 * (j + 1) * chi) for j in range(3))
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    lon = lon0 + math.atan2(math.sinh(eta_prime), math.cos(xi_prime))
    return (math.degrees(lat), _wrap_lon(math.degrees(lon)))


# ===========================================================================
# MGRS  (Military Grid Reference System — parsing/conversion only)
# ===========================================================================
_MGRS_BANDS = "CDEFGHJKLMNPQRSTUVWX"          # latitude bands 80S..84N (no I/O)
_MGRS_E_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"   # 100km easting letters (no I,O)
_MGRS_N_LETTERS = "ABCDEFGHJKLMNPQRSTUV"       # 100km northing letters (no I,O)
_MGRS_RE = re.compile(r"^(\d{1,2})([C-HJ-NP-X])\s*([A-HJ-NP-Z])([A-HJ-NP-V])\s*(\d*)$")


def _lat_band(lat: float) -> str:
    idx = int((lat + 80) / 8)
    idx = max(0, min(len(_MGRS_BANDS) - 1, idx))
    return _MGRS_BANDS[idx]


def latlon_to_mgrs(lat: float, lon: float, precision: int = 5) -> str:
    """Convert WGS84 to an MGRS string. ``precision`` = digits per axis (1..5)."""
    precision = max(1, min(5, precision))
    utm = latlon_to_utm(lat, lon)
    band = _lat_band(lat)
    e100 = int(utm.easting // 100000)
    n100 = int(utm.northing // 100000)
    # Easting letter set repeats every 3 zones (A-H, J-R, S-Z).
    e_idx = (e100 - 1) % 24 + (utm.zone - 1) % 3 * 8
    e_letter = _MGRS_E_LETTERS[e_idx % 24]
    # Northing letters shift by 5 on even zones.
    n_shift = 0 if utm.zone % 2 == 1 else 5
    n_letter = _MGRS_N_LETTERS[(n100 + n_shift) % 20]
    scale = 10 ** (5 - precision)
    east = int((utm.easting % 100000) // scale)
    north = int((utm.northing % 100000) // scale)
    return (f"{utm.zone}{band}{e_letter}{n_letter}"
            f"{east:0{precision}d}{north:0{precision}d}")


def mgrs_to_latlon(mgrs: str) -> Tuple[float, float]:
    """Convert an MGRS string back to WGS84 (centre of the referenced square)."""
    s = re.sub(r"\s+", "", mgrs.upper())
    m = _MGRS_RE.match(s)
    if not m:
        raise CoordinateParseError(f"not a valid MGRS reference: {mgrs!r}")
    zone = int(m.group(1))
    band = m.group(2)
    e_letter, n_letter = m.group(3), m.group(4)
    digits = m.group(5)
    if len(digits) % 2 != 0:
        raise CoordinateParseError(f"MGRS numeric part must have even length: {digits!r}")
    half = len(digits) // 2
    scale = 10 ** (5 - half) if half else 100000
    east_frac = int(digits[:half]) * scale if half else 0
    north_frac = int(digits[half:]) * scale if half else 0
    # Reconstruct 100km square origin.
    e_idx = _MGRS_E_LETTERS.index(e_letter) - (zone - 1) % 3 * 8
    e100 = (e_idx % 24) + 1
    easting = e100 * 100000 + east_frac + (scale / 2 if half < 5 else 0)
    n_shift = 0 if zone % 2 == 1 else 5
    n_base = (_MGRS_N_LETTERS.index(n_letter) - n_shift) % 20
    # Find the northing band consistent with the latitude band.
    band_lat = (_MGRS_BANDS.index(band) * 8) - 80
    approx_northing = _approx_northing_for_lat(band_lat, zone)
    n100 = n_base
    while n100 * 100000 < approx_northing - 1000000:
        n100 += 20
    northing = n100 * 100000 + north_frac + (scale / 2 if half < 5 else 0)
    hemi = "N" if band >= "N" else "S"
    lat, lon = utm_to_latlon(zone, hemi, easting, northing)
    return lat, lon


def _approx_northing_for_lat(lat: float, zone: int) -> float:
    lon0 = (zone - 1) * 6 - 180 + 3
    try:
        return latlon_to_utm(lat, lon0).northing
    except CoordinateParseError:
        return 0.0


def _looks_like_mgrs(upper: str) -> bool:
    return bool(_MGRS_RE.match(re.sub(r"\s+", "", upper)))


# ===========================================================================
# Open Location Code  (Google plus codes)
# ===========================================================================
_OLC_ALPHABET = "23456789CFGHJMPQRVWX"
_OLC_BASE = 20
_OLC_SEP = "+"
_OLC_SEP_POS = 8
_OLC_PADDING = "0"
_OLC_PAIR_RES = [20.0, 1.0, 0.05, 0.0025, 0.000125]     # degrees per pair step


def encode_plus_code(lat: float, lon: float, code_length: int = 10) -> str:
    """Encode WGS84 to an Open Location Code (default 10 chars ~= 14x14 m)."""
    if code_length < 2 or (code_length < _OLC_SEP_POS and code_length % 2 == 1):
        raise CoordinateParseError(f"invalid OLC length {code_length}")
    code_length = min(15, code_length)
    lat = max(-90.0, min(90.0, lat))
    if lat == 90.0:
        lat = 89.9999999
    return _olc_pairs(lat, _wrap_lon(lon), code_length)


def _olc_pairs(lat: float, lon: float, code_length: int) -> str:
    digits = ""
    lat_adj = lat + 90.0
    lon_adj = _wrap_lon(lon) + 180.0
    resolution = 20.0
    pairs = min(code_length, 10) // 2
    for _ in range(pairs):
        lat_i = int(lat_adj / resolution)
        lat_i = min(_OLC_BASE - 1, lat_i)
        lon_i = int(lon_adj / resolution)
        lon_i = min(_OLC_BASE - 1, lon_i)
        digits += _OLC_ALPHABET[lat_i]
        digits += _OLC_ALPHABET[lon_i]
        lat_adj -= lat_i * resolution
        lon_adj -= lon_i * resolution
        resolution /= _OLC_BASE
    grid = ""
    if code_length > 10:
        lat_grid = lat_adj
        lon_grid = lon_adj
        lat_res = resolution
        lon_res = resolution
        for _ in range(code_length - 10):
            lat_i = min(4, int(lat_grid / (lat_res / 5)))
            lon_i = min(3, int(lon_grid / (lon_res / 4)))
            grid += _OLC_ALPHABET[lat_i * 4 + lon_i]
            lat_grid -= lat_i * (lat_res / 5)
            lon_grid -= lon_i * (lon_res / 4)
            lat_res /= 5
            lon_res /= 4
    body = digits[:_OLC_SEP_POS] + _OLC_SEP + digits[_OLC_SEP_POS:] + grid
    return body


def decode_plus_code(code: str) -> Tuple[float, float]:
    """Decode an OLC to the centre of its cell (WGS84). Full codes only."""
    clean = code.replace(_OLC_SEP, "").upper().rstrip(_OLC_PADDING)
    if len(clean) < 2 or len(clean) % 2 != 0:
        raise CoordinateParseError(f"cannot decode short/padded OLC: {code!r}")
    lat = -90.0
    lon = -180.0
    resolution = 20.0
    idx = 0
    pair_count = min(len(clean), 10)
    while idx < pair_count:
        lat += _OLC_ALPHABET.index(clean[idx]) * resolution
        lon += _OLC_ALPHABET.index(clean[idx + 1]) * resolution
        resolution /= _OLC_BASE
        idx += 2
    # grid refinement
    lat_res = resolution * _OLC_BASE / 5    # last full pair resolution / 5
    lon_res = resolution * _OLC_BASE / 4
    lat_grid_res = 20.0 / (_OLC_BASE ** 4)
    lon_grid_res = lat_grid_res
    lat_p = lat_grid_res
    lon_p = lon_grid_res
    for gi in range(idx, len(clean)):
        v = _OLC_ALPHABET.index(clean[gi])
        row, col = divmod(v, 4)
        lat += row * (lat_p / 5)
        lon += col * (lon_p / 4)
        lat_p /= 5
        lon_p /= 4
    if len(clean) <= 10:
        lat += resolution * _OLC_BASE / 2
        lon += resolution * _OLC_BASE / 2
    else:
        lat += lat_p * 5 / 2
        lon += lon_p * 4 / 2
    return (_clamp_lat(lat), _wrap_lon(lon))


def _looks_like_plus_code(s: str) -> bool:
    body = s.strip().upper()
    if _OLC_SEP not in body:
        return False
    stripped = body.replace(_OLC_SEP, "").replace(_OLC_PADDING, "")
    return len(stripped) >= 2 and all(c in _OLC_ALPHABET for c in stripped)


# ===========================================================================
# WKT
# ===========================================================================
_WKT_POINT_RE = re.compile(
    r"POINT\s*Z?\s*\(\s*([-+]?\d+(?:\.\d+)?)\s+([-+]?\d+(?:\.\d+)?)",
    re.IGNORECASE)


def parse_wkt_point(text: str) -> Tuple[float, float]:
    """Parse ``POINT (lon lat)`` into WGS84 ``(lat, lon)`` (note axis order)."""
    m = _WKT_POINT_RE.search(text or "")
    if not m:
        raise CoordinateParseError(f"not a WKT POINT: {text!r}")
    lon, lat = float(m.group(1)), float(m.group(2))
    if not (-90.0 <= lat <= 90.0):
        raise CoordinateParseError(f"WKT latitude {lat} out of range")
    return lat, _wrap_lon(lon)
