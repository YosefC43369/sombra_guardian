"""
geo_osint.data.cities — a curated public-domain gazetteer of major places.

Real, well-known populated places with WGS84 coordinates and IANA timezones. It
powers *offline* geocoding, reverse geocoding (nearest-city) and the alias engine
without any network dependency. Capitals are derived from
:mod:`geo_osint.data.countries`; a curated set of major non-capital metros is
added here. Coordinates are city-centre points at ~2 decimals and are exposed
with that precision. Alternate/multilingual/historical names (e.g. Bangkok ↔
Krung Thep, Istanbul ↔ Constantinople) feed the alias engine (spec §33–34).

At runtime the GeoNames and Nominatim clients extend this gazetteer; nothing here
is invented — it is a finite table of public facts.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..models.city import City
from ..models.coordinate import Coordinate
from . import countries as _countries

# Representative IANA timezone per country (for capitals). Curated; a country may
# span several zones — this is the *capital's* zone, used as a labelled default.
CAPITAL_TZ: Dict[str, str] = {
    "TH": "Asia/Bangkok", "LA": "Asia/Vientiane", "KH": "Asia/Phnom_Penh",
    "VN": "Asia/Ho_Chi_Minh", "MY": "Asia/Kuala_Lumpur", "SG": "Asia/Singapore",
    "ID": "Asia/Jakarta", "PH": "Asia/Manila", "MM": "Asia/Yangon",
    "CN": "Asia/Shanghai", "HK": "Asia/Hong_Kong", "TW": "Asia/Taipei",
    "JP": "Asia/Tokyo", "KR": "Asia/Seoul", "KP": "Asia/Pyongyang",
    "IN": "Asia/Kolkata", "PK": "Asia/Karachi", "BD": "Asia/Dhaka",
    "NP": "Asia/Kathmandu", "LK": "Asia/Colombo", "MN": "Asia/Ulaanbaatar",
    "KZ": "Asia/Almaty", "UZ": "Asia/Tashkent", "AF": "Asia/Kabul",
    "IR": "Asia/Tehran", "IQ": "Asia/Baghdad", "SA": "Asia/Riyadh",
    "AE": "Asia/Dubai", "QA": "Asia/Qatar", "KW": "Asia/Kuwait",
    "BH": "Asia/Bahrain", "OM": "Asia/Muscat", "JO": "Asia/Amman",
    "LB": "Asia/Beirut", "SY": "Asia/Damascus", "IL": "Asia/Jerusalem",
    "TR": "Europe/Istanbul", "GE": "Asia/Tbilisi", "AM": "Asia/Yerevan",
    "AZ": "Asia/Baku", "BN": "Asia/Brunei",
    "RU": "Europe/Moscow", "UA": "Europe/Kiev", "BY": "Europe/Minsk",
    "PL": "Europe/Warsaw", "DE": "Europe/Berlin", "FR": "Europe/Paris",
    "GB": "Europe/London", "IE": "Europe/Dublin", "ES": "Europe/Madrid",
    "PT": "Europe/Lisbon", "IT": "Europe/Rome", "NL": "Europe/Amsterdam",
    "BE": "Europe/Brussels", "LU": "Europe/Luxembourg", "CH": "Europe/Zurich",
    "AT": "Europe/Vienna", "CZ": "Europe/Prague", "SK": "Europe/Bratislava",
    "HU": "Europe/Budapest", "RO": "Europe/Bucharest", "BG": "Europe/Sofia",
    "GR": "Europe/Athens", "HR": "Europe/Zagreb", "SI": "Europe/Ljubljana",
    "RS": "Europe/Belgrade", "BA": "Europe/Sarajevo", "AL": "Europe/Tirane",
    "MD": "Europe/Chisinau", "LT": "Europe/Vilnius", "LV": "Europe/Riga",
    "EE": "Europe/Tallinn", "FI": "Europe/Helsinki", "SE": "Europe/Stockholm",
    "NO": "Europe/Oslo", "DK": "Europe/Copenhagen", "IS": "Atlantic/Reykjavik",
    "CY": "Asia/Nicosia", "AD": "Europe/Andorra",
    "US": "America/New_York", "CA": "America/Toronto", "MX": "America/Mexico_City",
    "GT": "America/Guatemala", "HN": "America/Tegucigalpa", "CR": "America/Costa_Rica",
    "PA": "America/Panama", "CU": "America/Havana", "DO": "America/Santo_Domingo",
    "BR": "America/Sao_Paulo", "AR": "America/Argentina/Buenos_Aires",
    "CL": "America/Santiago", "CO": "America/Bogota", "PE": "America/Lima",
    "EC": "America/Guayaquil", "VE": "America/Caracas", "BO": "America/La_Paz",
    "PY": "America/Asuncion", "UY": "America/Montevideo",
    "AU": "Australia/Sydney", "NZ": "Pacific/Auckland",
    "EG": "Africa/Cairo", "MA": "Africa/Casablanca", "DZ": "Africa/Algiers",
    "TN": "Africa/Tunis", "LY": "Africa/Tripoli", "SD": "Africa/Khartoum",
    "NG": "Africa/Lagos", "GH": "Africa/Accra", "CI": "Africa/Abidjan",
    "SN": "Africa/Dakar", "BF": "Africa/Ouagadougou", "BJ": "Africa/Porto-Novo",
    "CM": "Africa/Douala", "CD": "Africa/Kinshasa", "AO": "Africa/Luanda",
    "KE": "Africa/Nairobi", "TZ": "Africa/Dar_es_Salaam", "UG": "Africa/Kampala",
    "ET": "Africa/Addis_Ababa", "ZA": "Africa/Johannesburg", "ZM": "Africa/Lusaka",
    "ZW": "Africa/Harare", "BW": "Africa/Gaborone",
}

# (name, cc, admin1, lat, lon, population, tz, feature_code, [alt names])
_METROS = [
    ("Chiang Mai", "TH", "Chiang Mai", 18.79, 98.98, 130000, "Asia/Bangkok", "PPLA", ["เชียงใหม่"]),
    ("Phuket", "TH", "Phuket", 7.88, 98.39, 90000, "Asia/Bangkok", "PPLA", ["ภูเก็ต"]),
    ("Pattaya", "TH", "Chon Buri", 12.93, 100.88, 120000, "Asia/Bangkok", "PPL", ["พัทยา"]),
    ("Nonthaburi", "TH", "Nonthaburi", 13.86, 100.51, 250000, "Asia/Bangkok", "PPLA", []),
    ("Hat Yai", "TH", "Songkhla", 7.01, 100.47, 160000, "Asia/Bangkok", "PPL", ["หาดใหญ่"]),
    ("New York", "US", "New York", 40.71, -74.01, 8400000, "America/New_York", "PPL", ["NYC"]),
    ("Los Angeles", "US", "California", 34.05, -118.24, 3900000, "America/Los_Angeles", "PPL", ["LA"]),
    ("Chicago", "US", "Illinois", 41.88, -87.63, 2700000, "America/Chicago", "PPL", []),
    ("San Francisco", "US", "California", 37.77, -122.42, 870000, "America/Los_Angeles", "PPL", ["SF"]),
    ("Seattle", "US", "Washington", 47.61, -122.33, 750000, "America/Los_Angeles", "PPL", []),
    ("Miami", "US", "Florida", 25.76, -80.19, 440000, "America/New_York", "PPL", []),
    ("Dallas", "US", "Texas", 32.78, -96.80, 1300000, "America/Chicago", "PPL", []),
    ("Ashburn", "US", "Virginia", 39.04, -77.49, 43000, "America/New_York", "PPL", ["Data Center Alley"]),
    ("Toronto", "CA", "Ontario", 43.65, -79.38, 2900000, "America/Toronto", "PPL", []),
    ("Vancouver", "CA", "British Columbia", 49.28, -123.12, 675000, "America/Vancouver", "PPL", []),
    ("Montreal", "CA", "Quebec", 45.50, -73.57, 1700000, "America/Toronto", "PPL", ["Montréal"]),
    ("São Paulo", "BR", "São Paulo", -23.55, -46.63, 12300000, "America/Sao_Paulo", "PPLA", ["Sao Paulo"]),
    ("Rio de Janeiro", "BR", "Rio de Janeiro", -22.91, -43.17, 6700000, "America/Sao_Paulo", "PPLA", ["Rio"]),
    ("Guadalajara", "MX", "Jalisco", 20.67, -103.35, 1500000, "America/Mexico_City", "PPLA", []),
    ("Manchester", "GB", "England", 53.48, -2.24, 550000, "Europe/London", "PPL", []),
    ("Birmingham", "GB", "England", 52.48, -1.90, 1100000, "Europe/London", "PPL", []),
    ("Edinburgh", "GB", "Scotland", 55.95, -3.19, 530000, "Europe/London", "PPLA", []),
    ("Frankfurt", "DE", "Hesse", 50.11, 8.68, 760000, "Europe/Berlin", "PPLA", ["Frankfurt am Main"]),
    ("Munich", "DE", "Bavaria", 48.14, 11.58, 1500000, "Europe/Berlin", "PPLA", ["München"]),
    ("Hamburg", "DE", "Hamburg", 53.55, 9.99, 1900000, "Europe/Berlin", "PPLA", []),
    ("Marseille", "FR", "Provence-Alpes-Côte d'Azur", 43.30, 5.37, 870000, "Europe/Paris", "PPLA", []),
    ("Lyon", "FR", "Auvergne-Rhône-Alpes", 45.76, 4.84, 520000, "Europe/Paris", "PPLA", []),
    ("Barcelona", "ES", "Catalonia", 41.39, 2.17, 1600000, "Europe/Madrid", "PPLA", []),
    ("Milan", "IT", "Lombardy", 45.46, 9.19, 1400000, "Europe/Rome", "PPLA", ["Milano"]),
    ("Rotterdam", "NL", "South Holland", 51.92, 4.48, 650000, "Europe/Amsterdam", "PPL", []),
    ("Saint Petersburg", "RU", "Saint Petersburg", 59.93, 30.34, 5400000, "Europe/Moscow", "PPLA", ["Leningrad", "Petrograd"]),
    ("Novosibirsk", "RU", "Novosibirsk Oblast", 55.01, 82.94, 1600000, "Asia/Novosibirsk", "PPLA", []),
    ("Istanbul", "TR", "Istanbul", 41.01, 28.98, 15500000, "Europe/Istanbul", "PPLA", ["Constantinople", "Byzantium"]),
    ("Izmir", "TR", "Izmir", 38.42, 27.14, 3000000, "Europe/Istanbul", "PPLA", ["Smyrna"]),
    ("Shanghai", "CN", "Shanghai", 31.23, 121.47, 24900000, "Asia/Shanghai", "PPLA", ["上海"]),
    ("Guangzhou", "CN", "Guangdong", 23.13, 113.26, 15300000, "Asia/Shanghai", "PPLA", ["广州", "Canton"]),
    ("Shenzhen", "CN", "Guangdong", 22.54, 114.06, 12500000, "Asia/Shanghai", "PPL", ["深圳"]),
    ("Chengdu", "CN", "Sichuan", 30.57, 104.07, 16300000, "Asia/Shanghai", "PPLA", ["成都"]),
    ("Osaka", "JP", "Osaka", 34.69, 135.50, 2700000, "Asia/Tokyo", "PPLA", ["大阪"]),
    ("Yokohama", "JP", "Kanagawa", 35.44, 139.64, 3700000, "Asia/Tokyo", "PPLA", ["横浜"]),
    ("Busan", "KR", "Busan", 35.18, 129.08, 3400000, "Asia/Seoul", "PPLA", ["부산", "Pusan"]),
    ("Mumbai", "IN", "Maharashtra", 19.08, 72.88, 12400000, "Asia/Kolkata", "PPLA", ["Bombay", "मुंबई"]),
    ("Bengaluru", "IN", "Karnataka", 12.97, 77.59, 8400000, "Asia/Kolkata", "PPLA", ["Bangalore", "ಬೆಂಗಳೂರು"]),
    ("Chennai", "IN", "Tamil Nadu", 13.08, 80.27, 7000000, "Asia/Kolkata", "PPLA", ["Madras"]),
    ("Kolkata", "IN", "West Bengal", 22.57, 88.36, 4500000, "Asia/Kolkata", "PPLA", ["Calcutta"]),
    ("Hyderabad", "IN", "Telangana", 17.39, 78.49, 6800000, "Asia/Kolkata", "PPLA", []),
    ("Karachi", "PK", "Sindh", 24.86, 67.01, 14900000, "Asia/Karachi", "PPLA", []),
    ("Lahore", "PK", "Punjab", 31.55, 74.34, 11100000, "Asia/Karachi", "PPLA", []),
    ("Ho Chi Minh City", "VN", "Ho Chi Minh", 10.82, 106.63, 8900000, "Asia/Ho_Chi_Minh", "PPLA", ["Saigon", "Sài Gòn"]),
    ("Da Nang", "VN", "Da Nang", 16.05, 108.20, 1100000, "Asia/Ho_Chi_Minh", "PPLA", ["Đà Nẵng"]),
    ("Cebu City", "PH", "Cebu", 10.32, 123.90, 950000, "Asia/Manila", "PPLA", []),
    ("Surabaya", "ID", "East Java", -7.26, 112.75, 2900000, "Asia/Jakarta", "PPLA", []),
    ("Bandung", "ID", "West Java", -6.91, 107.61, 2500000, "Asia/Jakarta", "PPLA", []),
    ("Dubai", "AE", "Dubai", 25.20, 55.27, 3300000, "Asia/Dubai", "PPLA", ["دبي"]),
    ("Jeddah", "SA", "Makkah", 21.49, 39.19, 4700000, "Asia/Riyadh", "PPLA", ["Jiddah"]),
    ("Tel Aviv", "IL", "Tel Aviv", 32.08, 34.78, 460000, "Asia/Jerusalem", "PPLA", ["Tel Aviv-Yafo"]),
    ("Casablanca", "MA", "Casablanca-Settat", 33.57, -7.59, 3400000, "Africa/Casablanca", "PPLA", ["الدار البيضاء"]),
    ("Alexandria", "EG", "Alexandria", 31.20, 29.92, 5200000, "Africa/Cairo", "PPLA", ["الإسكندرية"]),
    ("Lagos", "NG", "Lagos", 6.52, 3.38, 14800000, "Africa/Lagos", "PPLA", []),
    ("Cape Town", "ZA", "Western Cape", -33.92, 18.42, 4600000, "Africa/Johannesburg", "PPLA", []),
    ("Johannesburg", "ZA", "Gauteng", -26.20, 28.05, 5600000, "Africa/Johannesburg", "PPLA", ["Jozi"]),
    ("Durban", "ZA", "KwaZulu-Natal", -29.86, 31.02, 3400000, "Africa/Johannesburg", "PPLA", []),
    ("Melbourne", "AU", "Victoria", -37.81, 144.96, 5000000, "Australia/Melbourne", "PPLA", []),
    ("Sydney", "AU", "New South Wales", -33.87, 151.21, 5300000, "Australia/Sydney", "PPLA", []),
    ("Perth", "AU", "Western Australia", -31.95, 115.86, 2100000, "Australia/Perth", "PPLA", []),
    ("Auckland", "NZ", "Auckland", -36.85, 174.76, 1600000, "Pacific/Auckland", "PPLA", []),
]

_CITIES: List[City] = []
_BY_KEY: Dict[str, List[City]] = {}
_ALIASES: Dict[str, str] = {}    # lowered alias -> canonical city name


def _index(city: City) -> None:
    _CITIES.append(city)
    _BY_KEY.setdefault(city.name.lower(), []).append(city)
    for alt in city.alternate_names:
        _ALIASES.setdefault(alt.lower(), city.name)
        _BY_KEY.setdefault(alt.lower(), []).append(city)


def _build() -> None:
    if _CITIES:
        return
    # Capitals from the country table.
    for country in _countries.all_countries():
        if not country.capital or not country.centroid:
            continue
        tz = CAPITAL_TZ.get(country.iso2, "")
        _index(City(name=country.capital, coordinate=country.centroid,
                    country_code=country.iso2, admin1="", timezone=tz,
                    feature_code="PPLC", source="curated:capital"))
    # Major metros.
    for (name, cc, admin1, lat, lon, pop, tz, fcode, alts) in _METROS:
        _index(City(name=name,
                    coordinate=Coordinate(lat, lon, precision=2, source="curated:city"),
                    country_code=cc, admin1=admin1, timezone=tz, population=pop,
                    feature_code=fcode, alternate_names=list(alts),
                    source="curated:city"))
    # Bangkok's canonical alias pair (spec §34 worked example).
    _ALIASES.setdefault("krung thep", "Bangkok")
    _ALIASES.setdefault("krung thep maha nakhon", "Bangkok")
    _ALIASES.setdefault("กรุงเทพ", "Bangkok")
    _ALIASES.setdefault("กรุงเทพมหานคร", "Bangkok")


def all_cities() -> List[City]:
    _build()
    return list(_CITIES)


def find(name: str, country_code: str = "") -> List[City]:
    """Exact/alias lookup by name, optionally filtered by country."""
    _build()
    hits = list(_BY_KEY.get((name or "").strip().lower(), []))
    if country_code:
        cc = country_code.strip().upper()
        hits = [c for c in hits if c.country_code == cc]
    return hits


def canonical_name(alias: str) -> Optional[str]:
    _build()
    return _ALIASES.get((alias or "").strip().lower())


def aliases() -> Dict[str, str]:
    _build()
    return dict(_ALIASES)
