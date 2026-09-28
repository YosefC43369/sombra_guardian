"""
geo_osint.data.countries — a curated, verifiable public-domain country table.

This is stable public reference data (ISO 3166 codes, capitals, ITU calling
codes, ISO 4217 currencies, ccTLDs, continent, and the capital's approximate
coordinate). It is intentionally *curated and finite* rather than invented at
runtime: every row is a well-known public fact. Coordinates are capital-city
locations to ~2 decimal places and are exposed with that precision, never as a
rooftop fix. Population/area are deliberately omitted here (they drift and are
better fetched live from Wikidata/REST Countries by the country engine) rather
than baked in as stale numbers.

The table is a starting gazetteer covering every continent and all major
jurisdictions; the :class:`~geo_osint.maps.wikidata_client.WikidataClient` and
REST-Countries enrichment extend it at runtime when the network is available.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..models.coordinate import Coordinate
from ..models.country import Country

# (iso2, iso3, name, capital, continent, calling_code, currency, tld, cap_lat, cap_lon)
_ROWS = [
    ("AD", "AND", "Andorra", "Andorra la Vella", "EU", "+376", "EUR", ".ad", 42.51, 1.52),
    ("AE", "ARE", "United Arab Emirates", "Abu Dhabi", "AS", "+971", "AED", ".ae", 24.47, 54.37),
    ("AF", "AFG", "Afghanistan", "Kabul", "AS", "+93", "AFN", ".af", 34.53, 69.17),
    ("AL", "ALB", "Albania", "Tirana", "EU", "+355", "ALL", ".al", 41.33, 19.82),
    ("AM", "ARM", "Armenia", "Yerevan", "AS", "+374", "AMD", ".am", 40.18, 44.51),
    ("AO", "AGO", "Angola", "Luanda", "AF", "+244", "AOA", ".ao", -8.84, 13.23),
    ("AR", "ARG", "Argentina", "Buenos Aires", "SA", "+54", "ARS", ".ar", -34.61, -58.38),
    ("AT", "AUT", "Austria", "Vienna", "EU", "+43", "EUR", ".at", 48.21, 16.37),
    ("AU", "AUS", "Australia", "Canberra", "OC", "+61", "AUD", ".au", -35.28, 149.13),
    ("AZ", "AZE", "Azerbaijan", "Baku", "AS", "+994", "AZN", ".az", 40.41, 49.87),
    ("BA", "BIH", "Bosnia and Herzegovina", "Sarajevo", "EU", "+387", "BAM", ".ba", 43.86, 18.41),
    ("BD", "BGD", "Bangladesh", "Dhaka", "AS", "+880", "BDT", ".bd", 23.81, 90.41),
    ("BE", "BEL", "Belgium", "Brussels", "EU", "+32", "EUR", ".be", 50.85, 4.35),
    ("BF", "BFA", "Burkina Faso", "Ouagadougou", "AF", "+226", "XOF", ".bf", 12.37, -1.52),
    ("BG", "BGR", "Bulgaria", "Sofia", "EU", "+359", "BGN", ".bg", 42.70, 23.32),
    ("BH", "BHR", "Bahrain", "Manama", "AS", "+973", "BHD", ".bh", 26.23, 50.59),
    ("BJ", "BEN", "Benin", "Porto-Novo", "AF", "+229", "XOF", ".bj", 6.50, 2.60),
    ("BN", "BRN", "Brunei", "Bandar Seri Begawan", "AS", "+673", "BND", ".bn", 4.90, 114.94),
    ("BO", "BOL", "Bolivia", "Sucre", "SA", "+591", "BOB", ".bo", -19.03, -65.26),
    ("BR", "BRA", "Brazil", "Brasília", "SA", "+55", "BRL", ".br", -15.79, -47.88),
    ("BW", "BWA", "Botswana", "Gaborone", "AF", "+267", "BWP", ".bw", -24.63, 25.92),
    ("BY", "BLR", "Belarus", "Minsk", "EU", "+375", "BYN", ".by", 53.90, 27.57),
    ("CA", "CAN", "Canada", "Ottawa", "NA", "+1", "CAD", ".ca", 45.42, -75.70),
    ("CD", "COD", "DR Congo", "Kinshasa", "AF", "+243", "CDF", ".cd", -4.44, 15.27),
    ("CH", "CHE", "Switzerland", "Bern", "EU", "+41", "CHF", ".ch", 46.95, 7.45),
    ("CI", "CIV", "Côte d'Ivoire", "Yamoussoukro", "AF", "+225", "XOF", ".ci", 6.83, -5.29),
    ("CL", "CHL", "Chile", "Santiago", "SA", "+56", "CLP", ".cl", -33.45, -70.67),
    ("CM", "CMR", "Cameroon", "Yaoundé", "AF", "+237", "XAF", ".cm", 3.85, 11.50),
    ("CN", "CHN", "China", "Beijing", "AS", "+86", "CNY", ".cn", 39.90, 116.41),
    ("CO", "COL", "Colombia", "Bogotá", "SA", "+57", "COP", ".co", 4.71, -74.07),
    ("CR", "CRI", "Costa Rica", "San José", "NA", "+506", "CRC", ".cr", 9.93, -84.08),
    ("CU", "CUB", "Cuba", "Havana", "NA", "+53", "CUP", ".cu", 23.11, -82.37),
    ("CY", "CYP", "Cyprus", "Nicosia", "EU", "+357", "EUR", ".cy", 35.19, 33.38),
    ("CZ", "CZE", "Czechia", "Prague", "EU", "+420", "CZK", ".cz", 50.08, 14.44),
    ("DE", "DEU", "Germany", "Berlin", "EU", "+49", "EUR", ".de", 52.52, 13.40),
    ("DK", "DNK", "Denmark", "Copenhagen", "EU", "+45", "DKK", ".dk", 55.68, 12.57),
    ("DO", "DOM", "Dominican Republic", "Santo Domingo", "NA", "+1", "DOP", ".do", 18.49, -69.93),
    ("DZ", "DZA", "Algeria", "Algiers", "AF", "+213", "DZD", ".dz", 36.75, 3.06),
    ("EC", "ECU", "Ecuador", "Quito", "SA", "+593", "USD", ".ec", -0.18, -78.47),
    ("EE", "EST", "Estonia", "Tallinn", "EU", "+372", "EUR", ".ee", 59.44, 24.75),
    ("EG", "EGY", "Egypt", "Cairo", "AF", "+20", "EGP", ".eg", 30.04, 31.24),
    ("ES", "ESP", "Spain", "Madrid", "EU", "+34", "EUR", ".es", 40.42, -3.70),
    ("ET", "ETH", "Ethiopia", "Addis Ababa", "AF", "+251", "ETB", ".et", 9.03, 38.74),
    ("FI", "FIN", "Finland", "Helsinki", "EU", "+358", "EUR", ".fi", 60.17, 24.94),
    ("FR", "FRA", "France", "Paris", "EU", "+33", "EUR", ".fr", 48.85, 2.35),
    ("GB", "GBR", "United Kingdom", "London", "EU", "+44", "GBP", ".uk", 51.51, -0.13),
    ("GE", "GEO", "Georgia", "Tbilisi", "AS", "+995", "GEL", ".ge", 41.72, 44.83),
    ("GH", "GHA", "Ghana", "Accra", "AF", "+233", "GHS", ".gh", 5.60, -0.19),
    ("GR", "GRC", "Greece", "Athens", "EU", "+30", "EUR", ".gr", 37.98, 23.73),
    ("GT", "GTM", "Guatemala", "Guatemala City", "NA", "+502", "GTQ", ".gt", 14.63, -90.51),
    ("HK", "HKG", "Hong Kong", "Hong Kong", "AS", "+852", "HKD", ".hk", 22.32, 114.17),
    ("HN", "HND", "Honduras", "Tegucigalpa", "NA", "+504", "HNL", ".hn", 14.07, -87.19),
    ("HR", "HRV", "Croatia", "Zagreb", "EU", "+385", "EUR", ".hr", 45.81, 15.98),
    ("HU", "HUN", "Hungary", "Budapest", "EU", "+36", "HUF", ".hu", 47.50, 19.04),
    ("ID", "IDN", "Indonesia", "Jakarta", "AS", "+62", "IDR", ".id", -6.21, 106.85),
    ("IE", "IRL", "Ireland", "Dublin", "EU", "+353", "EUR", ".ie", 53.35, -6.26),
    ("IL", "ISR", "Israel", "Jerusalem", "AS", "+972", "ILS", ".il", 31.77, 35.22),
    ("IN", "IND", "India", "New Delhi", "AS", "+91", "INR", ".in", 28.61, 77.21),
    ("IQ", "IRQ", "Iraq", "Baghdad", "AS", "+964", "IQD", ".iq", 33.32, 44.36),
    ("IR", "IRN", "Iran", "Tehran", "AS", "+98", "IRR", ".ir", 35.69, 51.39),
    ("IS", "ISL", "Iceland", "Reykjavík", "EU", "+354", "ISK", ".is", 64.15, -21.94),
    ("IT", "ITA", "Italy", "Rome", "EU", "+39", "EUR", ".it", 41.90, 12.50),
    ("JO", "JOR", "Jordan", "Amman", "AS", "+962", "JOD", ".jo", 31.95, 35.93),
    ("JP", "JPN", "Japan", "Tokyo", "AS", "+81", "JPY", ".jp", 35.68, 139.69),
    ("KE", "KEN", "Kenya", "Nairobi", "AF", "+254", "KES", ".ke", -1.29, 36.82),
    ("KH", "KHM", "Cambodia", "Phnom Penh", "AS", "+855", "KHR", ".kh", 11.56, 104.92),
    ("KR", "KOR", "South Korea", "Seoul", "AS", "+82", "KRW", ".kr", 37.57, 126.98),
    ("KP", "PRK", "North Korea", "Pyongyang", "AS", "+850", "KPW", ".kp", 39.02, 125.75),
    ("KW", "KWT", "Kuwait", "Kuwait City", "AS", "+965", "KWD", ".kw", 29.38, 47.99),
    ("KZ", "KAZ", "Kazakhstan", "Astana", "AS", "+7", "KZT", ".kz", 51.17, 71.43),
    ("LA", "LAO", "Laos", "Vientiane", "AS", "+856", "LAK", ".la", 17.97, 102.63),
    ("LB", "LBN", "Lebanon", "Beirut", "AS", "+961", "LBP", ".lb", 33.89, 35.50),
    ("LK", "LKA", "Sri Lanka", "Sri Jayawardenepura Kotte", "AS", "+94", "LKR", ".lk", 6.90, 79.92),
    ("LT", "LTU", "Lithuania", "Vilnius", "EU", "+370", "EUR", ".lt", 54.69, 25.28),
    ("LU", "LUX", "Luxembourg", "Luxembourg", "EU", "+352", "EUR", ".lu", 49.61, 6.13),
    ("LV", "LVA", "Latvia", "Riga", "EU", "+371", "EUR", ".lv", 56.95, 24.11),
    ("LY", "LBY", "Libya", "Tripoli", "AF", "+218", "LYD", ".ly", 32.89, 13.19),
    ("MA", "MAR", "Morocco", "Rabat", "AF", "+212", "MAD", ".ma", 34.02, -6.83),
    ("MD", "MDA", "Moldova", "Chișinău", "EU", "+373", "MDL", ".md", 47.01, 28.86),
    ("MM", "MMR", "Myanmar", "Naypyidaw", "AS", "+95", "MMK", ".mm", 19.76, 96.08),
    ("MN", "MNG", "Mongolia", "Ulaanbaatar", "AS", "+976", "MNT", ".mn", 47.89, 106.91),
    ("MX", "MEX", "Mexico", "Mexico City", "NA", "+52", "MXN", ".mx", 19.43, -99.13),
    ("MY", "MYS", "Malaysia", "Kuala Lumpur", "AS", "+60", "MYR", ".my", 3.14, 101.69),
    ("NG", "NGA", "Nigeria", "Abuja", "AF", "+234", "NGN", ".ng", 9.08, 7.40),
    ("NL", "NLD", "Netherlands", "Amsterdam", "EU", "+31", "EUR", ".nl", 52.37, 4.90),
    ("NO", "NOR", "Norway", "Oslo", "EU", "+47", "NOK", ".no", 59.91, 10.75),
    ("NP", "NPL", "Nepal", "Kathmandu", "AS", "+977", "NPR", ".np", 27.72, 85.32),
    ("NZ", "NZL", "New Zealand", "Wellington", "OC", "+64", "NZD", ".nz", -41.29, 174.78),
    ("OM", "OMN", "Oman", "Muscat", "AS", "+968", "OMR", ".om", 23.59, 58.41),
    ("PA", "PAN", "Panama", "Panama City", "NA", "+507", "PAB", ".pa", 8.98, -79.52),
    ("PE", "PER", "Peru", "Lima", "SA", "+51", "PEN", ".pe", -12.05, -77.04),
    ("PH", "PHL", "Philippines", "Manila", "AS", "+63", "PHP", ".ph", 14.60, 120.98),
    ("PK", "PAK", "Pakistan", "Islamabad", "AS", "+92", "PKR", ".pk", 33.69, 73.05),
    ("PL", "POL", "Poland", "Warsaw", "EU", "+48", "PLN", ".pl", 52.23, 21.01),
    ("PT", "PRT", "Portugal", "Lisbon", "EU", "+351", "EUR", ".pt", 38.72, -9.14),
    ("PY", "PRY", "Paraguay", "Asunción", "SA", "+595", "PYG", ".py", -25.28, -57.63),
    ("QA", "QAT", "Qatar", "Doha", "AS", "+974", "QAR", ".qa", 25.29, 51.53),
    ("RO", "ROU", "Romania", "Bucharest", "EU", "+40", "RON", ".ro", 44.43, 26.10),
    ("RS", "SRB", "Serbia", "Belgrade", "EU", "+381", "RSD", ".rs", 44.79, 20.45),
    ("RU", "RUS", "Russia", "Moscow", "EU", "+7", "RUB", ".ru", 55.75, 37.62),
    ("SA", "SAU", "Saudi Arabia", "Riyadh", "AS", "+966", "SAR", ".sa", 24.71, 46.68),
    ("SD", "SDN", "Sudan", "Khartoum", "AF", "+249", "SDG", ".sd", 15.50, 32.56),
    ("SE", "SWE", "Sweden", "Stockholm", "EU", "+46", "SEK", ".se", 59.33, 18.07),
    ("SG", "SGP", "Singapore", "Singapore", "AS", "+65", "SGD", ".sg", 1.35, 103.82),
    ("SI", "SVN", "Slovenia", "Ljubljana", "EU", "+386", "EUR", ".si", 46.06, 14.51),
    ("SK", "SVK", "Slovakia", "Bratislava", "EU", "+421", "EUR", ".sk", 48.15, 17.11),
    ("SN", "SEN", "Senegal", "Dakar", "AF", "+221", "XOF", ".sn", 14.72, -17.47),
    ("SY", "SYR", "Syria", "Damascus", "AS", "+963", "SYP", ".sy", 33.51, 36.29),
    ("TH", "THA", "Thailand", "Bangkok", "AS", "+66", "THB", ".th", 13.75, 100.52),
    ("TN", "TUN", "Tunisia", "Tunis", "AF", "+216", "TND", ".tn", 36.81, 10.18),
    ("TR", "TUR", "Turkey", "Ankara", "AS", "+90", "TRY", ".tr", 39.93, 32.87),
    ("TW", "TWN", "Taiwan", "Taipei", "AS", "+886", "TWD", ".tw", 25.03, 121.57),
    ("TZ", "TZA", "Tanzania", "Dodoma", "AF", "+255", "TZS", ".tz", -6.16, 35.75),
    ("UA", "UKR", "Ukraine", "Kyiv", "EU", "+380", "UAH", ".ua", 50.45, 30.52),
    ("UG", "UGA", "Uganda", "Kampala", "AF", "+256", "UGX", ".ug", 0.35, 32.58),
    ("US", "USA", "United States", "Washington, D.C.", "NA", "+1", "USD", ".us", 38.90, -77.04),
    ("UY", "URY", "Uruguay", "Montevideo", "SA", "+598", "UYU", ".uy", -34.90, -56.16),
    ("UZ", "UZB", "Uzbekistan", "Tashkent", "AS", "+998", "UZS", ".uz", 41.30, 69.24),
    ("VE", "VEN", "Venezuela", "Caracas", "SA", "+58", "VES", ".ve", 10.49, -66.88),
    ("VN", "VNM", "Vietnam", "Hanoi", "AS", "+84", "VND", ".vn", 21.03, 105.85),
    ("ZA", "ZAF", "South Africa", "Pretoria", "AF", "+27", "ZAR", ".za", -25.75, 28.19),
    ("ZM", "ZMB", "Zambia", "Lusaka", "AF", "+260", "ZMW", ".zm", -15.42, 28.28),
    ("ZW", "ZWE", "Zimbabwe", "Harare", "AF", "+263", "ZWL", ".zw", -17.83, 31.05),
]

# A small set of well-known land borders (ISO2 -> neighbours). Curated, not
# exhaustive; empty is honest where borders are not encoded rather than guessed.
_NEIGHBORS: Dict[str, List[str]] = {
    "TH": ["MM", "LA", "KH", "MY"],
    "LA": ["TH", "MM", "CN", "VN", "KH"],
    "KH": ["TH", "LA", "VN"],
    "VN": ["CN", "LA", "KH"],
    "MY": ["TH", "SG", "BN", "ID"],
    "FR": ["BE", "LU", "DE", "CH", "IT", "ES", "AD"],
    "DE": ["DK", "PL", "CZ", "AT", "CH", "FR", "LU", "BE", "NL"],
    "US": ["CA", "MX"],
    "CN": ["RU", "KP", "VN", "LA", "MM", "IN", "NP", "PK", "KZ", "MN"],
}

_CONTINENT_NAMES = {
    "AF": "Africa", "AS": "Asia", "EU": "Europe", "NA": "North America",
    "SA": "South America", "OC": "Oceania", "AN": "Antarctica",
}

_BY_ISO2: Dict[str, Country] = {}
_BY_ISO3: Dict[str, Country] = {}
_BY_NAME: Dict[str, Country] = {}


def _build() -> None:
    if _BY_ISO2:
        return
    for (iso2, iso3, name, capital, cont, call, cur, tld, lat, lon) in _ROWS:
        c = Country(
            iso2=iso2, iso3=iso3, name=name, capital=capital,
            continent=_CONTINENT_NAMES.get(cont, cont), region=cont,
            calling_code=call, currency_code=cur, tld=tld,
            neighbors=_NEIGHBORS.get(iso2, []),
            centroid=Coordinate(lat, lon, precision=2, source="capital-centroid"),
        )
        _BY_ISO2[iso2] = c
        _BY_ISO3[iso3] = c
        _BY_NAME[name.lower()] = c


def all_countries() -> List[Country]:
    _build()
    return list(_BY_ISO2.values())


def by_iso2(code: str) -> Optional[Country]:
    _build()
    return _BY_ISO2.get((code or "").strip().upper()[:2])


def by_iso3(code: str) -> Optional[Country]:
    _build()
    return _BY_ISO3.get((code or "").strip().upper()[:3])


def by_name(name: str) -> Optional[Country]:
    _build()
    return _BY_NAME.get((name or "").strip().lower())


def resolve(token: str) -> Optional[Country]:
    """Resolve an ISO2, ISO3, calling code, TLD or country name to a Country.

    ISO lookups are length-guarded: a 2-char token is tried as ISO2 and a 3-char
    token as ISO3, so an arbitrary name like "Bangkok" is never truncated to a
    spurious code (its first two letters "BA" must not resolve to Bosnia).
    """
    if not token:
        return None
    t = token.strip()
    if len(t) == 2:
        hit = by_iso2(t)
        if hit:
            return hit
    if len(t) == 3:
        hit = by_iso3(t)
        if hit:
            return hit
    hit = by_name(t)
    if hit:
        return hit
    _build()
    tl = t.lower()
    for c in _BY_ISO2.values():
        if c.tld == (tl if tl.startswith(".") else "." + tl):
            return c
        if c.calling_code == (t if t.startswith("+") else "+" + t):
            return c
    return None
