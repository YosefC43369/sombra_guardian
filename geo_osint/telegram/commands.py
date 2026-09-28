"""
geo_osint.telegram.commands — Telegram command surface (spec §44-45).

Commands: /geo /geocode /reversegeo /airport /nearby /map /distance /country
/city /datacenter /asn_geo /ip_geo /domain_geo /geo_report.

Design (mirroring the other subsystems): the logic lives in
:class:`GeoCommandService` — pure ``async`` methods that return rendered strings and
are fully testable without a running bot (use a LOCAL-mode config to keep them
offline). The ``async def cmd_*`` handlers are thin adapters that parse arguments,
call the service and reply. ``python-telegram-bot`` is imported defensively so this
module imports in the pure test environment.

Every reply concerns PUBLIC geographic information only and shows evidence/precision
and, where relevant, the standing limitation that IP/ASN geolocation is an estimate.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..configuration import GeoConfig, GeoMode
from ..engine import GeoOSINTEngine, TargetKind
from ..geocoding.coordinate_normalizer import CoordinateNormalizer
from ..geocoding.geocoder import Geocoder
from ..geocoding.reverse_geocoder import ReverseGeocoder
from ..airports.airport_engine import AirportEngine
from ..infrastructure.cloud_region_engine import CloudRegionEngine
from ..infrastructure.datacenter_engine import DataCenterEngine
from ..correlation.distance import DistanceEngine
from ..data import countries as _countries
from ..data import cities as _cities
from ..models.coordinate import Coordinate, CoordinateParseError
from ..reports import GeoReportBuilder, markdown_report

logger = logging.getLogger("modbot.geo_osint.telegram")

try:
    from telegram import Update
    from telegram.ext import ContextTypes, CommandHandler
    HAVE_PTB = True
except Exception:                                # pragma: no cover
    Update = object
    ContextTypes = None
    CommandHandler = None
    HAVE_PTB = False

_LIMIT = 3900


class GeoCommandService:
    """Pure command implementations returning rendered text (bot-independent)."""

    def __init__(self, config: Optional[GeoConfig] = None) -> None:
        self.config = config or GeoConfig.build(GeoMode.PASSIVE)
        self._engine = GeoOSINTEngine(self.config)
        self._norm = CoordinateNormalizer()
        self._geocoder = Geocoder()
        self._reverse = ReverseGeocoder()
        self._airports = AirportEngine()
        self._cloud = CloudRegionEngine()
        self._dc = DataCenterEngine()
        self._distance = DistanceEngine()
        self._reports = GeoReportBuilder()

    # -- /geo --------------------------------------------------------------
    async def geo(self, arg: str) -> str:
        if not arg:
            return "Usage: /geo <coordinate|place|domain|ip|asn|airport|country>"
        result = await self._engine.investigate(arg.strip())
        lines = [f"🌍 *Geo-OSINT* — `{arg.strip()}` ({result.kind.value})",
                 f"observations: {len(result.observations)} · "
                 f"footprint {result.footprint_score.get('score') if result.footprint_score else '—'}"]
        if result.profile and result.profile.primary_country:
            pc = result.profile.primary_country
            lines.append(f"primary country: *{pc.value}* ({pc.confidence:.2f})")
        for o in result.observations.observations[:8]:
            lines.append(f"• {o.location_type.value}: "
                         f"{o.city or o.country_code or '—'} "
                         f"{_coord_str(o.coordinate)} [{o.source}]")
        lines.append("_public sources only; see /geo_report for full evidence_")
        return _clip("\n".join(lines))

    # -- /geocode ----------------------------------------------------------
    async def geocode(self, arg: str) -> str:
        if not arg:
            return "Usage: /geocode <place name>"
        hits = await self._geocoder.geocode(arg.strip(),
                                            allow_online=self.config.mode.uses_network)
        if not hits:
            return f"No match for '{arg}'."
        out = [f"📍 *Geocode* — {arg.strip()}"]
        for h in hits[:5]:
            out.append(f"• {h.display_name} {_coord_str(h.coordinate)} "
                       f"tz={h.timezone or '—'} [{h.source}]")
        return _clip("\n".join(out))

    # -- /reversegeo -------------------------------------------------------
    async def reversegeo(self, arg: str) -> str:
        try:
            coord = self._norm.parse(arg.strip())
        except (CoordinateParseError, ValueError):
            return "Usage: /reversegeo <lat,lon | DMS | MGRS | plus code>"
        loc = await self._reverse.reverse(coord,
                                          allow_online=self.config.mode.uses_network)
        return _clip(
            f"🧭 *Reverse* {_coord_str(coord)}\n"
            f"• {loc.display_name}\n"
            f"• country: {loc.country_code} · city: {loc.city or '—'} · "
            f"tz: {loc.timezone or '—'}\n"
            f"• confidence: {loc.confidence:.2f} [{loc.source}]")

    # -- /airport ----------------------------------------------------------
    async def airport(self, arg: str) -> str:
        if not arg:
            return "Usage: /airport <IATA|ICAO|name>"
        ap = self._airports.by_code(arg.strip()) or (
            self._airports.search(arg.strip(), limit=1) or [None])[0]
        if not ap:
            return f"No airport for '{arg}'."
        return _clip(
            f"✈️ *{ap.name}* ({ap.iata}/{ap.icao})\n"
            f"• {ap.city}, {ap.country} {_coord_str(ap.coordinate)}\n"
            f"• elevation: {ap.elevation_ft or '—'} ft · tz: {ap.timezone or '—'}")

    # -- /nearby -----------------------------------------------------------
    async def nearby(self, arg: str) -> str:
        parts = arg.split()
        if not parts:
            return "Usage: /nearby <lat,lon|place> [radius_km]"
        radius = 50.0
        if len(parts) >= 2 and _isfloat(parts[-1]):
            radius = float(parts[-1])
            arg = " ".join(parts[:-1])
        coord = await self._resolve_coord(arg)
        if coord is None:
            return f"Could not resolve '{arg}' to a coordinate."
        aps = self._airports.nearest(coord, limit=5, max_km=radius)
        clouds = self._cloud.nearest(coord, limit=3, max_km=radius)
        out = [f"📡 *Nearby public infrastructure* within {radius:.0f} km",
               "airports:"] + [f"  • {a.code} {a.name} — {d} km" for a, d in aps]
        out.append("cloud regions:")
        out += [f"  • {r.provider}:{r.region_code} ({r.city}) — {d} km"
                for r, d in clouds]
        return _clip("\n".join(out))

    # -- /distance ---------------------------------------------------------
    async def distance(self, arg: str) -> str:
        parts = arg.split("|") if "|" in arg else arg.split()
        if len(parts) < 2:
            return "Usage: /distance <A> | <B>  (places, codes or coordinates)"
        a = await self._resolve_coord(parts[0].strip())
        b = await self._resolve_coord(parts[1].strip())
        if a is None or b is None:
            return "Could not resolve both endpoints."
        km = self._distance.between(a, b)
        return (f"📏 *Distance*\n{parts[0].strip()} ↔ {parts[1].strip()}\n"
                f"• {km:,.1f} km (geodesic) / "
                f"{a.distance_km(b, method='haversine'):,.1f} km (haversine)")

    # -- /country ----------------------------------------------------------
    async def country(self, arg: str) -> str:
        c = _countries.resolve(arg.strip())
        if not c:
            return f"No country for '{arg}'."
        return _clip(
            f"🏳 *{c.name}* ({c.iso2}/{c.iso3})\n"
            f"• capital: {c.capital} {_coord_str(c.centroid)}\n"
            f"• continent: {c.continent} · calling: {c.calling_code} · "
            f"currency: {c.currency_code} · TLD: {c.tld}\n"
            f"• neighbors: {', '.join(c.neighbors) or '—'}")

    # -- /city -------------------------------------------------------------
    async def city(self, arg: str) -> str:
        hits = _cities.find(arg.strip())
        if not hits:
            canon = _cities.canonical_name(arg.strip())
            hits = _cities.find(canon) if canon else []
        if not hits:
            return f"No city for '{arg}'."
        c = hits[0]
        return _clip(
            f"🏙 *{c.name}* ({c.country_code})\n"
            f"• {_coord_str(c.coordinate)} · tz: {c.timezone or '—'} · "
            f"pop: {c.population or '—'}\n"
            f"• also known as: {', '.join(c.alternate_names) or '—'}")

    # -- /datacenter -------------------------------------------------------
    async def datacenter(self, arg: str) -> str:
        # Offline: cloud regions in a country/city; online adds PeeringDB facilities.
        regions = (self._cloud.by_country(arg.strip())
                   if len(arg.strip()) == 2 else self._cloud.in_city(arg.strip()))
        out = [f"🖥 *Cloud regions / data centres* — {arg.strip()}"]
        for r in regions[:12]:
            out.append(f"• {r.provider}:{r.region_code} — {r.city}, {r.country_code}")
        if not regions:
            out.append("_no curated cloud regions; try a 2-letter country or a city_")
        return _clip("\n".join(out))

    # -- /asn_geo, /ip_geo, /domain_geo -----------------------------------
    async def asn_geo(self, arg: str) -> str:
        return await self._geoloc(arg, TargetKind.ASN, "AS")

    async def ip_geo(self, arg: str) -> str:
        return await self._geoloc(arg, TargetKind.IP, "IP")

    async def domain_geo(self, arg: str) -> str:
        return await self._geoloc(arg, TargetKind.DOMAIN, "domain")

    async def _geoloc(self, arg: str, kind: TargetKind, label: str) -> str:
        if not arg:
            return f"Usage: /{label.lower()}_geo <{label}>"
        result = await self._engine.investigate(arg.strip(), kind=kind)
        if not result.observations.observations:
            return (f"No public geolocation signal for {label} `{arg.strip()}`"
                    + ("" if self.config.mode.uses_network
                       else " (offline mode; enable PASSIVE for provider lookups)"))
        out = [f"🌐 *{label} geolocation* — `{arg.strip()}`"]
        for o in result.observations.observations[:6]:
            out.append(f"• {o.city or o.country_code or '—'} "
                       f"{_coord_str(o.coordinate)} (conf {o.confidence:.2f}) [{o.source}]")
        out.append("_estimate from public data — not a physical device location_")
        return _clip("\n".join(out))

    # -- /map --------------------------------------------------------------
    async def map(self, arg: str) -> str:
        if not arg:
            return "Usage: /map <place|coordinate>"
        result = await self._engine.investigate(arg.strip())
        fc = result.to_feature_collection()
        n = len(fc["features"])
        return (f"🗺 *Map* — {arg.strip()}\n"
                f"• {n} placed feature(s) as GeoJSON.\n"
                f"• Use /geo_report for the full HTML map + inventory.")

    # -- /geo_report -------------------------------------------------------
    async def geo_report(self, arg: str) -> str:
        if not arg:
            return "Usage: /geo_report <entity>"
        result = await self._engine.investigate(arg.strip())
        report = self._reports.build(result)
        return _clip(markdown_report.render(report))

    # -- helpers -----------------------------------------------------------
    async def _resolve_coord(self, token: str) -> Optional[Coordinate]:
        try:
            return self._norm.parse(token)
        except (CoordinateParseError, ValueError):
            pass
        ap = self._airports.by_code(token)
        if ap and ap.coordinate:
            return ap.coordinate
        hits = await self._geocoder.geocode(
            token, allow_online=self.config.mode.uses_network)
        return hits[0].coordinate if hits and hits[0].coordinate else None


def _coord_str(coord: Optional[Coordinate]) -> str:
    if coord is None:
        return ""
    lat, lon = coord.rounded(min(5, max(2, coord.precision)))
    return f"({lat}, {lon})"


def _isfloat(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def _clip(text: str) -> str:
    return text if len(text) <= _LIMIT else text[:_LIMIT - 1] + "…"


# --------------------------------------------------------------------------
# Thin async handlers (require python-telegram-bot at call time)
# --------------------------------------------------------------------------
_service: Optional[GeoCommandService] = None


def _svc() -> GeoCommandService:
    global _service
    if _service is None:
        _service = GeoCommandService()
    return _service


def _arg(context) -> str:
    try:
        return " ".join(context.args) if getattr(context, "args", None) else ""
    except Exception:
        return ""


async def _run(update, context, method_name: str) -> None:
    text = await getattr(_svc(), method_name)(_arg(context))
    await update.message.reply_text(text, parse_mode="Markdown",
                                    disable_web_page_preview=True)


def build_handlers() -> List:
    """Return CommandHandlers for registration with a PTB Application."""
    if not HAVE_PTB:
        raise RuntimeError("python-telegram-bot is required to build handlers")
    names = ["geo", "geocode", "reversegeo", "airport", "nearby", "map",
             "distance", "country", "city", "datacenter", "asn_geo", "ip_geo",
             "domain_geo", "geo_report"]

    def make(name):
        async def handler(update, context):
            await _run(update, context, name)
        return handler

    return [CommandHandler(name, make(name)) for name in names]
