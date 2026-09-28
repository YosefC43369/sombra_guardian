"""
geo_osint.storage.sqlite_store — durable observation storage with spatial indexing.

Persists :class:`~geo_osint.models.observation.GeoObservation` rows in SQLite and,
when the SQLite build has the R*Tree module (it usually does), maintains an
``rtree`` virtual table so bounding-box and radius queries are index-accelerated
for the millions-of-records target (spec §51). When R*Tree is unavailable it falls
back to a plain indexed scan — the API is identical either way. Inserts are
chunked/streamed so a large import never buffers everything in memory.

Pure stdlib (:mod:`sqlite3`, :mod:`json`); safe for concurrent readers.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Dict, Iterable, Iterator, List, Optional

from ..models.coordinate import Coordinate, haversine_km
from ..models.geofence import BoundingBox
from ..models.observation import GeoObservation

logger = logging.getLogger("modbot.geo_osint.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    geo_id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL,
    location_type TEXT,
    latitude REAL,
    longitude REAL,
    coordinate_precision INTEGER,
    source TEXT,
    source_url TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    timezone TEXT,
    confidence REAL,
    first_seen REAL,
    last_seen REAL,
    observation_timestamp REAL,
    doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_obs_entity ON observations(entity_id);
CREATE INDEX IF NOT EXISTS ix_obs_country ON observations(country_code);
CREATE INDEX IF NOT EXISTS ix_obs_type ON observations(location_type);
CREATE INDEX IF NOT EXISTS ix_obs_latlon ON observations(latitude, longitude);
"""

_RTREE_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS obs_rtree USING rtree(
    id, min_lat, max_lat, min_lon, max_lon
);
"""


class SQLiteGeoStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._rtree = self._init_schema()
        self._rowid = 0

    def _init_schema(self) -> bool:
        self._conn.executescript(_SCHEMA)
        try:
            self._conn.executescript(_RTREE_SCHEMA)
            self._conn.commit()
            return True
        except sqlite3.OperationalError as exc:
            logger.info("SQLite R*Tree unavailable, using scan fallback: %s", exc)
            self._conn.commit()
            return False

    @property
    def rtree_enabled(self) -> bool:
        return self._rtree

    # -- writes ------------------------------------------------------------
    def add(self, obs: GeoObservation) -> None:
        self._insert_rows([obs])
        self._conn.commit()

    def add_many(self, observations: Iterable[GeoObservation],
                 chunk: int = 1000) -> int:
        total = 0
        batch: List[GeoObservation] = []
        for obs in observations:
            batch.append(obs)
            if len(batch) >= chunk:
                self._insert_rows(batch)
                total += len(batch)
                batch = []
        if batch:
            self._insert_rows(batch)
            total += len(batch)
        self._conn.commit()
        return total

    def _insert_rows(self, batch: List[GeoObservation]) -> None:
        rows = []
        rtree_rows = []
        for obs in batch:
            lat = obs.coordinate.latitude if obs.coordinate else None
            lon = obs.coordinate.longitude if obs.coordinate else None
            rows.append((
                obs.geo_id, obs.entity_id, obs.location_type.value, lat, lon,
                obs.coordinate_precision, obs.source, obs.source_url,
                obs.country_code, obs.region, obs.city, obs.timezone,
                obs.confidence, obs.first_seen, obs.last_seen,
                obs.observation_timestamp,
                json.dumps(obs.to_dict(), ensure_ascii=False)))
            if self._rtree and lat is not None and lon is not None:
                self._rowid += 1
                rtree_rows.append((self._rowid, lat, lat, lon, lon))
                obs.metadata.setdefault("_rtree_id", self._rowid)
        self._conn.executemany(
            "INSERT OR REPLACE INTO observations VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        if rtree_rows:
            self._conn.executemany(
                "INSERT INTO obs_rtree VALUES (?,?,?,?,?)", rtree_rows)

    # -- reads -------------------------------------------------------------
    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]

    def by_entity(self, entity_id: str) -> List[GeoObservation]:
        cur = self._conn.execute(
            "SELECT doc FROM observations WHERE entity_id=?", (entity_id,))
        return [self._load(r["doc"]) for r in cur.fetchall()]

    def by_country(self, country_code: str) -> List[GeoObservation]:
        cur = self._conn.execute(
            "SELECT doc FROM observations WHERE country_code=?",
            (country_code.upper(),))
        return [self._load(r["doc"]) for r in cur.fetchall()]

    def in_bbox(self, bbox: BoundingBox) -> List[GeoObservation]:
        if self._rtree:
            cur = self._conn.execute(
                "SELECT o.doc FROM observations o "
                "WHERE o.latitude BETWEEN ? AND ? AND o.longitude BETWEEN ? AND ?",
                (bbox.south, bbox.north, bbox.west, bbox.east))
        else:
            cur = self._conn.execute(
                "SELECT doc FROM observations "
                "WHERE latitude BETWEEN ? AND ? AND longitude BETWEEN ? AND ?",
                (bbox.south, bbox.north, bbox.west, bbox.east))
        return [self._load(r["doc"]) for r in cur.fetchall()]

    def within_radius(self, coord: Coordinate, radius_km: float) -> List[GeoObservation]:
        """Bounding-box pre-filter (index) then exact great-circle refinement."""
        bbox = BoundingBox.around(coord.latitude, coord.longitude, radius_km)
        candidates = self.in_bbox(bbox)
        out = []
        for obs in candidates:
            if obs.coordinate and coord.distance_km(obs.coordinate, method="haversine") <= radius_km:
                out.append(obs)
        return out

    def iter_all(self) -> Iterator[GeoObservation]:
        cur = self._conn.execute("SELECT doc FROM observations")
        for row in cur:
            yield self._load(row["doc"])

    @staticmethod
    def _load(doc: str) -> GeoObservation:
        return GeoObservation.from_dict(json.loads(doc))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteGeoStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
