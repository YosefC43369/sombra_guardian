"""
behavioral_intelligence.models.observation — the universal observation object.

WHAT / WHY
----------
Every upstream module in this repository emits activity records in its own shape:
an ``osint`` source hit, a SOCMINT public post, an Entity Fusion alias sighting,
a public IOC reference. The Behavioral Intelligence Engine cannot analyse activity
until those share one vocabulary. This module defines that vocabulary: a single
``Observation`` — one atomic, timestamped, publicly-observed event attributed to a
platform/account — plus the value objects that keep every observation traceable
back to its public source.

DESIGN NOTES (mirrors entity_fusion.entity discipline)
------------------------------------------------------
- **Provenance is never optional.** An observation records where it was seen
  (``source``, ``source_url``, ``collected_at``) and can be pinned to an
  ``evidence_id``. This engine separates observed fact from inference; the
  confidence layer reads this provenance, it never invents it.
- **UTC internally, always.** ``timestamp`` and ``collected_at`` are epoch
  seconds in UTC (float), matching ``time.time()`` used across the repo. Any
  timezone presentation is a *display* concern handled at the edge; the engine
  never treats a rendered local hour as identity evidence.
- **Timestamp precision is explicit.** Public sources disagree on granularity (a
  crawl may only know the day). ``timestamp_precision`` records that so temporal
  analysis can widen its uncertainty rather than pretend to second accuracy.
- **Content is hashed, not hoarded.** ``content_hash`` (SHA-256 of normalised
  text) lets the engine dedupe and cache without retaining raw text longer than
  needed; ``text`` itself is optional and subject to the privacy layer.
- **Standard library only.** dataclasses + enum + hashlib + datetime. No third
  party dependency, so the analytical core runs and tests without httpx et al.
"""

from __future__ import annotations

import hashlib
import time
import uuid
import unicodedata
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Sequence


# --------------------------------------------------------------------------- #
# Enumerations                                                                 #
# --------------------------------------------------------------------------- #

class TimestampPrecision(str, Enum):
    """How precisely the observation time is known.

    Analysis widens its uncertainty for coarse precisions (a DAY-precise
    observation contributes to a daily histogram but not to an hour-of-day
    heatmap). ``str`` mixin so it serialises as a plain string."""

    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    MONTH = "month"
    YEAR = "year"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "TimestampPrecision":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN

    @property
    def supports_hour(self) -> bool:
        """True when the precision is fine enough to place the event in an
        hour-of-day bucket (hour/minute/second)."""
        return self in (TimestampPrecision.SECOND, TimestampPrecision.MINUTE,
                        TimestampPrecision.HOUR)

    @property
    def supports_day(self) -> bool:
        return self not in (TimestampPrecision.MONTH, TimestampPrecision.YEAR,
                            TimestampPrecision.UNKNOWN)


class ContentType(str, Enum):
    """The structural kind of a public content event. Deliberately platform
    neutral so a tweet, a toot, a Reddit comment and an RSS item map onto the
    same set."""

    POST = "post"
    REPLY = "reply"
    REPOST = "repost"          # retweet / boost / share
    QUOTE = "quote"
    COMMENT = "comment"
    THREAD = "thread"
    PROFILE = "profile"        # a profile/bio snapshot
    MEDIA = "media"
    ARTICLE = "article"        # blog / news / long form
    COMMIT = "commit"          # public VCS activity
    RELEASE = "release"
    REACTION = "reaction"      # like/upvote where public metadata exists
    MENTION_EVENT = "mention"  # observed being mentioned by someone else
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "ContentType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


def _now() -> float:
    return time.time()


def new_id(prefix: str = "obs") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_text(text: str) -> str:
    """NFC-normalise, collapse whitespace and casefold for hashing/comparison.

    Uses ``str.casefold`` (not ``lower``) so non-ASCII scripts fold correctly,
    and NFC so canonically-equivalent Unicode compares equal — important for the
    mixed-script (Thai/Japanese/Arabic) content this engine handles."""
    if not text:
        return ""
    nfc = unicodedata.normalize("NFC", text)
    return " ".join(nfc.split()).casefold()


def content_hash(text: str) -> str:
    """SHA-256 of the normalised text. Stable across runs and platforms so the
    same content re-shared elsewhere hashes identically (used by content-reuse
    detection and the observation cache)."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# The Observation                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class Observation:
    """One publicly-observed activity event attributed to an account/platform.

    Only the ``platform``/``account_id``/``timestamp`` triple is conceptually
    required; everything else is filled where a source provides it. ``entity_id``
    links the observation to an Entity Fusion identity when one is known, so
    behaviour can be aggregated across an actor's correlated accounts *within an
    authorized program* — the engine never performs that correlation itself.
    """

    platform: str = ""
    account_id: str = ""
    timestamp: float = 0.0                       # epoch seconds, UTC
    observation_id: str = field(default_factory=lambda: new_id("obs"))
    entity_id: str = ""                          # Entity Fusion id, if resolved
    timestamp_precision: TimestampPrecision = TimestampPrecision.SECOND
    source_url: str = ""
    content_type: ContentType = ContentType.POST
    text: str = ""                               # optional; privacy layer may drop
    content_hash: str = ""
    language: str = ""                           # ISO-639-1 where known
    script: str = ""                             # Unicode script name, if detected
    location_reference: str = ""                 # self-declared location string only
    entities: List[str] = field(default_factory=list)   # named entities in text
    hashtags: List[str] = field(default_factory=list)
    mentions: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    in_reply_to: str = ""                         # account/post this replies to
    thread_id: str = ""
    repost_of: str = ""                           # source content_hash if a repost
    metadata: Dict[str, Any] = field(default_factory=dict)
    collected_at: float = field(default_factory=_now)
    source: str = ""                              # provider/module that collected
    evidence_id: str = ""
    confidence: float = 1.0                       # source's self-reported reliability

    def __post_init__(self) -> None:
        self.timestamp_precision = TimestampPrecision.coerce(self.timestamp_precision)
        self.content_type = ContentType.coerce(self.content_type)
        self.platform = (self.platform or "").strip().lower()
        self.account_id = (self.account_id or "").strip()
        self.language = (self.language or "").strip().lower()
        # normalise hashtag/mention casing and strip leading markers
        self.hashtags = _dedup_lower(h.lstrip("#") for h in self.hashtags)
        self.mentions = _dedup_lower(m.lstrip("@") for m in self.mentions)
        self.domains = _dedup_lower(self.domains)
        if self.text and not self.content_hash:
            self.content_hash = content_hash(self.text)

    # ---- derived temporal fields (UTC) ---------------------------------- #

    @property
    def dt_utc(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc)

    @property
    def hour_utc(self) -> int:
        """0-23 hour-of-day in UTC."""
        return self.dt_utc.hour

    @property
    def weekday_utc(self) -> int:
        """0=Monday .. 6=Sunday, UTC (matches datetime.weekday())."""
        return self.dt_utc.weekday()

    @property
    def date_utc(self) -> str:
        return self.dt_utc.strftime("%Y-%m-%d")

    @property
    def month_utc(self) -> str:
        return self.dt_utc.strftime("%Y-%m")

    @property
    def iso_week_utc(self) -> str:
        y, w, _ = self.dt_utc.isocalendar()
        return f"{y}-W{w:02d}"

    def local_hour(self, utc_offset_hours: float = 0.0) -> int:
        """Hour-of-day after a *display* timezone shift. The engine records the
        offset used and never asserts it as identity evidence on its own."""
        return int((self.hour_utc + utc_offset_hours) % 24)

    @property
    def has_time(self) -> bool:
        return self.timestamp > 0

    # ---- convenience ----------------------------------------------------- #

    def dedupe_key(self) -> str:
        """Stable identity for deduplicating re-collected observations: the
        platform+account+time+content, not the random observation_id."""
        return "|".join([
            self.platform, self.account_id, f"{self.timestamp:.0f}",
            self.content_type.value, self.content_hash or self.source_url,
        ])

    def all_domains(self) -> List[str]:
        """Domains explicitly recorded plus any parsed from URLs (best-effort,
        stdlib only)."""
        out = set(self.domains)
        for u in self.urls:
            d = _domain_of(u)
            if d:
                out.add(d)
        return sorted(out)

    # ---- serialization --------------------------------------------------- #

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp_precision"] = self.timestamp_precision.value
        d["content_type"] = self.content_type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        return cls(
            platform=str(data.get("platform", "")),
            account_id=str(data.get("account_id", "")),
            timestamp=float(data.get("timestamp", 0.0) or 0.0),
            observation_id=str(data.get("observation_id") or new_id("obs")),
            entity_id=str(data.get("entity_id", "")),
            timestamp_precision=TimestampPrecision.coerce(
                data.get("timestamp_precision")),
            source_url=str(data.get("source_url", "")),
            content_type=ContentType.coerce(data.get("content_type")),
            text=str(data.get("text", "")),
            content_hash=str(data.get("content_hash", "")),
            language=str(data.get("language", "")),
            script=str(data.get("script", "")),
            location_reference=str(data.get("location_reference", "")),
            entities=list(data.get("entities", []) or []),
            hashtags=list(data.get("hashtags", []) or []),
            mentions=list(data.get("mentions", []) or []),
            urls=list(data.get("urls", []) or []),
            domains=list(data.get("domains", []) or []),
            in_reply_to=str(data.get("in_reply_to", "")),
            thread_id=str(data.get("thread_id", "")),
            repost_of=str(data.get("repost_of", "")),
            metadata=dict(data.get("metadata", {}) or {}),
            collected_at=float(data.get("collected_at", _now()) or _now()),
            source=str(data.get("source", "")),
            evidence_id=str(data.get("evidence_id", "")),
            confidence=float(data.get("confidence", 1.0) or 1.0),
        )

    @classmethod
    def from_record(cls, record: Dict[str, Any], *, source: str = "",
                    platform: str = "") -> "Observation":
        """Lift a loosely-typed upstream record into an Observation. Recognised
        keys are mapped; everything else is carried into ``metadata`` so nothing
        is lost. Accepts ``timestamp`` as epoch seconds or an ISO-8601 string."""
        known = {
            "platform", "account_id", "timestamp", "observation_id", "entity_id",
            "timestamp_precision", "source_url", "content_type", "text",
            "content_hash", "language", "script", "location_reference", "entities",
            "hashtags", "mentions", "urls", "domains", "in_reply_to", "thread_id",
            "repost_of", "collected_at", "source", "evidence_id", "confidence",
        }
        ts = record.get("timestamp", 0.0)
        obs = cls(
            platform=str(record.get("platform", platform) or platform),
            account_id=str(record.get("account_id", "")),
            timestamp=parse_timestamp(ts),
            entity_id=str(record.get("entity_id", "")),
            timestamp_precision=TimestampPrecision.coerce(
                record.get("timestamp_precision", "second")),
            source_url=str(record.get("source_url", record.get("url", ""))),
            content_type=ContentType.coerce(record.get("content_type", "post")),
            text=str(record.get("text", record.get("content", ""))),
            language=str(record.get("language", "")),
            location_reference=str(record.get("location_reference",
                                              record.get("location", ""))),
            entities=list(record.get("entities", []) or []),
            hashtags=list(record.get("hashtags", []) or []),
            mentions=list(record.get("mentions", []) or []),
            urls=list(record.get("urls", []) or []),
            domains=list(record.get("domains", []) or []),
            in_reply_to=str(record.get("in_reply_to", "")),
            thread_id=str(record.get("thread_id", "")),
            repost_of=str(record.get("repost_of", "")),
            source=str(record.get("source", source) or source),
            evidence_id=str(record.get("evidence_id", "")),
            confidence=float(record.get("confidence", 1.0) or 1.0),
        )
        for k, v in record.items():
            if k not in known and k not in ("url", "content", "location"):
                obs.metadata[k] = v
        return obs

    def summary(self) -> str:
        when = self.dt_utc.strftime("%Y-%m-%d %H:%MZ") if self.has_time else "no-time"
        return (f"{self.platform}/{self.account_id} {self.content_type.value} "
                f"@ {when} [{self.source or '?'}]")


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _dedup_lower(items: Iterable[str]) -> List[str]:
    """Lower-case, strip, drop empties, preserve first-seen order."""
    seen: Dict[str, None] = {}
    for it in items:
        v = str(it).strip().lower()
        if v and v not in seen:
            seen[v] = None
    return list(seen.keys())


def _domain_of(url: str) -> str:
    """Extract a registrable-ish host from a URL, stdlib only. Not a PSL parse —
    it returns the host; domain_behavior applies eTLD folding where needed."""
    if not url:
        return ""
    from urllib.parse import urlsplit
    try:
        host = urlsplit(url if "://" in url else "//" + url, scheme="http").hostname
    except ValueError:
        return ""
    return (host or "").lower().lstrip(".")


def parse_timestamp(value: Any) -> float:
    """Coerce an epoch number or an ISO-8601 / common string into UTC epoch
    seconds. Returns 0.0 when unparseable (the observation is then treated as
    having no reliable time). Never raises."""
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    # numeric string
    try:
        return float(s)
    except ValueError:
        pass
    # ISO-8601 (handle trailing Z)
    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
                "%Y/%m/%d", "%d %b %Y", "%a, %d %b %Y %H:%M:%S %z"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


@dataclass
class ObservationBatch:
    """A cohesive set of observations plus the window they cover. This is the
    unit most engines consume: they never reach back to storage themselves, they
    are handed a batch and return typed models over exactly that batch, so a
    result's sample size and observation period are always well-defined."""

    observations: List[Observation] = field(default_factory=list)
    entity_id: str = ""
    label: str = ""

    def __len__(self) -> int:
        return len(self.observations)

    def __iter__(self):
        return iter(self.observations)

    def timed(self) -> List[Observation]:
        """Only observations with a usable timestamp, sorted ascending."""
        return sorted((o for o in self.observations if o.has_time),
                      key=lambda o: o.timestamp)

    def platforms(self) -> List[str]:
        return sorted({o.platform for o in self.observations if o.platform})

    def accounts(self) -> List[str]:
        return sorted({f"{o.platform}/{o.account_id}"
                       for o in self.observations if o.account_id})

    def span(self) -> "tuple[float, float]":
        """(earliest, latest) timestamp among timed observations, or (0,0)."""
        timed = self.timed()
        if not timed:
            return (0.0, 0.0)
        return (timed[0].timestamp, timed[-1].timestamp)

    def dedupe(self) -> "ObservationBatch":
        """Return a new batch with re-collected duplicates removed (keeping the
        earliest ``collected_at`` for each ``dedupe_key``)."""
        best: Dict[str, Observation] = {}
        for o in self.observations:
            k = o.dedupe_key()
            cur = best.get(k)
            if cur is None or o.collected_at < cur.collected_at:
                best[k] = o
        return ObservationBatch(list(best.values()), entity_id=self.entity_id,
                                label=self.label)

    def filter_platform(self, platform: str) -> "ObservationBatch":
        p = platform.strip().lower()
        return ObservationBatch([o for o in self.observations if o.platform == p],
                                entity_id=self.entity_id, label=self.label)

    def to_dict(self) -> Dict[str, Any]:
        lo, hi = self.span()
        return {
            "entity_id": self.entity_id,
            "label": self.label,
            "count": len(self.observations),
            "platforms": self.platforms(),
            "span": {"start": lo, "end": hi},
            "observations": [o.to_dict() for o in self.observations],
        }

    @classmethod
    def from_records(cls, records: Sequence[Dict[str, Any]], *, source: str = "",
                     entity_id: str = "") -> "ObservationBatch":
        obs = [Observation.from_record(r, source=source) for r in records]
        return cls(obs, entity_id=entity_id)
