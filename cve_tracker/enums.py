"""
cve_tracker.enums — the closed vocabularies the subsystem speaks in.

Every enum here is a *normalized* target: source adapters map their own
messy strings ("Critical", "CRITICAL", "critical", "High/Critical") onto these
canonical members so the rest of the pipeline (storage, intelligence, alerts,
AI prompts) never has to branch on per-source spellings.

All enums are ``str``-valued so they serialize straight into JSON / sqlite TEXT
columns and compare equal to their stored form without a conversion step.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class _StrEnum(str, Enum):
    """Base: a str enum whose ``str()`` is the value (not 'Class.MEMBER').

    Python's stdlib grew ``enum.StrEnum`` only in 3.11; the bot targets a
    wider range, so we keep a tiny local base with the one behaviour we rely
    on — ``str(member) == member.value`` — plus a forgiving ``coerce``.
    """

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)

    @classmethod
    def coerce(cls, value, default=None):
        """Best-effort parse of an arbitrary value into a member.

        Accepts a member, its value, or its name (case/space/hyphen
        insensitive). Returns ``default`` when nothing matches instead of
        raising — ingestion must never crash on an unexpected source string.
        """
        if value is None:
            return default
        if isinstance(value, cls):
            return value
        text = str(value).strip()
        if not text:
            return default
        low = text.lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if str(member.value).lower() == text.lower():
                return member
            if member.name.lower() == low:
                return member
        return default


class Severity(_StrEnum):
    """Qualitative severity band. Ordered low→high via ``rank`` so alert
    filters can express 'HIGH and above' without a lookup table."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return {
            Severity.UNKNOWN: -1,
            Severity.NONE: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __ge__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other):  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    @classmethod
    def from_cvss_score(cls, score: Optional[float], *, version: str = "3.1") -> "Severity":
        """Map a numeric CVSS base score to its official qualitative band.

        CVSS v3.x and v4.0 share the same cut points; v2.0 uses a coarser
        three-band scale (Low/Medium/High) which we widen to this enum. We do
        NOT invent a score here — the caller passes a score the source gave.
        """
        if score is None:
            return cls.UNKNOWN
        try:
            s = float(score)
        except (TypeError, ValueError):
            return cls.UNKNOWN
        if version.startswith("2"):
            # CVSS v2: 0.0-3.9 Low, 4.0-6.9 Medium, 7.0-10.0 High
            if s >= 7.0:
                return cls.HIGH
            if s >= 4.0:
                return cls.MEDIUM
            if s > 0.0:
                return cls.LOW
            return cls.NONE
        # CVSS v3.x / v4.0
        if s >= 9.0:
            return cls.CRITICAL
        if s >= 7.0:
            return cls.HIGH
        if s >= 4.0:
            return cls.MEDIUM
        if s > 0.0:
            return cls.LOW
        return cls.NONE


class CVSSVersion(_StrEnum):
    """Which CVSS specification a score/vector belongs to."""

    V2 = "2.0"
    V30 = "3.0"
    V31 = "3.1"
    V40 = "4.0"


class SourceKind(_StrEnum):
    """Category of a CVE information source. Drives per-kind rate limits,
    trust weighting in conflict resolution, and health grouping."""

    NVD = "nvd"
    CVE_ORG = "cve_org"
    CISA_KEV = "cisa_kev"
    GITHUB_ADVISORY = "github_advisory"
    VENDOR_ADVISORY = "vendor_advisory"
    OTHER = "other"


class SourceHealthState(_StrEnum):
    """Rolling health of a single source, surfaced by /cve_status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILING = "failing"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class ReferenceType(_StrEnum):
    """What a reference URL *is*. Classification only — the subsystem never
    fetches or executes anything a reference points at (see security rules)."""

    ADVISORY = "advisory"
    VENDOR_ADVISORY = "vendor_advisory"
    PATCH = "patch"
    EXPLOIT = "exploit"
    POC = "poc"
    EXPLOIT_DB = "exploit_db"
    GITHUB_REPO = "github_repo"
    TECHNICAL = "technical"
    RESEARCH = "research"
    BLOG = "blog"
    NEWS = "news"
    MAILING_LIST = "mailing_list"
    ISSUE_TRACKER = "issue_tracker"
    THIRD_PARTY = "third_party"
    MITIGATION = "mitigation"
    PRODUCT = "product"
    UNKNOWN = "unknown"


class ExploitMaturity(_StrEnum):
    """Confidence that exploit code exists for a CVE — derived strictly from
    references and KEV, never asserted by the AI. 'CONFIRMED' requires an
    explicit factual signal (CISA KEV, an Exploit-DB entry, a source's
    'exploit maturity' field), not a guess."""

    NONE = "none"                 # no exploit-ish reference seen
    REFERENCED = "referenced"     # a PoC/exploit reference is present
    PUBLIC_POC = "public_poc"     # a public PoC is referenced
    CONFIRMED = "confirmed"       # KEV / Exploit-DB / source-asserted
    UNKNOWN = "unknown"


class AIProcessingState(_StrEnum):
    """Lifecycle of the AI summary for a CVE record."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"
    FALLBACK = "fallback"        # published with a deterministic template
    SKIPPED = "skipped"          # AI disabled by config
    UNAVAILABLE = "unavailable"  # provider down at send time


class NotificationState(_StrEnum):
    """Delivery lifecycle of one CVE→chat notification."""

    PENDING = "pending"
    QUEUED = "queued"
    SENT = "sent"
    FAILED = "failed"
    RETRY = "retry"
    SUPPRESSED = "suppressed"    # filtered out / already sent / throttled


class EventType(_StrEnum):
    """Internal domain events other modules may subscribe to. These are NOT
    the platform's bus event names — the plugin suite maps them across."""

    CVE_DISCOVERED = "cve.discovered"
    CVE_UPDATED = "cve.updated"
    CVE_SEVERITY_CHANGED = "cve.severity_changed"
    CVE_CVSS_CHANGED = "cve.cvss_changed"
    CVE_KEV_ADDED = "cve.kev_added"
    CVE_REFERENCE_ADDED = "cve.reference_added"
    CVE_EXPLOIT_STATUS_CHANGED = "cve.exploit_status_changed"
    CVE_AI_SUMMARIZED = "cve.ai_summarized"
    CVE_ALERT_SENT = "cve.alert_sent"
    CVE_ALERT_FAILED = "cve.alert_failed"
    SOURCE_SYNC_OK = "source.sync_ok"
    SOURCE_SYNC_FAILED = "source.sync_failed"


class ChangeKind(_StrEnum):
    """A single field-level change detected between two versions of a CVE."""

    DESCRIPTION = "description"
    CVSS = "cvss"
    SEVERITY = "severity"
    CWE = "cwe"
    CPE = "cpe"
    REFERENCES = "references"
    AFFECTED_VERSIONS = "affected_versions"
    FIXED_VERSIONS = "fixed_versions"
    KEV_STATUS = "kev_status"
    EXPLOIT_STATUS = "exploit_status"
    VENDORS = "vendors"
    PRODUCTS = "products"
    TITLE = "title"


class Priority(_StrEnum):
    """Internal, non-official prioritization band. Deliberately named so it is
    never confused with a CVSS severity — it blends CVSS, KEV, exploit
    references, exposure and recency into an operational signal."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    URGENT = "URGENT"

    @property
    def rank(self) -> int:
        return {
            Priority.INFO: 0, Priority.LOW: 1, Priority.MEDIUM: 2,
            Priority.HIGH: 3, Priority.URGENT: 4,
        }[self]


# CVSS 3.x/4.0 metric vocabularies, used by enrichment.cvss to validate and
# explain vectors. Kept here so both the parser and the AI prompt builder read
# the same canonical labels.
ATTACK_VECTOR = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
ATTACK_COMPLEXITY = {"L": "Low", "H": "High"}
PRIVILEGES_REQUIRED = {"N": "None", "L": "Low", "H": "High"}
USER_INTERACTION = {"N": "None", "R": "Required", "P": "Passive", "A": "Active"}
SCOPE = {"U": "Unchanged", "C": "Changed"}
IMPACT = {"N": "None", "L": "Low", "H": "High"}

# CVSS v2 metric vocabularies (distinct label set).
V2_ACCESS_VECTOR = {"L": "Local", "A": "Adjacent Network", "N": "Network"}
V2_ACCESS_COMPLEXITY = {"H": "High", "M": "Medium", "L": "Low"}
V2_AUTHENTICATION = {"M": "Multiple", "S": "Single", "N": "None"}
V2_IMPACT = {"N": "None", "P": "Partial", "C": "Complete"}
