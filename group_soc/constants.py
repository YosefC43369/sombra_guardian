"""
group_soc/constants.py — the SOC vocabulary.

Central, dependency-free definitions shared across the subsystem: event taxonomy,
severities, the alert/case/incident lifecycles, and the canonical bus event-type
strings the SOC produces and consumes.

Everything here is a plain string/enum so it can be imported anywhere (storage,
tests, commands) without pulling in Telegram, the DB, or the event bus.

IMPORTANT — Telegram-observability note (rule §6/§ "DO NOT FABRICATE"):
The event taxonomy lists security-relevant things the SOC *models*. Not all are
directly observable from the Telegram Bot API. Each member is annotated with how
the SOC actually obtains it:
  [OBS]   observable from a normal group message/update the bot receives
  [MEMBER]observable from ChatMemberUpdated (bot must receive member updates)
  [ADMIN] observable only if the bot is an admin (and even then, limited)
  [DERIVED] produced *inside* the SOC (correlation/detection/alerting), not from TG
  [UPSTREAM] delivered by another Sombra module via the event bus, not read from TG
The collector layer only subscribes to event types the platform actually emits;
the rest of the taxonomy exists so upstream modules can feed richer events later.
"""

from __future__ import annotations

from enum import Enum


# --------------------------------------------------------------------------- #
# Event taxonomy
# --------------------------------------------------------------------------- #
class EventType(str, Enum):
    # message lifecycle
    MESSAGE_CREATED = "message_created"          # [OBS]
    MESSAGE_EDITED = "message_edited"            # [OBS] (edited_message update)
    MESSAGE_DELETED = "message_deleted"          # [DERIVED] TG bots cannot see arbitrary deletions
    # membership
    MEMBER_JOINED = "member_joined"              # [MEMBER]
    MEMBER_LEFT = "member_left"                  # [MEMBER]
    MEMBER_RESTRICTED = "member_restricted"      # [MEMBER/ADMIN]
    MEMBER_UNRESTRICTED = "member_unrestricted"  # [MEMBER/ADMIN]
    MEMBER_BANNED = "member_banned"              # [MEMBER/ADMIN]
    # admin / permissions
    ADMIN_ADDED = "admin_added"                  # [ADMIN] via ChatMemberUpdated on admins
    ADMIN_REMOVED = "admin_removed"              # [ADMIN]
    ADMIN_PERMISSION_CHANGED = "admin_permission_changed"  # [ADMIN]
    GROUP_PERMISSION_CHANGED = "group_permission_changed"  # [ADMIN]
    # bots
    BOT_ADDED = "bot_added"                      # [MEMBER]
    BOT_REMOVED = "bot_removed"                  # [MEMBER]
    # invites
    INVITE_CREATED = "invite_created"            # [ADMIN] chat_member/ chat_join_request
    INVITE_REVOKED = "invite_revoked"            # [ADMIN]
    # security signals fed from upstream detectors
    SECURITY_RULE_TRIGGERED = "security_rule_triggered"  # [UPSTREAM] rule.matched
    IOC_MATCHED = "ioc_matched"                  # [UPSTREAM] intel.ioc_matched
    DETECTION_TRIGGERED = "detection_triggered"  # [UPSTREAM] detection.triggered
    # SOC-internal, produced by the pipeline
    ANOMALY_DETECTED = "anomaly_detected"        # [DERIVED]
    CORRELATION_CREATED = "correlation_created"  # [DERIVED]
    ALERT_CREATED = "alert_created"              # [DERIVED]
    ALERT_ESCALATED = "alert_escalated"          # [DERIVED]
    CASE_CREATED = "case_created"                # [DERIVED]
    INCIDENT_CREATED = "incident_created"        # [DERIVED]
    INCIDENT_RESOLVED = "incident_resolved"      # [DERIVED]

    def __str__(self) -> str:  # so f-strings render the value, not EventType.X
        return self.value


VALID_EVENT_TYPES = frozenset(e.value for e in EventType)

#: event types that originate from real Telegram updates the bot receives
OBSERVABLE_EVENT_TYPES = frozenset({
    EventType.MESSAGE_CREATED.value, EventType.MESSAGE_EDITED.value,
    EventType.MEMBER_JOINED.value, EventType.MEMBER_LEFT.value,
    EventType.MEMBER_RESTRICTED.value, EventType.MEMBER_UNRESTRICTED.value,
    EventType.MEMBER_BANNED.value, EventType.BOT_ADDED.value, EventType.BOT_REMOVED.value,
    EventType.ADMIN_ADDED.value, EventType.ADMIN_REMOVED.value,
    EventType.ADMIN_PERMISSION_CHANGED.value, EventType.GROUP_PERMISSION_CHANGED.value,
})

#: event types delivered by other Sombra modules via the bus (not read from TG)
UPSTREAM_EVENT_TYPES = frozenset({
    EventType.SECURITY_RULE_TRIGGERED.value, EventType.IOC_MATCHED.value,
    EventType.DETECTION_TRIGGERED.value,
})


# --------------------------------------------------------------------------- #
# Object / entity kinds referenced by an event
# --------------------------------------------------------------------------- #
class ObjectType(str, Enum):
    MESSAGE = "message"
    USER = "user"
    BOT = "bot"
    URL = "url"
    DOMAIN = "domain"
    INVITE = "invite"
    PERMISSION = "permission"
    CHAT = "chat"
    NONE = "none"

    def __str__(self) -> str:
        return self.value


class EntityKind(str, Enum):
    USER = "user"
    BOT = "bot"
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    HASH = "hash"
    PHRASE = "phrase"
    PATTERN = "pattern"
    EVENT_TYPE = "event_type"

    def __str__(self) -> str:
        return self.value


VALID_ENTITY_KINDS = frozenset(k.value for k in EntityKind)


# --------------------------------------------------------------------------- #
# Severity / confidence / analytic-state
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


#: ordered so severity comparisons are meaningful
SEVERITY_ORDER = (
    Severity.INFO.value, Severity.LOW.value, Severity.MEDIUM.value,
    Severity.HIGH.value, Severity.CRITICAL.value,
)
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}
VALID_SEVERITIES = frozenset(SEVERITY_ORDER)


class AnalyticState(str, Enum):
    """The evidentiary standing of a signal — deliberately separate from severity.
    Confidence/severity is an analytical signal, never proof of malicious intent."""
    OBSERVED = "observed"
    CORRELATED = "correlated"
    SUSPICIOUS = "suspicious"
    CONFIRMED = "confirmed"

    def __str__(self) -> str:
        return self.value


VALID_ANALYTIC_STATES = frozenset(s.value for s in AnalyticState)


# --------------------------------------------------------------------------- #
# Lifecycles
# --------------------------------------------------------------------------- #
class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    CLOSED = "closed"

    def __str__(self) -> str:
        return self.value


VALID_ALERT_STATUSES = frozenset(s.value for s in AlertStatus)
TERMINAL_ALERT_STATUSES = frozenset({AlertStatus.RESOLVED.value, AlertStatus.CLOSED.value})

#: allowed alert transitions (from -> {to})
ALERT_TRANSITIONS = {
    AlertStatus.NEW.value: {AlertStatus.TRIAGED.value, AlertStatus.ACKNOWLEDGED.value,
                            AlertStatus.SUPPRESSED.value, AlertStatus.RESOLVED.value,
                            AlertStatus.CLOSED.value},
    AlertStatus.TRIAGED.value: {AlertStatus.ACKNOWLEDGED.value, AlertStatus.INVESTIGATING.value,
                                AlertStatus.ESCALATED.value, AlertStatus.SUPPRESSED.value,
                                AlertStatus.RESOLVED.value, AlertStatus.CLOSED.value},
    AlertStatus.ACKNOWLEDGED.value: {AlertStatus.INVESTIGATING.value, AlertStatus.ESCALATED.value,
                                     AlertStatus.RESOLVED.value, AlertStatus.CLOSED.value},
    AlertStatus.INVESTIGATING.value: {AlertStatus.ESCALATED.value, AlertStatus.RESOLVED.value,
                                      AlertStatus.CLOSED.value},
    AlertStatus.ESCALATED.value: {AlertStatus.INVESTIGATING.value, AlertStatus.RESOLVED.value,
                                  AlertStatus.CLOSED.value},
    AlertStatus.SUPPRESSED.value: {AlertStatus.NEW.value, AlertStatus.CLOSED.value},
    AlertStatus.RESOLVED.value: {AlertStatus.CLOSED.value},
    AlertStatus.CLOSED.value: set(),
}


class CaseStatus(str, Enum):
    OPEN = "open"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    ON_HOLD = "on_hold"
    RESOLVED = "resolved"
    CLOSED = "closed"

    def __str__(self) -> str:
        return self.value


VALID_CASE_STATUSES = frozenset(s.value for s in CaseStatus)
TERMINAL_CASE_STATUSES = frozenset({CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value})

CASE_TRANSITIONS = {
    CaseStatus.OPEN.value: {CaseStatus.ASSIGNED.value, CaseStatus.IN_PROGRESS.value,
                            CaseStatus.ON_HOLD.value, CaseStatus.RESOLVED.value,
                            CaseStatus.CLOSED.value},
    CaseStatus.ASSIGNED.value: {CaseStatus.IN_PROGRESS.value, CaseStatus.ON_HOLD.value,
                                CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value},
    CaseStatus.IN_PROGRESS.value: {CaseStatus.ON_HOLD.value, CaseStatus.RESOLVED.value,
                                   CaseStatus.CLOSED.value},
    CaseStatus.ON_HOLD.value: {CaseStatus.IN_PROGRESS.value, CaseStatus.RESOLVED.value,
                               CaseStatus.CLOSED.value},
    CaseStatus.RESOLVED.value: {CaseStatus.CLOSED.value, CaseStatus.IN_PROGRESS.value},
    CaseStatus.CLOSED.value: set(),
}


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    RESOLVED = "resolved"
    CLOSED = "closed"

    def __str__(self) -> str:
        return self.value


VALID_INCIDENT_STATUSES = frozenset(s.value for s in IncidentStatus)
TERMINAL_INCIDENT_STATUSES = frozenset({IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value})

INCIDENT_TRANSITIONS = {
    IncidentStatus.OPEN.value: {IncidentStatus.CONTAINED.value, IncidentStatus.RESOLVED.value,
                                IncidentStatus.CLOSED.value},
    IncidentStatus.CONTAINED.value: {IncidentStatus.ERADICATED.value, IncidentStatus.RECOVERED.value,
                                     IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value},
    IncidentStatus.ERADICATED.value: {IncidentStatus.RECOVERED.value, IncidentStatus.RESOLVED.value,
                                      IncidentStatus.CLOSED.value},
    IncidentStatus.RECOVERED.value: {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value},
    IncidentStatus.RESOLVED.value: {IncidentStatus.CLOSED.value},
    IncidentStatus.CLOSED.value: set(),
}


class IncidentClass(str, Enum):
    SPAM_CAMPAIGN = "spam_campaign"
    COORDINATED_ACTIVITY = "coordinated_activity"
    RAID = "raid"
    IMPERSONATION = "impersonation"
    MALICIOUS_LINK = "malicious_link"
    IOC_EXPOSURE = "ioc_exposure"
    PERMISSION_ABUSE = "permission_abuse"
    ACCOUNT_TAKEOVER = "account_takeover"
    OTHER = "other"

    def __str__(self) -> str:
        return self.value


VALID_INCIDENT_CLASSES = frozenset(c.value for c in IncidentClass)


# --------------------------------------------------------------------------- #
# Correlation / detection kinds
# --------------------------------------------------------------------------- #
class CorrelationKind(str, Enum):
    TEMPORAL = "temporal"
    ENTITY = "entity"
    BEHAVIORAL = "behavioral"
    SEQUENCE = "sequence"
    CAMPAIGN = "campaign"

    def __str__(self) -> str:
        return self.value


class DetectorKind(str, Enum):
    RULE = "rule"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"
    ANOMALY = "anomaly"

    def __str__(self) -> str:
        return self.value


# --------------------------------------------------------------------------- #
# Canonical bus event-type strings
# --------------------------------------------------------------------------- #
# Consumed (already emitted elsewhere in the platform):
BUS_MESSAGE_RECEIVED = "message.received"
BUS_MEMBER_JOINED = "member.joined"
BUS_MEMBER_LEFT = "member.left"
BUS_DETECTION_TRIGGERED = "detection.triggered"
BUS_RULE_MATCHED = "rule.matched"
BUS_IOC_MATCHED = "intel.ioc_matched"
BUS_INCIDENT_CREATED = "incident.created"
BUS_EVIDENCE_CREATED = "evidence.created"

CONSUMED_BUS_EVENTS = (
    BUS_MESSAGE_RECEIVED, BUS_MEMBER_JOINED, BUS_MEMBER_LEFT,
    BUS_DETECTION_TRIGGERED, BUS_RULE_MATCHED, BUS_IOC_MATCHED,
    BUS_INCIDENT_CREATED, BUS_EVIDENCE_CREATED,
)

# Produced by the SOC:
SOC_EVENT_RECORDED = "soc.event.recorded"
SOC_SIGNAL_CREATED = "soc.signal.created"
SOC_ALERT_CREATED = "soc.alert.created"
SOC_ALERT_ESCALATED = "soc.alert.escalated"
SOC_CASE_CREATED = "soc.case.created"
SOC_INCIDENT_CREATED = "soc.incident.created"
SOC_INCIDENT_RESOLVED = "soc.incident.resolved"


# --------------------------------------------------------------------------- #
# Limits / bounds (hard ceilings; tunables live in config.py)
# --------------------------------------------------------------------------- #
MAX_QUERY_LIMIT = 200
DEFAULT_QUERY_LIMIT = 20
MAX_REASON_LEN = 2000
MAX_NOTE_LEN = 4000
MAX_LABEL_LEN = 200
