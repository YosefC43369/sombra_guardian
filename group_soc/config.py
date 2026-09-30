"""
group_soc/config.py — SOC feature flags and tunables, read through ``envutil``
with safe defaults (same idiom as blueteam/config.py).

Two layers of control, mirroring the rest of the platform:

  * **Global flags** (env) — a master kill switch (``SOC_ENABLED``, default OFF so
    deploying the code changes nothing) plus per-capability gates. External lookups
    (threat-intel enrichment) are OFF by default for privacy.
  * **Per-group policy** (DB, ``soc_group_policy``) — even with the master switch on,
    the SOC only ingests/alerts in a group once an admin turns it on. Safe default
    everywhere is "inactive".

Nothing here talks to the network or Telegram; values are read at call time.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

import envutil


@dataclass(frozen=True)
class SocConfig:
    # master + capability gates
    enabled: bool                    # master kill switch (OFF by default)
    ingest_enabled: bool             # record events at all
    correlation_enabled: bool
    detection_enabled: bool
    alerting_enabled: bool
    intel_enrichment_enabled: bool   # opt-in external/threat-intel lookups (OFF)
    emit_soc_events: bool            # publish soc.* events back onto the bus

    # retention (days)
    event_retention_days: int
    signal_retention_days: int
    alert_retention_days: int
    audit_retention_days: int

    # pipeline
    max_events_per_batch: int
    queue_maxsize: int               # bounded queue → backpressure
    worker_poll_interval_s: float

    # correlation
    correlation_window_s: int        # temporal window
    correlation_max_buffer: int      # per-chat ring-buffer size
    sequence_window_s: int

    # detection / thresholds
    join_burst_threshold: int        # joins within window → raid signal
    join_burst_window_s: int
    similar_message_threshold: int   # near-duplicate messages → campaign signal
    similar_message_window_s: int

    # alerting
    alert_cooldown_s: int            # suppression cooldown per dedup key
    alert_group_window_s: int        # group alerts sharing a correlation id
    escalation_repeat_threshold: int # N repeats of a dedup key → escalate

    # privacy
    redact_message_text: bool        # store only hashes/lengths of message text
    hash_salt_env: str               # env var name holding the salt (value read by hashing util)

    @classmethod
    def load(cls) -> "SocConfig":
        return cls(
            enabled=envutil.env_bool("SOC_ENABLED", "false"),
            ingest_enabled=envutil.env_bool("SOC_INGEST_ENABLED", "true"),
            correlation_enabled=envutil.env_bool("SOC_CORRELATION_ENABLED", "true"),
            detection_enabled=envutil.env_bool("SOC_DETECTION_ENABLED", "true"),
            alerting_enabled=envutil.env_bool("SOC_ALERTING_ENABLED", "true"),
            intel_enrichment_enabled=envutil.env_bool("SOC_INTEL_ENRICHMENT_ENABLED", "false"),
            emit_soc_events=envutil.env_bool("SOC_EMIT_EVENTS", "true"),

            event_retention_days=max(1, envutil.env_int("SOC_EVENT_RETENTION_DAYS", 30)),
            signal_retention_days=max(1, envutil.env_int("SOC_SIGNAL_RETENTION_DAYS", 60)),
            alert_retention_days=max(1, envutil.env_int("SOC_ALERT_RETENTION_DAYS", 180)),
            audit_retention_days=max(1, envutil.env_int("SOC_AUDIT_RETENTION_DAYS", 365)),

            max_events_per_batch=max(1, envutil.env_int("SOC_MAX_EVENTS_PER_BATCH", 100)),
            queue_maxsize=max(16, envutil.env_int("SOC_QUEUE_MAXSIZE", 2000)),
            worker_poll_interval_s=max(0.05, envutil.env_float("SOC_WORKER_POLL_INTERVAL_S", 0.5)),

            correlation_window_s=max(1, envutil.env_int("SOC_CORRELATION_WINDOW_S", 300)),
            correlation_max_buffer=max(64, envutil.env_int("SOC_CORRELATION_MAX_BUFFER", 512)),
            sequence_window_s=max(1, envutil.env_int("SOC_SEQUENCE_WINDOW_S", 120)),

            join_burst_threshold=max(2, envutil.env_int("SOC_JOIN_BURST_THRESHOLD", 5)),
            join_burst_window_s=max(1, envutil.env_int("SOC_JOIN_BURST_WINDOW_S", 60)),
            similar_message_threshold=max(2, envutil.env_int("SOC_SIMILAR_MESSAGE_THRESHOLD", 3)),
            similar_message_window_s=max(1, envutil.env_int("SOC_SIMILAR_MESSAGE_WINDOW_S", 120)),

            alert_cooldown_s=max(0, envutil.env_int("SOC_ALERT_COOLDOWN_S", 300)),
            alert_group_window_s=max(1, envutil.env_int("SOC_ALERT_GROUP_WINDOW_S", 600)),
            escalation_repeat_threshold=max(2, envutil.env_int("SOC_ESCALATION_REPEAT_THRESHOLD", 3)),

            redact_message_text=envutil.env_bool("SOC_REDACT_MESSAGE_TEXT", "true"),
            hash_salt_env="SOC_HASH_SALT",
        )

    def capability_enabled(self, capability: str) -> bool:
        """True only if the master switch AND the specific capability are on."""
        if not self.enabled:
            return False
        return {
            "ingest": self.ingest_enabled,
            "correlation": self.correlation_enabled,
            "detection": self.detection_enabled,
            "alerting": self.alerting_enabled,
            "intel_enrichment": self.intel_enrichment_enabled,
            "emit_events": self.emit_soc_events,
        }.get(capability, False)

    def as_dict(self) -> dict:
        return asdict(self)


_config: Optional[SocConfig] = None


def get_config(refresh: bool = False) -> SocConfig:
    global _config
    if _config is None or refresh:
        _config = SocConfig.load()
    return _config
