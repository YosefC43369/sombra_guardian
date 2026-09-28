"""
blueteam/ — the Blue Team Suite for Sombra Guardian (v0.7.0).

Three passive, defensive moderation modules that plug into the existing platform
(Event Bus + Workflow Engine + Plugins) without touching the legacy moderation
flow:

  * **Link Guard** (:mod:`blueteam.linkguard`) — malicious/phishing URL detection,
    layered offline → reputation → optional SSRF-guarded active probe.
  * **Scam & Impersonation** (:mod:`blueteam.scamguard`, :mod:`blueteam.impersonation`)
    — deterministic Thai/English scam lexicon, campaign clustering, and admin/VIP
    impersonation detection.
  * **Join Guard / Anti-Raid** (:mod:`blueteam.joinguard`) — adaptive join-rate
    anomaly detection, a hysteresis state machine, HMAC-signed verification
    challenges, and idempotent lockdown with permission snapshot/restore.

Foundations (this package's shared core):
  * :mod:`blueteam.models` — explainable ``Verdict`` / ``Signal`` / ``Assessment``.
  * :mod:`blueteam.textkit` — normalization, confusable skeletons, SimHash, distances.
  * :mod:`blueteam.urlkit` — URL extraction / de-obfuscation / defang / eTLD+1.
  * :mod:`blueteam.rules` — versioned, checksum-verified rule packs (reloadable).
  * :mod:`blueteam.store` — WAL SQLite persistence (``bt_*`` tables, chat-scoped).
  * :mod:`blueteam.config` — feature flags / kill switch / tunables.

DISCIPLINE: passive analysis only — never runs files, never executes JavaScript,
never builds attack tooling. Every score is explainable and carries a limitation
line; permanent bans require human confirmation unless an admin opts into auto
mode. Errors are isolated so a fault here never breaks legacy moderation.
"""

from .models import Verdict, Signal, Assessment, PolicyAction
from .config import BlueTeamConfig, get_config
from .store import BlueTeamStore
from .rules import get_registry, reload_registry
from .messages_th import msg

__all__ = [
    "Verdict", "Signal", "Assessment", "PolicyAction",
    "BlueTeamConfig", "get_config", "BlueTeamStore",
    "get_registry", "reload_registry", "msg",
]

__version__ = "0.7.0"
