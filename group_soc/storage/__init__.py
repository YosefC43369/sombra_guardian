"""
group_soc.storage — sqlite persistence for the SOC.

Schema is owned by ``migrations/m0006_group_soc.py`` (never created here). Each store
is a thin, typed repository over one concern; all share :class:`SocStore` for
connection handling (WAL, per-op connections), the audit log, per-group policy and
retention. A :class:`StorageBundle` groups them so the runtime holds one object.
"""

from .repository import SocStore
from .event_store import EventStore
from .signal_store import SignalStore
from .alert_store import AlertStore
from .case_store import CaseStore
from .incident_store import IncidentStore
from .timeline_store import TimelineStore
from .watchlist_store import WatchlistStore
from .investigation_store import InvestigationStore


class StorageBundle:
    """One object holding every store for a db_path. Constructed once per runtime."""

    def __init__(self, db_path: str = "bot.db"):
        self.db_path = db_path
        self.base = SocStore(db_path)
        self.events = EventStore(db_path)
        self.signals = SignalStore(db_path)
        self.alerts = AlertStore(db_path)
        self.cases = CaseStore(db_path)
        self.incidents = IncidentStore(db_path)
        self.timeline = TimelineStore(db_path)
        self.watchlist = WatchlistStore(db_path)
        self.investigations = InvestigationStore(db_path)

    # convenience passthroughs used widely
    def audit(self, *args, **kwargs):
        return self.base.audit(*args, **kwargs)

    def get_policy(self, chat_id: int):
        return self.base.get_policy(chat_id)

    def set_policy(self, chat_id: int, **kwargs):
        return self.base.set_policy(chat_id, **kwargs)

    def is_group_active(self, chat_id: int) -> bool:
        return self.base.is_group_active(chat_id)


__all__ = [
    "SocStore", "EventStore", "SignalStore", "AlertStore", "CaseStore",
    "IncidentStore", "TimelineStore", "WatchlistStore", "InvestigationStore",
    "StorageBundle",
]
