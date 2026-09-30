"""group_soc.collector — adapt raw bus events into RawEvents via a table-driven router."""

from .event_router import EventRouter
from .message_events import collect_message
from .member_events import collect_member_joined, collect_member_left
from .signal_events import collect_detection, collect_rule_matched, collect_ioc_matched

__all__ = [
    "EventRouter", "collect_message", "collect_member_joined", "collect_member_left",
    "collect_detection", "collect_rule_matched", "collect_ioc_matched",
]
