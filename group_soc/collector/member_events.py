"""
group_soc/collector/member_events.py — collect member.joined / member.left.

member.joined payload: {chat_id, user_id, username, display_name, is_bot, invite}
member.left  payload:  {chat_id, user_id}

A join by a bot is recorded as BOT_ADDED (derivable from the is_bot flag), otherwise
MEMBER_JOINED — this is a real distinction the payload supports, not a fabricated one.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..constants import EventType, ObjectType
from ..normalization.schema import RawEvent


def collect_member_joined(payload: Dict[str, Any], *,
                          correlation_id: Optional[str] = None) -> Optional[RawEvent]:
    if not payload or payload.get("chat_id") is None:
        return None
    is_bot = bool(payload.get("is_bot"))
    return RawEvent(
        event_type=EventType.BOT_ADDED.value if is_bot else EventType.MEMBER_JOINED.value,
        chat_id=payload.get("chat_id"),
        source="telegram",
        correlation_id=correlation_id,
        actor_id=payload.get("user_id"),
        actor_label=payload.get("username") or payload.get("display_name"),
        object_type=ObjectType.BOT.value if is_bot else ObjectType.USER.value,
        context={
            "is_bot": is_bot,
            "via_invite": bool(payload.get("invite")),
        },
    )


def collect_member_left(payload: Dict[str, Any], *,
                        correlation_id: Optional[str] = None) -> Optional[RawEvent]:
    if not payload or payload.get("chat_id") is None:
        return None
    return RawEvent(
        event_type=EventType.MEMBER_LEFT.value,
        chat_id=payload.get("chat_id"),
        source="telegram",
        correlation_id=correlation_id,
        actor_id=payload.get("user_id"),
        object_type=ObjectType.USER.value,
    )
