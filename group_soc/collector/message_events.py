"""
group_soc/collector/message_events.py — collect message.received into a RawEvent.

Bus payload shape (as emitted by app.py):
    {chat_id, user_id, message_id, text, entities, username, display_name, mention_count}
``entities`` is a list of Telegram message-entity dicts; we scan it for explicit
URLs (text_link) that may not appear verbatim in text. Everything PII is left for
the Normalizer to hash/drop.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..constants import EventType, ObjectType, EntityKind
from ..normalization.schema import RawEvent


def _urls_from_entities(entities: Any) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not isinstance(entities, list):
        return out
    for ent in entities[:50]:
        if not isinstance(ent, dict):
            continue
        url = ent.get("url")
        if url:
            out.append((EntityKind.URL.value, str(url)))
    return out


def collect_message(payload: Dict[str, Any], *, correlation_id: Optional[str] = None) -> Optional[RawEvent]:
    if not payload or payload.get("chat_id") is None:
        return None
    text = payload.get("text") or ""
    return RawEvent(
        event_type=EventType.MESSAGE_CREATED.value,
        chat_id=payload.get("chat_id"),
        source="telegram",
        correlation_id=correlation_id,
        actor_id=payload.get("user_id"),
        actor_label=payload.get("username") or payload.get("display_name"),
        object_type=ObjectType.MESSAGE.value,
        object_id=payload.get("message_id"),
        text=text,
        entities=_urls_from_entities(payload.get("entities")),
        context={
            "mention_count": int(payload.get("mention_count") or 0),
            "has_text": bool(text),
        },
    )
