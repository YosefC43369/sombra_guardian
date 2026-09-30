"""
group_soc/normalization/normalizer.py — RawEvent → SecurityEvent.

This is the privacy boundary (rule §17). It:
  * hashes actor/target ids into salted hashes,
  * reduces message text to a content hash + length (raw text is dropped here and
    never persisted),
  * turns entity values into privacy-safe EntityRefs (users hashed, domains/urls
    defanged),
  * keeps only non-identifying context.

The Normalizer never raises into the caller: a malformed RawEvent yields a minimal
but valid SecurityEvent so ingest can continue.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..models.event import SecurityEvent
from ..models.entity import EntityRef
from ..constants import EntityKind, ObjectType, Severity, AnalyticState
from ..util import now, hash_id, content_hash, defang, new_correlation_id, clean_str
from ..constants import MAX_LABEL_LEN
from .schema import RawEvent
from .context import extract_entities

logger = logging.getLogger("modbot.group_soc.normalizer")


class Normalizer:
    def __init__(self, *, redact_text: bool = True, extract_from_text: bool = True):
        self.redact_text = redact_text
        self.extract_from_text = extract_from_text

    def normalize(self, raw: RawEvent) -> SecurityEvent:
        try:
            return self._normalize(raw)
        except Exception:
            logger.exception("normalizer failed; emitting minimal event")
            return SecurityEvent(event_type=raw.event_type or "message_created",
                                 chat_id=int(raw.chat_id or 0),
                                 source=raw.source or "telegram")

    def _normalize(self, raw: RawEvent) -> SecurityEvent:
        actor_hash = hash_id(raw.actor_id)
        target_hash = hash_id(raw.target_id)

        text = raw.text or ""
        chash = content_hash(text) if text else None
        clen = len(text)

        entities = self._build_entities(raw, actor_hash)

        # context: strip anything that could be PII; keep structural/aggregate fields
        context = dict(raw.context or {})
        context.pop("text", None)
        context.pop("username", None)
        context.pop("display_name", None)

        return SecurityEvent(
            event_type=raw.event_type,
            chat_id=int(raw.chat_id or 0),
            ts=int(raw.ts) if raw.ts else now(),
            source=raw.source or "telegram",
            correlation_id=raw.correlation_id or new_correlation_id(),
            actor_hash=actor_hash,
            target_hash=target_hash,
            object_type=raw.object_type or ObjectType.NONE.value,
            object_id=clean_str(str(raw.object_id), 64) if raw.object_id is not None else None,
            content_hash=chash,
            content_len=clen,
            entities=entities,
            severity=raw.severity or Severity.INFO.value,
            confidence=raw.confidence if raw.confidence is not None else 0.0,
            analytic_state=AnalyticState.OBSERVED.value,
            context=context,
            metadata=dict(raw.metadata or {}),
        )

    def _build_entities(self, raw: RawEvent, actor_hash: Optional[str]) -> List[EntityRef]:
        refs: List[EntityRef] = []
        seen = set()

        def _add(ref: Optional[EntityRef]):
            if ref is not None and ref.ident not in seen:
                refs.append(ref)
                seen.add(ref.ident)

        # the actor as a user entity (so correlation can join on the actor)
        if actor_hash:
            _add(EntityRef.user(actor_hash, clean_str(raw.actor_label, MAX_LABEL_LEN)))

        # collector-provided entities
        for kind, value in (raw.entities or []):
            _add(self._entity_from(kind, value))

        # text-derived entities (domains/urls), if enabled
        if self.extract_from_text and raw.text:
            for kind, value in extract_entities(raw.text):
                _add(self._entity_from(kind, value))

        return refs[:100]

    @staticmethod
    def _entity_from(kind: str, value: str) -> Optional[EntityRef]:
        if value is None:
            return None
        kind = str(kind)
        if kind == EntityKind.USER.value or kind == EntityKind.BOT.value:
            # a raw user id/username → hash it
            return EntityRef.user(hash_id(value), None)
        if kind == EntityKind.DOMAIN.value:
            return EntityRef.domain(value)
        if kind == EntityKind.URL.value:
            return EntityRef.url(value)
        # ip/hash/phrase/pattern/event_type stored defanged as-is
        return EntityRef(kind, defang(str(value)) if kind in ("ip",) else str(value))
