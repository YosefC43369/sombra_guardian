"""
blueteam/dac/records.py — build the normalized detection **record** (pure).

A record is a flat dict of features a rule can test. The wiring passes raw,
already-extracted primitives (text, url list, sender metadata) — this module never
touches telegram objects, so it stays pure and unit-testable. Feature names are the
documented rule vocabulary (see docs/blueteam/rule-writing guide).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .. import urlkit


def build_record(*, text: str = "", urls: Optional[List[str]] = None,
                 user_id: Optional[int] = None, chat_id: Optional[int] = None,
                 is_new_member: bool = False, account_age_days: Optional[float] = None,
                 has_username: bool = True, reply_to_is_admin: bool = False,
                 entities: Optional[Dict[str, int]] = None,
                 forward_from: str = "", extra: Optional[Dict[str, Any]] = None
                 ) -> Dict[str, Any]:
    text = text or ""
    urls = urls or []
    domains: List[str] = []
    for u in urls:
        try:
            host = urlkit.canonicalize(u).split("/")[0]
            domains.append(host)
        except Exception:
            continue
    ent = entities or {}
    rec: Dict[str, Any] = {
        "text": text,
        "text_lower": text.lower(),
        "text_len": len(text),
        "urls": urls,
        "domains": domains,
        "registrable_domains": [urlkit.registrable_domain(d) for d in domains],
        "url_count": len(urls),
        "has_url": bool(urls),
        "user_id": user_id,
        "chat_id": chat_id,
        "is_new_member": is_new_member,
        "account_age_days": account_age_days,
        "has_username": has_username,
        "reply_to_is_admin": reply_to_is_admin,
        "mention_count": int(ent.get("mention", 0)),
        "url_entity_count": int(ent.get("url", 0)),
        "emoji_count": int(ent.get("emoji", 0)),
        "forward_from": forward_from,
        "is_forward": bool(forward_from),
    }
    if extra:
        rec.update(extra)
    return rec


__all__ = ["build_record"]
