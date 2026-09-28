"""
behavioral_intelligence.providers.activitypub — public ActivityPub outbox
provider (spec §53 ActivityPub).

Reads a PUBLIC ActivityPub actor outbox (the JSON a Fediverse server serves at an
actor's ``/outbox``) and lifts each ``Create``/``Announce`` activity into an
``Observation``. Content type maps: ``Create`` of a ``Note`` → post/reply,
``Announce`` → repost. HTML content is stripped to text; tags become hashtags and
mentions.

Passive and public only: it reads the already-public outbox JSON over HTTP GET.
It never authenticates, never touches non-public collections, and honours the
configured timeout/rate limit. ``normalize`` accepts a parsed dict/list so the
mapping is testable offline.
"""

from __future__ import annotations

import html
import re
from typing import Any, List, Optional

from ..models.observation import Observation, ContentType, parse_timestamp
from .base import BehaviorProvider

try:
    from osint.utils.async_http import AsyncHTTPClient, HAVE_HTTPX
except Exception:  # pragma: no cover
    AsyncHTTPClient = None  # type: ignore[assignment,misc]
    HAVE_HTTPX = False

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(s: str) -> str:
    if not s:
        return ""
    return html.unescape(_TAG_RE.sub(" ", s)).strip()


class ActivityPubProvider(BehaviorProvider):
    name = "activitypub"
    kind = "account"

    def __init__(self, config=None, *, platform: str = "fediverse"):
        super().__init__(config)
        self.platform = platform

    async def health_check(self) -> bool:
        return bool(HAVE_HTTPX and AsyncHTTPClient is not None)

    async def collect(self, target: str) -> Any:
        """Fetch a public outbox collection. ``target`` is the outbox URL."""
        if AsyncHTTPClient is None or not HAVE_HTTPX:
            raise RuntimeError("HTTP stack unavailable; supply outbox JSON to normalize()")
        async with AsyncHTTPClient(rate=self.config.per_host_rate,
                                   burst=self.config.per_host_burst,
                                   timeout=self.config.timeout_seconds,
                                   max_retries=self.config.max_retries,
                                   user_agent=self.config.user_agent) as client:
            data = await client.get_json(target)
            return data

    def normalize(self, raw: Any) -> List[Observation]:
        if raw is None:
            return []
        items = self._items(raw)
        out: List[Observation] = []
        for act in items:
            obs = self._activity_to_obs(act)
            if obs is not None:
                out.append(obs)
        return out

    def _items(self, raw: Any) -> List[dict]:
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
        if isinstance(raw, dict):
            for key in ("orderedItems", "items"):
                if isinstance(raw.get(key), list):
                    return [x for x in raw[key] if isinstance(x, dict)]
            if raw.get("type") in ("Create", "Announce", "Note"):
                return [raw]
        return []

    def _activity_to_obs(self, act: dict) -> Optional[Observation]:
        atype = act.get("type", "")
        obj = act.get("object")
        actor = act.get("actor") or act.get("attributedTo") or ""
        actor = actor if isinstance(actor, str) else str(actor.get("id", "")) \
            if isinstance(actor, dict) else ""
        account_id = actor.rstrip("/").split("/")[-1] if actor else ""

        if atype == "Announce":
            ctype = ContentType.REPOST
            boosted = obj if isinstance(obj, dict) else {}
            text = _strip_html(boosted.get("content", "")) if boosted else ""
            url = obj if isinstance(obj, str) else str(boosted.get("id", "") or "")
            ts = parse_timestamp(act.get("published", ""))
            return Observation(platform=self.platform, account_id=account_id,
                               timestamp=ts, content_type=ctype, source_url=url,
                               text=text, repost_of="", source=self.name)

        note = obj if isinstance(obj, dict) else (act if atype == "Note" else None)
        if not isinstance(note, dict):
            return None
        text = _strip_html(note.get("content", ""))
        in_reply_to = note.get("inReplyTo") or ""
        ctype = ContentType.REPLY if in_reply_to else ContentType.POST
        tags = note.get("tag", []) or []
        hashtags = [t.get("name", "").lstrip("#") for t in tags
                    if isinstance(t, dict) and t.get("type") == "Hashtag"]
        mentions = [t.get("name", "").lstrip("@") for t in tags
                    if isinstance(t, dict) and t.get("type") == "Mention"]
        ts = parse_timestamp(note.get("published", act.get("published", "")))
        return Observation(
            platform=self.platform, account_id=account_id, timestamp=ts,
            content_type=ctype, source_url=str(note.get("id", note.get("url", "")) or ""),
            text=text, hashtags=hashtags, mentions=mentions,
            in_reply_to=str(in_reply_to) if in_reply_to else "",
            language=str(note.get("contentMap", {}).get("_lang", "") or ""),
            source=self.name)
