"""
entity_fusion.enrichers.gravatar — resolve the PUBLIC Gravatar profile for an
email address.

Gravatar is a public, opt-in service: a user publishes a profile keyed by the
md5 of their email. Fetching ``https://www.gravatar.com/{md5}.json`` returns only
what that user chose to make public (display name, linked accounts, verified
URLs). This enricher turns those into discovered entities (usernames, websites)
linked to the email. No key required.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult


def gravatar_hash(email: str) -> str:
    return hashlib.md5((email or "").strip().lower().encode("utf-8")).hexdigest()


class GravatarEnricher(Enricher):
    name = "gravatar"
    handles = (EntityType.EMAIL,)

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        canon = norm.canonical_email(entity.value)
        if not canon:
            result.ok = False
            result.reason = "invalid email"
            return result
        gh = gravatar_hash(canon)
        result.derived["gravatar_hash"] = gh
        url = f"https://www.gravatar.com/{gh}.json"
        resp = await client.get_json(url)
        if not resp.ok:
            result.ok = resp.status == 404  # 404 = no public profile, not an error
            result.reason = "no public gravatar profile" if resp.status == 404 else resp.reason
            return result
        try:
            data = resp.json()
            profile = (data.get("entry") or [{}])[0]
        except Exception:
            result.ok = False
            result.reason = "unparseable gravatar profile"
            return result

        if profile.get("preferredUsername"):
            uname = str(profile["preferredUsername"])
            result.derived["gravatar_username"] = uname
            child = Entity(type=EntityType.USERNAME, value=uname)
            child.add_source(SourceRef(provider="gravatar", url=url))
            child.add_relationship(Relationship(target_id=entity.id,
                                                type=RelationType.SHARES_EMAIL))
            result.entities.append(child)
        if profile.get("displayName"):
            result.derived["display_name"] = str(profile["displayName"])
        for acct in profile.get("accounts", []) or []:
            handle = acct.get("username") or acct.get("display")
            urlv = acct.get("url", "")
            if handle:
                child = Entity(type=EntityType.USERNAME, value=str(handle))
                child.metadata["service"] = acct.get("shortname", "")
                child.add_source(SourceRef(provider="gravatar", url=urlv))
                child.add_relationship(Relationship(target_id=entity.id,
                                                    type=RelationType.SHARES_EMAIL))
                result.entities.append(child)
        for url_entry in profile.get("urls", []) or []:
            site = url_entry.get("value")
            if site:
                child = Entity(type=EntityType.WEBSITE, value=str(site))
                child.add_source(SourceRef(provider="gravatar", url=url))
                result.entities.append(child)
        result.evidence.append(Evidence(
            kind="gravatar_profile", value=gh, weight=0.3,
            source=SourceRef(provider="gravatar", url=url),
            note="public gravatar profile resolved"))
        return result
