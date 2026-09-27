"""
entity_fusion.enrichers.github — resolve a PUBLIC GitHub user profile.

The GitHub REST API's ``/users/{login}`` endpoint returns a user's public
profile: name, company, blog/website, public email (only if they published it),
location and public repo count. This enricher turns those into discovered
entities (a website, an email if public, an organisation) linked to the username.
Unauthenticated requests work at a low rate limit; a ``GITHUB_TOKEN`` in the
environment (never hard-coded) raises the limit when present.
"""

from __future__ import annotations

from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult


class GitHubEnricher(Enricher):
    name = "github"
    handles = (EntityType.USERNAME,)
    env_key = "GITHUB_TOKEN"       # optional; raises rate limit when set

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        login = norm.normalize_text(entity.value, casefold=False).strip().lstrip("@")
        if not login or " " in login:
            result.ok = False
            result.reason = "not a plausible github login"
            return result
        headers = {"Accept": "application/vnd.github+json"}
        token = self.api_key()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = f"https://api.github.com/users/{login}"
        resp = await client.get_json(url, headers=headers)
        if not resp.ok:
            result.ok = resp.status == 404
            result.reason = "no such github user" if resp.status == 404 else resp.reason
            return result
        try:
            data = resp.json()
        except Exception:
            result.ok = False
            result.reason = "unparseable github response"
            return result

        result.derived["github_login"] = data.get("login", login)
        if data.get("name"):
            result.derived["display_name"] = data["name"]
        if data.get("company"):
            org_name = str(data["company"]).lstrip("@")
            result.derived["organization"] = org_name
            child = Entity(type=EntityType.ORGANIZATION, value=org_name)
            child.add_source(SourceRef(provider="github", url=url))
            child.add_relationship(Relationship(target_id=entity.id,
                                                type=RelationType.SHARES_ORG))
            result.entities.append(child)
        if data.get("blog"):
            site = norm.canonical_url(str(data["blog"]))
            if site:
                result.derived["website"] = site
                child = Entity(type=EntityType.WEBSITE, value=site)
                child.add_source(SourceRef(provider="github", url=url))
                result.entities.append(child)
        if data.get("email"):
            canon = norm.canonical_email(str(data["email"]))
            if canon:
                child = Entity(type=EntityType.EMAIL, value=canon)
                child.add_source(SourceRef(provider="github", url=url,
                                           detail="public profile email"))
                child.add_relationship(Relationship(target_id=entity.id,
                                                    type=RelationType.OWNS))
                result.entities.append(child)
        if data.get("location"):
            result.derived["location"] = str(data["location"])
        result.evidence.append(Evidence(
            kind="github_profile", value=data.get("login", login), weight=0.3,
            source=SourceRef(provider="github", url=url),
            note="public github profile resolved"))
        return result
