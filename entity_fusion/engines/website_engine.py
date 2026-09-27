"""
entity_fusion.engines.website_engine — derive correlation keys from a website
record offline: canonical URL, host domain, and social/link extraction from
metadata (title/description/links), plus static-host detection (GitHub Pages,
Netlify, Vercel, Cloudflare Pages). The HTTP fetch that populates title/favicon
is an enricher; this engine correlates on whatever the record already carries.
"""

from __future__ import annotations

import re

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult

# host substring → static-hosting provider label
_STATIC_HOSTS = {
    "github.io": "github_pages", "githubusercontent.com": "github_pages",
    "netlify.app": "netlify", "vercel.app": "vercel",
    "pages.dev": "cloudflare_pages", "web.app": "firebase",
    "firebaseapp.com": "firebase", "gitlab.io": "gitlab_pages",
    "surge.sh": "surge", "wordpress.com": "wordpress",
}

_SOCIAL_RE = re.compile(
    r"https?://(?:www\.)?(github|twitter|x|mastodon|linkedin|instagram|"
    r"facebook|youtube|t\.me|telegram|reddit|medium)\.[^\s\"'<>]+", re.IGNORECASE)


class WebsiteEngine(CorrelationEngine):
    name = "website_engine"
    handles = (EntityType.WEBSITE,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        canon = norm.canonical_url(entity.value)
        if canon:
            entity.normalized = canon
            result.derived["canonical_url"] = canon
        host = norm.canonical_domain(entity.value)
        if host:
            result.derived["host_domain"] = host
            child = Entity(type=EntityType.DOMAIN, value=host)
            child.add_source(SourceRef(provider="website", detail="website host"))
            child.add_relationship(Relationship(
                target_id=entity.id, type=RelationType.SHARES_DOMAIN))
            result.entities.append(child)
            for needle, label in _STATIC_HOSTS.items():
                if host.endswith(needle):
                    result.derived["static_host"] = label
                    break

        text = " ".join(str(entity.metadata.get(k, "")) for k in
                        ("html", "description", "links", "social", "bio"))
        socials = sorted({m.group(0) for m in _SOCIAL_RE.finditer(text)})
        if socials:
            result.derived["social_links"] = socials
            result.evidence.append(Evidence(
                kind="social_links", value=str(len(socials)), weight=0.1,
                note=f"{len(socials)} social link(s) on site"))
        return result
