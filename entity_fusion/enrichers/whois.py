"""
entity_fusion.enrichers.whois — registration data via RDAP (the modern,
JSON-over-HTTPS successor to port-43 WHOIS).

RDAP is public and structured, so parsing is deterministic (unlike free-text
WHOIS). This enricher queries ``rdap.org`` (which redirects to the authoritative
registry) for a domain and extracts the registrar, registrant organisation
(when not redacted) and nameservers, emitting an organisation entity when a
registrant org is present. No key. GDPR/registry redaction is common — a
redacted record simply yields fewer derived fields, never an error.
"""

from __future__ import annotations

from typing import Any

from ..entity import Entity, EntityType, Evidence, SourceRef, Relationship, RelationType
from .. import normalization as norm
from .base import Enricher, EnrichmentResult


def _extract_org(entities: list) -> str:
    """Pull an organisation name from RDAP vCard entities, if present."""
    for ent in entities or []:
        roles = ent.get("roles", [])
        if "registrant" in roles or "registrar" in roles:
            vcard = ent.get("vcardArray", [])
            if len(vcard) == 2:
                for field in vcard[1]:
                    if len(field) >= 4 and field[0] in ("org", "fn"):
                        return str(field[3])
    return ""


class WhoisEnricher(Enricher):
    name = "whois"
    handles = (EntityType.DOMAIN,)

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:
        result = EnrichmentResult()
        domain = norm.canonical_domain(entity.value)
        if not domain:
            result.ok = False
            result.reason = "invalid domain"
            return result
        url = f"https://rdap.org/domain/{domain}"
        resp = await client.get_json(url)
        if not resp.ok:
            result.ok = resp.status == 404
            result.reason = "no rdap record" if resp.status == 404 else resp.reason
            return result
        try:
            data = resp.json()
        except Exception:
            result.ok = False
            result.reason = "unparseable rdap"
            return result

        nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
                       if ns.get("ldhName")]
        if nameservers:
            result.derived["nameservers"] = nameservers
        org = _extract_org(data.get("entities", []))
        if org:
            result.derived["registrant"] = org
            result.derived["organization"] = org
            child = Entity(type=EntityType.ORGANIZATION, value=org)
            child.add_source(SourceRef(provider="whois", url=url))
            child.add_relationship(Relationship(target_id=entity.id,
                                                type=RelationType.OWNS))
            result.entities.append(child)
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                result.derived["registered_at"] = event.get("eventDate", "")
        result.evidence.append(Evidence(
            kind="rdap_record", value=domain, weight=0.2,
            source=SourceRef(provider="whois", url=url),
            note="RDAP registration record resolved"))
        return result
