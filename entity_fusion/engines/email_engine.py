"""
entity_fusion.engines.email_engine — canonicalize email addresses, compute the
public Gravatar hash, and extract embedded identifiers from an email or a text
blob (bio, contact page).

PUBLIC-DATA POSTURE. This engine derives the Gravatar identifier (an MD5 of the
lower-cased address, exactly as Gravatar's public API specifies) and canonical
alias forms. It does NOT query breach databases for arbitrary individuals; any
breach/exposure lookup in this repo is scoped to an organisation's own assets by
the authorization gate, never pointed at a private person. Nothing here contacts
the network — it is pure derivation.
"""

from __future__ import annotations

import re
import hashlib
from typing import List

from ..entity import Entity, EntityType, Evidence, SourceRef
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult

_EMAIL_FIND_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}")


def gravatar_hash(email: str) -> str:
    """The public Gravatar identifier: md5 of the trimmed, lower-cased address.
    (Gravatar's documented, intentionally-public avatar lookup key.)"""
    canon = (email or "").strip().lower()
    return hashlib.md5(canon.encode("utf-8")).hexdigest() if canon else ""


def extract_emails(text: str) -> List[str]:
    """Pull canonical email addresses out of free text (a bio/contact page),
    de-duplicated. Handles the common ``name [at] domain [dot] com`` defang."""
    if not text:
        return []
    # Un-defang common obfuscations, absorbing whitespace around the token so
    # "john [at] example [dot] com" collapses to "john@example.com".
    defanged = re.sub(r"\s*(?:\[at\]|\(at\)|\bat\b)\s*", "@", text, flags=re.IGNORECASE)
    defanged = re.sub(r"\s*(?:\[dot\]|\(dot\)|\bdot\b)\s*", ".", defanged, flags=re.IGNORECASE)
    found = set()
    for raw in _EMAIL_FIND_RE.findall(defanged):
        canon = norm.canonical_email(raw)
        if canon:
            found.add(canon)
    return sorted(found)


class EmailEngine(CorrelationEngine):
    name = "email_engine"
    handles = (EntityType.EMAIL,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        canon = norm.canonical_email(entity.value)
        if not canon:
            return result
        result.derived["canonical_email"] = canon
        result.derived["email_domain"] = norm.email_domain(canon)
        gh = gravatar_hash(canon)
        if gh:
            result.derived["gravatar_hash"] = gh
            result.evidence.append(Evidence(
                kind="gravatar_hash", value=gh, weight=0.0,
                note="public gravatar identifier derived from address"))
        # the local-part often equals a reused handle → alias for correlation
        local = canon.split("@", 1)[0]
        if local:
            entity.add_alias(local)
            result.derived["email_local"] = local
        return result


class BioEmailExtractor(CorrelationEngine):
    """A cross-type engine: given any entity with a bio/description, extract
    email entities embedded in it and return them as discovered entities linked
    back to the source. Demonstrates the engine→pipeline discovery path."""

    name = "bio_email_extractor"
    handles = ()   # any type with a bio

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        text = " ".join(str(entity.metadata.get(k, "")) for k in
                        ("bio", "description", "about", "contact"))
        for email in extract_emails(text):
            child = Entity(type=EntityType.EMAIL, value=email)
            child.add_source(SourceRef(provider=f"bio:{entity.type.value}",
                                       detail="extracted from profile text"))
            result.entities.append(child)
        if result.entities:
            result.evidence.append(Evidence(
                kind="emails_in_bio", value=str(len(result.entities)), weight=0.1,
                note="email(s) extracted from profile text"))
        return result
