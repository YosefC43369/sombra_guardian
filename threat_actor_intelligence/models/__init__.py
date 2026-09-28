"""
threat_actor_intelligence.models — the typed CTI domain layer.

Pure data + epistemics: no I/O, no telegram, no sqlite. Everything round-trips
through ``to_dict``/``from_dict`` losslessly and every analytical object anchors
to evidence with an explainable confidence. Imported by every other layer; the
architecture tests assert this package imports nothing outward.
"""

from .evidence import (TLP, SourceClass, SOURCE_CLASS_WEIGHT, EvidenceRef,
                       EvidenceBundle)
from .confidence import (AssertionKind, ConfidenceModel, Assertion, Limitation,
                         band_for, confidence_from_evidence, STANDING_LIMITATIONS)
from .relation import ObjectType, RelationType, Relationship
from .ioc import IOC, IOCType, CanonicalizeError, canonicalize, detect_type, ioc_id
from .technique import (ATTACKDomain, Tactic, Technique, Mitigation, CAPECPattern,
                        ENTERPRISE_TACTICS, tactic_order, is_technique_id,
                        is_tactic_id, normalize_technique_id)
from .software import SoftwareType, Software
from .victimology import (SECTORS, normalize_sector, TargetingConfidence,
                          VictimObservation, Victimology)
from .threat_actor import ThreatActor, ActorType, Alias, slugify
from .campaign import Campaign
from .malware_family import MalwareFamily
from .infrastructure import InfraType, Infrastructure
from .report import Report, content_fingerprint

__all__ = [
    # evidence / confidence
    "TLP", "SourceClass", "SOURCE_CLASS_WEIGHT", "EvidenceRef", "EvidenceBundle",
    "AssertionKind", "ConfidenceModel", "Assertion", "Limitation", "band_for",
    "confidence_from_evidence", "STANDING_LIMITATIONS",
    # relations
    "ObjectType", "RelationType", "Relationship",
    # ioc
    "IOC", "IOCType", "CanonicalizeError", "canonicalize", "detect_type", "ioc_id",
    # mitre
    "ATTACKDomain", "Tactic", "Technique", "Mitigation", "CAPECPattern",
    "ENTERPRISE_TACTICS", "tactic_order", "is_technique_id", "is_tactic_id",
    "normalize_technique_id", "SoftwareType", "Software",
    # victimology
    "SECTORS", "normalize_sector", "TargetingConfidence", "VictimObservation",
    "Victimology",
    # entities
    "ThreatActor", "ActorType", "Alias", "slugify", "Campaign", "MalwareFamily",
    "InfraType", "Infrastructure", "Report", "content_fingerprint",
]
