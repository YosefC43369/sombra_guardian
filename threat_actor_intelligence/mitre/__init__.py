"""
threat_actor_intelligence.mitre — ATT&CK / CAPEC knowledge and mapping.

``ATTACKEngine`` and ``CAPECEngine`` hold the reference catalogs (loaded from the
public STIX/JSON exports, with offline seeds); the three mappers turn observed
free text / malware names into validated technique, tactic and software mappings.
"""

from .attack_engine import ATTACKEngine, ATTACKGroup
from .capec_engine import CAPECEngine
from .technique_mapper import TechniqueMapper, TechniqueHit, KEYWORD_TECHNIQUES
from .tactic_mapper import TacticMapper, TacticCoverage
from .software_mapper import SoftwareMapper, SoftwareMatch

__all__ = ["ATTACKEngine", "ATTACKGroup", "CAPECEngine", "TechniqueMapper",
           "TechniqueHit", "KEYWORD_TECHNIQUES", "TacticMapper", "TacticCoverage",
           "SoftwareMapper", "SoftwareMatch"]
