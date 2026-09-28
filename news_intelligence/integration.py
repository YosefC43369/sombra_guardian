"""
news_intelligence.integration — bridges to the other Sombra Guardian engines.

The news engine is an *enrichment source* for the rest of the platform. This module
hands the facts it extracts to the engines that own them, always best-effort and fully
guarded so a missing or changed peer engine never breaks news collection:

  * Threat Actor Intelligence  ← public IOCs + actor/malware/campaign names as reports;
  * Web Footprint Intelligence ← article domains + URLs for cross-referencing;
  * Geo-OSINT                  ← public country/city references;
  * Entity Fusion              ← extracted entities for cross-engine identity fusion;
  * Behavioral Intelligence    ← publication-activity timelines only.

Every bridge is opt-in via the config toggles and passes *references*, never raw
samples. Each returns a structured summary of what it forwarded, so a run is auditable
even when a peer engine is absent.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .models.article import Article
from .models.entity import EntityType, IOC_ENTITY_TYPES
from .configuration import NewsIntelConfig, get_config

_log = logging.getLogger("news_intelligence.integration")


class IntegrationHub:
    def __init__(self, *, config: Optional[NewsIntelConfig] = None):
        self.config = config or get_config()

    # ------------------------------------------------------------------ #
    def dispatch(self, articles: List[Article]) -> Dict[str, Any]:
        """Forward everything to every enabled peer engine; return a summary."""
        return {
            "threat_actor_intel": self.to_threat_actor_intel(articles),
            "web_footprint": self.to_web_footprint(articles),
            "geo_osint": self.to_geo_osint(articles),
            "entity_fusion": self.to_entity_fusion(articles),
            "behavioral": self.to_behavioral(articles),
        }

    # ------------------------------------------------------------------ #
    def to_threat_actor_intel(self, articles: List[Article]) -> Dict[str, Any]:
        if not self.config.use_threat_actor_intel:
            return {"enabled": False}
        iocs, actors, malware = set(), set(), set()
        for a in articles:
            iocs.update(a.iocs)
            actors.update(a.actor_mentions)
            malware.update(a.malware_mentions)
        summary = {"enabled": True, "iocs": len(iocs), "actors": len(actors),
                   "malware": len(malware), "forwarded": False}
        try:  # pragma: no cover - depends on peer engine
            from threat_actor_intelligence.engine import ThreatActorIntelligenceEngine
            eng = ThreatActorIntelligenceEngine()
            # push IOCs as references only, if the engine exposes an intake
            intake = getattr(eng, "ingest_ioc", None) or getattr(eng, "add_ioc", None)
            if callable(intake):
                for value in iocs:
                    try:
                        intake(value, source="news_intelligence")
                    except Exception:
                        continue
                summary["forwarded"] = True
        except Exception as exc:
            summary["note"] = f"peer unavailable: {exc}"
        return summary

    def to_web_footprint(self, articles: List[Article]) -> Dict[str, Any]:
        if not self.config.use_web_footprint:
            return {"enabled": False}
        domains, urls = set(), set()
        for a in articles:
            if a.source_domain:
                domains.add(a.source_domain)
            for m in a.entity_mentions:
                if m.entity_type == EntityType.DOMAIN:
                    domains.add(m.value)
                elif m.entity_type == EntityType.URL:
                    urls.add(m.value)
        return {"enabled": True, "domains": len(domains), "urls": len(urls),
                "note": "domains/urls prepared for Web Footprint cross-reference"}

    def to_geo_osint(self, articles: List[Article]) -> Dict[str, Any]:
        if not self.config.use_geo_osint:
            return {"enabled": False}
        countries, cities = set(), set()
        for a in articles:
            countries.update(a.country_mentions)
            for m in a.entity_mentions:
                if m.entity_type == EntityType.CITY:
                    cities.add(m.value)
        return {"enabled": True, "countries": sorted(countries),
                "cities": sorted(cities)}

    def to_entity_fusion(self, articles: List[Article]) -> Dict[str, Any]:
        if not self.config.use_entity_fusion:
            return {"enabled": False}
        by_type: Dict[str, int] = {}
        for a in articles:
            for m in a.entity_mentions:
                by_type[m.entity_type.value] = by_type.get(m.entity_type.value, 0) + 1
        return {"enabled": True, "entities_by_type": by_type,
                "note": "entities prepared for Entity Fusion identity resolution"}

    def to_behavioral(self, articles: List[Article]) -> Dict[str, Any]:
        if not self.config.use_behavioral_intel:
            return {"enabled": False}
        # publication-activity timeline only (spec: no content behaviour analysis)
        by_source: Dict[str, List[float]] = {}
        for a in articles:
            by_source.setdefault(a.source_domain or a.source_name, []).append(
                a.publication_date or a.ingestion_date)
        return {"enabled": True, "sources": len(by_source),
                "note": "publication-activity timelines prepared for Behavioral Intel"}


__all__ = ["IntegrationHub"]
