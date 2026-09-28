"""
threat_actor_intelligence.engine — the ThreatActorIntelligenceEngine public API.

The single service-layer entry point used by the Telegram surface, ``app.py`` and
other Sombra Guardian engines. It composes the store, the ATT&CK/CAPEC knowledge
bases, the report builders and the graph/timeline builders, and answers the core
questions from the spec:

    which reports mention this actor?          -> actor_report / mentions
    which aliases refer to the same actor?     -> resolve_actor / merge_candidates
    which malware families are associated?     -> actor_report.malware_relationships
    which public IOCs belong to campaigns?     -> campaign_report.iocs
    which infrastructure overlaps campaigns?   -> infrastructure_overlaps
    which ATT&CK techniques are documented?    -> attack_coverage / technique lookup
    which countries/industries are targeted?   -> victimology
    what timeline of activity is supported?    -> timeline
    which sources corroborate the same thing?  -> corroborations

Every result carries evidence and confidence; nothing is fabricated and no
attribution is asserted beyond the cited public sources.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .configuration import TAIConfig, get_config
from .storage.sqlite_store import SQLiteStore
from .mitre.attack_engine import ATTACKEngine
from .mitre.capec_engine import CAPECEngine
from .mitre.tactic_mapper import TacticMapper
from .reports import (ActorReportBuilder, CampaignReportBuilder,
                      MalwareReportBuilder, render_report)
from .graph.actor_graph import ActorGraphBuilder
from .graph.campaign_graph import CampaignGraphBuilder
from .graph.infrastructure_graph import InfrastructureGraphBuilder
from .graph.mitre_graph import MitreGraphBuilder
from .timeline.activity_timeline import ActivityTimelineBuilder
from .timeline.campaign_timeline import CampaignTimelineBuilder
from .correlation.infrastructure_correlation import InfrastructureCorrelator
from .correlation.report_correlation import ReportCorrelator
from .models.ioc import detect_type, canonicalize, ioc_id, CanonicalizeError


class ThreatActorIntelligenceEngine:
    def __init__(self, *, config: Optional[TAIConfig] = None,
                 store: Optional[SQLiteStore] = None,
                 attack: Optional[ATTACKEngine] = None,
                 capec: Optional[CAPECEngine] = None):
        self.config = config or get_config()
        self.store = store or SQLiteStore(self.config.db_path)
        self.attack = attack or ATTACKEngine().load_seed()
        self.capec = capec or CAPECEngine().load_seed()
        self.actor_reports = ActorReportBuilder(self.store, attack=self.attack)
        self.campaign_reports = CampaignReportBuilder(self.store, attack=self.attack)
        self.malware_reports = MalwareReportBuilder(self.store, attack=self.attack)
        self.tactic_mapper = TacticMapper(self.attack)

    # -- actors ------------------------------------------------------------ #

    def resolve_actor(self, name_or_id: str):
        return (self.store.get_actor(name_or_id)
                or self.store.find_actor_by_name(name_or_id))

    def actor_report(self, name_or_id: str, *, fmt: str = "dict"):
        actor = self.resolve_actor(name_or_id)
        if actor is None:
            return None
        dossier = self.actor_reports.build(actor)
        return dossier if fmt == "dict" else render_report(dossier, fmt=fmt)

    def actors_for_alias(self, alias: str):
        return self.store.find_actors_by_alias(alias)

    def merge_candidates(self) -> List[Dict[str, Any]]:
        return self.store.kv_get("correlation", "merge_candidates", []) or []

    # -- campaigns --------------------------------------------------------- #

    def resolve_campaign(self, name_or_id: str):
        return (self.store.get_campaign(name_or_id)
                or self.store.find_campaign_by_name(name_or_id))

    def campaign_report(self, name_or_id: str, *, fmt: str = "dict"):
        camp = self.resolve_campaign(name_or_id)
        if camp is None:
            return None
        dossier = self.campaign_reports.build(camp)
        return dossier if fmt == "dict" else render_report(dossier, fmt=fmt)

    # -- malware ----------------------------------------------------------- #

    def resolve_family(self, name_or_id: str):
        return (self.store.get_family(name_or_id)
                or self.store.find_family_by_name(name_or_id))

    def malware_report(self, name_or_id: str, *, fmt: str = "dict"):
        fam = self.resolve_family(name_or_id)
        if fam is None:
            return None
        dossier = self.malware_reports.build(fam)
        return dossier if fmt == "dict" else render_report(dossier, fmt=fmt)

    # -- IOCs -------------------------------------------------------------- #

    def lookup_ioc(self, value: str) -> Optional[Dict[str, Any]]:
        t = detect_type(value)
        if t is None:
            return None
        try:
            canon = canonicalize(t, value)
        except CanonicalizeError:
            return None
        ioc = self.store.get_ioc(ioc_id(t, canon)) or self.store.find_ioc_by_value(canon)
        if ioc is None:
            return None
        rels = self.store.relationships_for("ioc", ioc.id)
        return {"ioc": ioc.to_dict(), "relationships": [r.to_dict() for r in rels]}

    # -- ATT&CK / CAPEC ---------------------------------------------------- #

    def technique(self, tid: str) -> Optional[Dict[str, Any]]:
        t = self.attack.resolve_technique(tid)
        if t is None:
            return None
        return {"technique": t.to_dict(),
                "mitigations": [m.to_dict() for m in self.attack.mitigations_for(
                    t.technique_id)],
                "capec": [p.to_dict() for p in self.capec.patterns_for_technique(
                    t.technique_id)]}

    def capec_pattern(self, cid: str) -> Optional[Dict[str, Any]]:
        p = self.capec.get(cid)
        return p.to_dict() if p else None

    def attack_coverage(self, name_or_id: str) -> Optional[Dict[str, Any]]:
        for resolver, kind in ((self.resolve_actor, "actor"),
                               (self.resolve_campaign, "campaign"),
                               (self.resolve_family, "malware")):
            obj = resolver(name_or_id)
            if obj is not None:
                return {"kind": kind, "subject": name_or_id,
                        "coverage": self.tactic_mapper.summary(obj.techniques)}
        return None

    # -- timeline ---------------------------------------------------------- #

    def timeline(self, name_or_id: str) -> Optional[Dict[str, Any]]:
        actor = self.resolve_actor(name_or_id)
        if actor is not None:
            campaigns = [c for c in (self.store.get_campaign(cid)
                                     for cid in actor.campaigns) if c]
            return ActivityTimelineBuilder().build(actor, campaigns=campaigns).to_dict()
        camp = self.resolve_campaign(name_or_id)
        if camp is not None:
            iocs = [i for i in (self.store.get_ioc(oid) for oid in camp.iocs) if i]
            return CampaignTimelineBuilder().build(camp, iocs=iocs).to_dict()
        return None

    # -- graphs ------------------------------------------------------------ #

    def _labels(self) -> Dict[str, str]:
        labels: Dict[str, str] = {}
        for a in self.store.iter_actors(limit=5000):
            labels[a.actor_id] = a.canonical_name
        for c in self.store.iter_campaigns(limit=5000):
            labels[c.campaign_id] = c.campaign_name
        for m in self.store.iter_families(limit=5000):
            labels[m.family_id] = m.family_name
        return labels

    def actor_graph(self, name_or_id: str, *, fmt: str = "json") -> Optional[str]:
        actor = self.resolve_actor(name_or_id)
        if actor is None:
            return None
        rels = self.store.relationships_for("actor", actor.actor_id)
        g = ActorGraphBuilder().build(actor, relationships=rels, labels=self._labels())
        return g.export(fmt)

    def campaign_graph(self, name_or_id: str, *, fmt: str = "json") -> Optional[str]:
        camp = self.resolve_campaign(name_or_id)
        if camp is None:
            return None
        rels = self.store.relationships_for("campaign", camp.campaign_id)
        g = CampaignGraphBuilder().build(camp, relationships=rels, labels=self._labels())
        return g.export(fmt)

    def infrastructure_graph(self, *, fmt: str = "json", limit: int = 500
                             ) -> str:
        nodes = list(self.store.iter_infrastructure(limit=limit))
        res = InfrastructureCorrelator(
            min_signals=self.config.min_overlap_signals).correlate(nodes)
        g = InfrastructureGraphBuilder().build(
            nodes, overlap_relationships=res.relationships, labels=self._labels())
        return g.export(fmt)

    def mitre_graph(self, name_or_id: str, *, fmt: str = "json") -> Optional[str]:
        for resolver, kind, idf, label in (
                (self.resolve_actor, "actor", "actor_id", "canonical_name"),
                (self.resolve_campaign, "campaign", "campaign_id", "campaign_name")):
            obj = resolver(name_or_id)
            if obj is not None:
                g = MitreGraphBuilder(self.attack).build(
                    subject_id=getattr(obj, idf), subject_type=kind,
                    technique_ids=obj.techniques,
                    subject_label=getattr(obj, label))
                return g.export(fmt)
        return None

    # -- infrastructure / corroboration ----------------------------------- #

    def infrastructure_overlaps(self, *, limit: int = 500) -> Dict[str, Any]:
        nodes = list(self.store.iter_infrastructure(limit=limit))
        corr = InfrastructureCorrelator(min_signals=self.config.min_overlap_signals)
        res = corr.correlate(nodes)
        return {"relationships": [r.to_dict() for r in res.relationships],
                "clusters": corr.clusters(nodes)}

    def corroborations(self, *, limit: int = 5000) -> List[Dict[str, Any]]:
        reports = list(self.store.iter_reports(limit=limit))
        return [c.to_dict() for c in ReportCorrelator().corroborations(reports)
                if c.corroborated]

    # -- summary ----------------------------------------------------------- #

    def stats(self) -> Dict[str, Any]:
        return {"store": self.store.stats(), "attack": self.attack.stats(),
                "capec": self.capec.stats()}


__all__ = ["ThreatActorIntelligenceEngine"]
