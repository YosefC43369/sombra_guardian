"""
threat_actor_intelligence.pipeline — resolve ingest results into stored entities.

The pipeline is the resolution stage between raw ingestion and correlation. It
takes an ``IngestResult`` (reports, IOCs, structured or named actors/malware/
campaigns, techniques) and folds it into the store *idempotently*:

  * reports deduplicate by content hash (incremental ingestion);
  * structured entities (from STIX/OTX) upsert-merge into existing rows by id,
    unioning aliases, references and evidence, then recompute confidence;
  * free-text names resolve to an existing actor/family/campaign by name or
    alias, or create a minimal evidence-anchored stub — never a blind merge;
  * IOCs batch-write and link to their named campaign/malware/actor;
  * ATT&CK technique mapping runs over each report's text + explicit ids and links
    techniques onto the entities the report is about;
  * intra-report co-occurrence emits CORRELATED relationships (actor↔malware,
    actor↔campaign, campaign↔malware) each citing that report as evidence.

Everything an entity gains carries the citing report as an ``EvidenceRef`` so
provenance is preserved end to end.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models.threat_actor import ThreatActor, ActorType, Alias, slugify
from .models.campaign import Campaign
from .models.malware_family import MalwareFamily
from .models.infrastructure import Infrastructure
from .models.ioc import IOC
from .models.report import Report
from .models.relation import Relationship, ObjectType, RelationType
from .models.evidence import EvidenceRef
from .ingestion.base import IngestResult
from .mitre.attack_engine import ATTACKEngine
from .mitre.technique_mapper import TechniqueMapper
from .mitre.software_mapper import SoftwareMapper
from .correlation.base import build_relationship


@dataclass
class PipelineStats:
    reports_new: int = 0
    reports_skipped: int = 0
    actors_upserted: int = 0
    campaigns_upserted: int = 0
    families_upserted: int = 0
    infrastructure_upserted: int = 0
    iocs_written: int = 0
    relationships: int = 0
    techniques_linked: int = 0

    def to_dict(self) -> Dict[str, int]:
        return self.__dict__.copy()


class ResolutionPipeline:
    def __init__(self, store, *, attack: Optional[ATTACKEngine] = None,
                 now: Optional[float] = None):
        self.store = store
        self.attack = attack
        self.tech_mapper = TechniqueMapper(attack)
        self.software_mapper = SoftwareMapper(attack)
        self._now = now

    def now(self) -> float:
        return self._now if self._now is not None else time.time()

    # -- entity upsert helpers -------------------------------------------- #

    def _upsert_actor(self, incoming: ThreatActor, stats: PipelineStats
                      ) -> ThreatActor:
        existing = self.store.get_actor(incoming.actor_id) \
            or self.store.find_actor_by_name(incoming.canonical_name)
        if existing is None:
            incoming.recompute_confidence(now=self.now())
            self.store.save_actor(incoming)
            stats.actors_upserted += 1
            return incoming
        for a in incoming.aliases:
            existing.add_alias(a)
        for attr in ("campaigns", "malware_families", "infrastructure",
                     "techniques", "software", "references", "report_ids",
                     "motivations"):
            for v in getattr(incoming, attr, []):
                existing.link(attr, v)
        for ref in incoming.evidence.refs:
            existing.evidence.add(ref)
        if incoming.actor_type != ActorType.UNKNOWN and \
                existing.actor_type == ActorType.UNKNOWN:
            existing.actor_type = incoming.actor_type
        if incoming.attack_group_id and not existing.attack_group_id:
            existing.attack_group_id = incoming.attack_group_id
        if incoming.suspected_origin and not existing.suspected_origin:
            existing.suspected_origin = incoming.suspected_origin
        existing.touch(incoming.first_seen or self.now())
        existing.touch(incoming.last_seen or self.now())
        existing.recompute_confidence(now=self.now())
        self.store.save_actor(existing)
        stats.actors_upserted += 1
        return existing

    def _upsert_campaign(self, incoming: Campaign, stats: PipelineStats) -> Campaign:
        existing = self.store.get_campaign(incoming.campaign_id) \
            or self.store.find_campaign_by_name(incoming.campaign_name)
        if existing is None:
            incoming.recompute_confidence(now=self.now())
            self.store.save_campaign(incoming)
            stats.campaigns_upserted += 1
            return incoming
        for a in incoming.aliases:
            existing.add_alias(a)
        for attr in ("actors", "malware_families", "infrastructure", "iocs",
                     "techniques", "references", "report_ids"):
            for v in getattr(incoming, attr, []):
                existing.link(attr, v)
        for ref in incoming.evidence.refs:
            existing.evidence.add(ref)
        for obs in incoming.victimology.observations:
            existing.victimology.add(obs)
        if incoming.summary and not existing.summary:
            existing.summary = incoming.summary
        existing.touch(incoming.first_observed or self.now())
        existing.touch(incoming.last_observed or self.now())
        existing.recompute_confidence(now=self.now())
        self.store.save_campaign(existing)
        stats.campaigns_upserted += 1
        return existing

    def _upsert_family(self, incoming: MalwareFamily, stats: PipelineStats
                       ) -> MalwareFamily:
        existing = self.store.get_family(incoming.family_id) \
            or self.store.find_family_by_name(incoming.family_name)
        if existing is None:
            self.software_mapper.enrich(incoming)
            incoming.recompute_confidence(now=self.now())
            self.store.save_family(incoming)
            stats.families_upserted += 1
            return incoming
        for a in incoming.aliases:
            existing.add_alias(a)
        for attr in ("actors", "campaigns", "techniques", "capec", "platforms",
                     "languages", "references", "report_ids"):
            for v in getattr(incoming, attr, []):
                existing.link(attr, v)
        for h in incoming.known_hashes:
            existing.add_hash(h)
        for ref in incoming.evidence.refs:
            existing.evidence.add(ref)
        if incoming.category and not existing.category:
            existing.category = incoming.category
        if incoming.attack_software_id and not existing.attack_software_id:
            existing.attack_software_id = incoming.attack_software_id
        self.software_mapper.enrich(existing)
        existing.touch(incoming.first_seen or self.now())
        existing.touch(incoming.last_seen or self.now())
        existing.recompute_confidence(now=self.now())
        self.store.save_family(existing)
        stats.families_upserted += 1
        return existing

    def _upsert_infrastructure(self, incoming: Infrastructure, stats: PipelineStats
                               ) -> Infrastructure:
        existing = self.store.get_infrastructure(incoming.infra_id)
        if existing is None:
            incoming.recompute_confidence(now=self.now())
            self.store.save_infrastructure(incoming)
            stats.infrastructure_upserted += 1
            return incoming
        for attr in ("resolves_to", "domains", "certificates", "campaigns",
                     "actors", "malware_families", "references", "report_ids"):
            for v in getattr(incoming, attr, []):
                existing.link(attr, v)
        for ref in incoming.evidence.refs:
            existing.evidence.add(ref)
        if incoming.asn and not existing.asn:
            existing.asn = incoming.asn
        if incoming.country and not existing.country:
            existing.country = incoming.country
        existing.touch(incoming.first_seen or self.now())
        existing.touch(incoming.last_seen or self.now())
        existing.recompute_confidence(now=self.now())
        self.store.save_infrastructure(existing)
        stats.infrastructure_upserted += 1
        return existing

    # -- name resolution --------------------------------------------------- #

    def _resolve_actor_name(self, name: str, ev: EvidenceRef, report: Optional[Report],
                            stats: PipelineStats) -> Optional[ThreatActor]:
        if not name.strip():
            return None
        actor = self.store.find_actor_by_name(name)
        if actor is None:
            actor = ThreatActor(canonical_name=name.strip(),
                                first_seen=ev.observed_at or self.now(),
                                last_seen=ev.observed_at or self.now())
        actor.evidence.add(ev)
        if report:
            actor.link("report_ids", report.report_id)
        actor.touch(ev.observed_at or self.now())
        actor.recompute_confidence(now=self.now())
        self.store.save_actor(actor)
        return actor

    def _resolve_family_name(self, name: str, ev: EvidenceRef, report: Optional[Report],
                             stats: PipelineStats) -> Optional[MalwareFamily]:
        if not name.strip():
            return None
        fam = self.store.find_family_by_name(name)
        if fam is None:
            fam = MalwareFamily(family_name=name.strip(),
                                first_seen=ev.observed_at or self.now(),
                                last_seen=ev.observed_at or self.now())
        fam.evidence.add(ev)
        if report:
            fam.link("report_ids", report.report_id)
        self.software_mapper.enrich(fam)
        fam.touch(ev.observed_at or self.now())
        fam.recompute_confidence(now=self.now())
        self.store.save_family(fam)
        return fam

    # -- main entry -------------------------------------------------------- #

    def process(self, result: IngestResult) -> PipelineStats:
        stats = PipelineStats()

        # 1) reports (dedup by content hash), keep the resolved report objects
        stored_reports: List[Report] = []
        for report in result.reports:
            if self.store.report_exists(content_hash=report.content_hash):
                stats.reports_skipped += 1
                stored_reports.append(report)
                continue
            self._map_report_techniques(report)
            self.store.save_report(report)
            stats.reports_new += 1
            stored_reports.append(report)

        # 2) structured entities from STIX/OTX
        for actor in result.actors:
            self._upsert_actor(actor, stats)
        for camp in result.campaigns:
            self._upsert_campaign(camp, stats)
        for fam in result.families:
            self._upsert_family(fam, stats)
        for node in result.infrastructure:
            self._upsert_infrastructure(node, stats)

        # 3) IOCs (batch)
        if result.iocs:
            stats.iocs_written += self.store.save_iocs(result.iocs)

        # 4) per-report resolution + intra-report relationships
        rels: List[Relationship] = []
        for report in stored_reports:
            rels.extend(self._resolve_report(report, stats))

        # 5) structured relationships (STIX/OTX)
        for rel in result.relationships:
            rels.append(rel)

        if rels:
            stats.relationships += self.store.save_relationships(rels)
            # 6) denormalize edges into entity reference lists (bidirectional),
            # so dossiers list the campaigns/malware/techniques an entity is tied
            # to without re-walking the relationship table.
            self._denormalize(rels)
        return stats

    # -- denormalization --------------------------------------------------- #

    # (src_type, rel_type, dst_type) -> (src_list_field, dst_list_field|None)
    _DENORM = {
        ("actor", "uses", "malware"): ("malware_families", "actors"),
        ("actor", "uses", "infrastructure"): ("infrastructure", "actors"),
        ("actor", "uses", "technique"): ("techniques", None),
        ("actor", "uses", "software"): ("software", None),
        ("campaign", "attributed_to", "actor"): ("actors", "campaigns"),
        ("campaign", "uses", "malware"): ("malware_families", "campaigns"),
        ("campaign", "uses", "infrastructure"): ("infrastructure", "campaigns"),
        ("campaign", "uses", "technique"): ("techniques", None),
        ("campaign", "indicates", "ioc"): ("iocs", None),
        ("campaign", "uses", "ioc"): ("iocs", None),
        ("malware", "uses", "technique"): ("techniques", None),
    }

    def _load(self, cache, obj_type, obj_id):
        key = (obj_type, obj_id)
        if key in cache:
            return cache[key]
        loader = {"actor": self.store.get_actor,
                  "campaign": self.store.get_campaign,
                  "malware": self.store.get_family,
                  "infrastructure": self.store.get_infrastructure}.get(obj_type)
        obj = loader(obj_id) if loader else None
        cache[key] = obj
        return obj

    def _save(self, obj_type, obj):
        saver = {"actor": self.store.save_actor,
                 "campaign": self.store.save_campaign,
                 "malware": self.store.save_family,
                 "infrastructure": self.store.save_infrastructure}.get(obj_type)
        if saver:
            saver(obj)

    def _denormalize(self, rels: List[Relationship]) -> None:
        cache: Dict[tuple, Any] = {}
        touched: set = set()
        for rel in rels:
            key = (rel.src_type.value, rel.rel_type.value, rel.dst_type.value)
            mapping = self._DENORM.get(key)
            if not mapping:
                continue
            src_field, dst_field = mapping
            src = self._load(cache, rel.src_type.value, rel.src_id)
            if src is not None and hasattr(src, src_field):
                src.link(src_field, rel.dst_id)
                touched.add((rel.src_type.value, rel.src_id))
            if dst_field:
                dst = self._load(cache, rel.dst_type.value, rel.dst_id)
                if dst is not None and hasattr(dst, dst_field):
                    dst.link(dst_field, rel.src_id)
                    touched.add((rel.dst_type.value, rel.dst_id))
        for (otype, oid) in touched:
            obj = cache.get((otype, oid))
            if obj is not None:
                self._save(otype, obj)

    def _map_report_techniques(self, report: Report) -> None:
        text = f"{report.title}\n{report.summary}"
        hits = self.tech_mapper.map_text(text)
        for h in hits:
            report.link("technique_ids", h.technique_id)

    def _resolve_report(self, report: Report, stats: PipelineStats
                        ) -> List[Relationship]:
        ev = report.as_evidence()
        rels: List[Relationship] = []
        actors = [a for a in (self._resolve_actor_name(n, ev, report, stats)
                              for n in set(report.actor_names)) if a]
        families = [f for f in (self._resolve_family_name(n, ev, report, stats)
                                for n in set(report.malware_names)) if f]

        # link report ids back onto the report row
        if actors or families:
            for a in actors:
                report.link("actor_ids", a.actor_id)
            for f in families:
                report.link("family_ids", f.family_id)
            self.store.save_report(report)

        # intra-report co-occurrence relationships (CORRELATED, cite this report)
        for a in actors:
            for f in families:
                rels.append(build_relationship(
                    src_type="actor", src_id=a.actor_id, rel_type="uses",
                    dst_type="malware", dst_id=f.family_id,
                    signal=f"co-reported in {report.source or report.vendor}",
                    evidence=[ev], now=self.now(), weight=0.5))
                # link references onto the entities
                a.link("malware_families", f.family_id)
                f.link("actors", a.actor_id)
                self.store.save_actor(a)
                self.store.save_family(f)

        # technique links to actors
        for tid in report.technique_ids:
            for a in actors:
                a.link("techniques", tid)
                self.store.save_actor(a)
                rels.append(build_relationship(
                    src_type="actor", src_id=a.actor_id, rel_type="uses",
                    dst_type="technique", dst_id=tid,
                    signal="technique documented in report", evidence=[ev],
                    now=self.now(), weight=0.4))
                stats.techniques_linked += 1
            for f in families:
                f.link("techniques", tid)
                self.store.save_family(f)
        return rels


__all__ = ["ResolutionPipeline", "PipelineStats"]
