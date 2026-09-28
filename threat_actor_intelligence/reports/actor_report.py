"""
threat_actor_intelligence.reports.actor_report — the actor dossier.

Assembles a complete, evidence-graded dossier for one ThreatActor by pulling its
related entities from the store and folding in the ATT&CK coverage and timeline.
The dossier is a plain dict with the spec's sections (Executive Summary, Aliases,
Campaign Timeline, Malware Relationships, ATT&CK Coverage, Infrastructure,
Victimology, Public Reports, Evidence, Confidence, Limitations). Format renderers
(markdown/html/json/csv) turn this one structure into output, so every format
carries the same facts, labels and limitations.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..models.threat_actor import ThreatActor
from ..mitre.attack_engine import ATTACKEngine
from ..mitre.tactic_mapper import TacticMapper
from ..timeline.activity_timeline import ActivityTimelineBuilder


class ActorReportBuilder:
    def __init__(self, store, *, attack: Optional[ATTACKEngine] = None):
        self.store = store
        self.attack = attack
        self.tactic_mapper = TacticMapper(attack)
        self.timeline_builder = ActivityTimelineBuilder()

    def build(self, actor_id: str, *, now: Optional[float] = None
              ) -> Optional[Dict[str, Any]]:
        actor = self.store.get_actor(actor_id) if isinstance(actor_id, str) else actor_id
        if actor is None:
            return None
        now = now if now is not None else time.time()
        if actor.confidence is None:
            actor.recompute_confidence(now=now)

        campaigns = [c for c in (self.store.get_campaign(cid)
                                 for cid in actor.campaigns) if c]
        families = [m for m in (self.store.get_family(mid)
                                for mid in actor.malware_families) if m]
        infra = [n for n in (self.store.get_infrastructure(iid)
                             for iid in actor.infrastructure) if n]
        reports = [r for r in (self.store.get_report(rid)
                               for rid in actor.report_ids) if r]
        rels = self.store.relationships_for("actor", actor.actor_id)
        timeline = self.timeline_builder.build(actor, campaigns=campaigns)
        coverage = self.tactic_mapper.summary(actor.techniques)

        return {
            "kind": "actor",
            "generated_at": now,
            "executive_summary": self._exec_summary(actor, campaigns, families),
            "identity": {
                "actor_id": actor.actor_id, "canonical_name": actor.canonical_name,
                "actor_type": actor.actor_type.value,
                "attack_group_id": actor.attack_group_id,
                "suspected_origin": actor.suspected_origin,
                "motivations": actor.motivations,
                "first_seen": actor.first_seen, "last_seen": actor.last_seen,
            },
            "aliases": [a.to_dict() for a in actor.aliases],
            "campaign_timeline": timeline.to_dict(),
            "campaigns": [{"campaign_id": c.campaign_id, "name": c.campaign_name,
                           "first_observed": c.first_observed,
                           "last_observed": c.last_observed,
                           "confidence": (c.confidence.score if c.confidence else 0)}
                          for c in campaigns],
            "malware_relationships": [
                {"family_id": m.family_id, "name": m.family_name,
                 "category": m.category, "techniques": m.techniques,
                 "hashes_known": len(m.known_hashes)} for m in families],
            "attack_coverage": coverage,
            "infrastructure": [
                {"infra_id": n.infra_id, "type": n.infra_type.value,
                 "value": n.value, "asn": n.asn, "country": n.country,
                 "role": n.role} for n in infra],
            "victimology": actor.victimology.to_dict(),
            "public_reports": [
                {"report_id": r.report_id, "title": r.title, "url": r.url,
                 "source": r.source, "vendor": r.vendor,
                 "published_at": r.published_at} for r in reports],
            "relationships": [r.to_dict() for r in rels],
            "evidence": actor.evidence.to_list(),
            "confidence": actor.confidence.to_dict() if actor.confidence else None,
            "limitations": ([l.to_dict() for l in actor.confidence.limitations]
                            if actor.confidence else []),
        }

    def _exec_summary(self, actor: ThreatActor, campaigns: List, families: List
                      ) -> str:
        conf = actor.confidence.band if actor.confidence else "unknown"
        alias_str = ", ".join(a.name for a in actor.aliases[:5]) or "no tracked aliases"
        parts = [
            f"{actor.canonical_name} is a {actor.actor_type.value} actor tracked "
            f"under {len(actor.aliases)} public alias(es) ({alias_str}).",
            f"Public reporting associates it with {len(campaigns)} campaign(s) and "
            f"{len(families)} malware family(ies), across "
            f"{actor.evidence.distinct_count()} independent source(s).",
            f"Overall evidence confidence: {conf}.",
        ]
        if actor.suspected_origin:
            parts.append(f"Suspected origin, as reported: {actor.suspected_origin} "
                         f"(reported attribution only, not independently established).")
        return " ".join(parts)


__all__ = ["ActorReportBuilder"]
