"""
threat_actor_intelligence.reports.campaign_report — the campaign dossier.

Assembles the evidence-graded dossier for one Campaign: attributed actors, the
malware and infrastructure it used, its IOCs, ATT&CK coverage, victimology,
corroborating public reports, the dated timeline, evidence and confidence — the
same section structure as the actor dossier so renderers are shared.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..models.campaign import Campaign
from ..mitre.attack_engine import ATTACKEngine
from ..mitre.tactic_mapper import TacticMapper
from ..timeline.campaign_timeline import CampaignTimelineBuilder


class CampaignReportBuilder:
    def __init__(self, store, *, attack: Optional[ATTACKEngine] = None):
        self.store = store
        self.attack = attack
        self.tactic_mapper = TacticMapper(attack)
        self.timeline_builder = CampaignTimelineBuilder()

    def build(self, campaign_id, *, now: Optional[float] = None
              ) -> Optional[Dict[str, Any]]:
        camp = (self.store.get_campaign(campaign_id) if isinstance(campaign_id, str)
                else campaign_id)
        if camp is None:
            return None
        now = now if now is not None else time.time()
        if camp.confidence is None:
            camp.recompute_confidence(now=now)
        actors = [a for a in (self.store.get_actor(aid) for aid in camp.actors) if a]
        families = [m for m in (self.store.get_family(mid)
                                for mid in camp.malware_families) if m]
        infra = [n for n in (self.store.get_infrastructure(iid)
                             for iid in camp.infrastructure) if n]
        iocs = [i for i in (self.store.get_ioc(oid) for oid in camp.iocs) if i]
        rels = self.store.relationships_for("campaign", camp.campaign_id)
        timeline = self.timeline_builder.build(camp, iocs=iocs)
        coverage = self.tactic_mapper.summary(camp.techniques)

        return {
            "kind": "campaign",
            "generated_at": now,
            "executive_summary": self._exec_summary(camp, actors, families, iocs),
            "identity": {"campaign_id": camp.campaign_id,
                         "campaign_name": camp.campaign_name,
                         "attack_campaign_id": camp.attack_campaign_id,
                         "first_observed": camp.first_observed,
                         "last_observed": camp.last_observed,
                         "duration_days": camp.duration_days(),
                         "summary": camp.summary},
            "aliases": [a.to_dict() for a in camp.aliases],
            "attributed_actors": [{"actor_id": a.actor_id,
                                   "name": a.canonical_name,
                                   "type": a.actor_type.value} for a in actors],
            "campaign_timeline": timeline.to_dict(),
            "malware_relationships": [{"family_id": m.family_id,
                                       "name": m.family_name,
                                       "category": m.category} for m in families],
            "attack_coverage": coverage,
            "infrastructure": [{"infra_id": n.infra_id, "type": n.infra_type.value,
                                "value": n.value, "asn": n.asn,
                                "country": n.country} for n in infra],
            "iocs": [i.to_dict() for i in iocs],
            "victimology": camp.victimology.to_dict(),
            "public_reports": [{"report_id": rid} for rid in camp.report_ids],
            "relationships": [r.to_dict() for r in rels],
            "evidence": camp.evidence.to_list(),
            "confidence": camp.confidence.to_dict() if camp.confidence else None,
            "limitations": ([l.to_dict() for l in camp.confidence.limitations]
                            if camp.confidence else []),
        }

    def _exec_summary(self, camp: Campaign, actors, families, iocs) -> str:
        conf = camp.confidence.band if camp.confidence else "unknown"
        attr = (", ".join(a.canonical_name for a in actors)
                if actors else "no confidently attributed actor")
        return (f"Campaign '{camp.campaign_name}' spans {camp.duration_days()} day(s) "
                f"of documented activity. Attribution: {attr}. It is associated with "
                f"{len(families)} malware family(ies) and {len(iocs)} tracked IOC(s), "
                f"corroborated by {camp.evidence.distinct_count()} independent "
                f"source(s). Evidence confidence: {conf}.")


__all__ = ["CampaignReportBuilder"]
