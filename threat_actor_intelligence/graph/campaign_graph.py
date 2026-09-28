"""
threat_actor_intelligence.graph.campaign_graph — campaign-centric graph.

The campaign, the actors attributed to it, the malware/infrastructure/IOCs it
used, its techniques and its targeted victims (country/industry) — wired for the
``/campaign_graph`` view and the campaign report.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..models.campaign import Campaign
from ..models.relation import Relationship
from .base import CTIGraph


class CampaignGraphBuilder:
    def build(self, campaign: Campaign, *,
              relationships: Optional[Sequence[Relationship]] = None,
              labels: Optional[Dict[str, str]] = None) -> CTIGraph:
        g = CTIGraph(name=f"campaign:{campaign.campaign_id}")
        labels = dict(labels or {})
        cid = campaign.campaign_id
        g.add_node(cid, "campaign", campaign.campaign_name,
                   confidence=(campaign.confidence.score if campaign.confidence else 0.0))
        for aid in campaign.actors:
            g.add_node(aid, "actor", labels.get(aid, aid))
            g.add_edge(cid, aid, "attributed_to", signal="reported attribution",
                       weight=0.7)
        for mid in campaign.malware_families:
            g.add_node(mid, "malware", labels.get(mid, mid))
            g.add_edge(cid, mid, "uses", signal="campaign used malware", weight=0.7)
        for iid in campaign.infrastructure:
            g.add_node(iid, "infrastructure", labels.get(iid, iid))
            g.add_edge(cid, iid, "uses", signal="campaign infrastructure", weight=0.6)
        for oid in campaign.iocs:
            g.add_node(oid, "ioc", labels.get(oid, oid))
            g.add_edge(cid, oid, "indicates", signal="campaign IOC", weight=0.5)
        for tid in campaign.techniques:
            g.add_node(tid, "technique", labels.get(tid, tid))
            g.add_edge(cid, tid, "uses", signal="documented technique", weight=0.4)
        for obs in campaign.victimology.observations:
            if obs.country:
                g.add_node(f"country:{obs.country}", "country", obs.country)
                g.add_edge(cid, f"country:{obs.country}", "targets",
                           signal="targeted country", weight=0.5)
            if obs.sector:
                g.add_node(f"industry:{obs.sector}", "industry", obs.sector)
                g.add_edge(cid, f"industry:{obs.sector}", "targets",
                           signal="targeted sector", weight=0.5)
        for rel in (relationships or []):
            g.add_relationship(rel, labels=labels)
        return g


__all__ = ["CampaignGraphBuilder"]
