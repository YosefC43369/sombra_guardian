"""
news_intelligence.graph.campaign_graph — campaign-centric graph.

Builds a campaign's neighbourhood from a ``CampaignNews`` aggregate: the actors,
malware, CVEs, countries, techniques and IOCs it involves, plus the source domains
that corroborate it, with provenance on every edge.
"""
from __future__ import annotations
from typing import Optional
from .base import NewsGraph, BaseGraphBuilder


class CampaignGraphBuilder(BaseGraphBuilder):
    def build(self, campaign) -> NewsGraph:
        g = NewsGraph(f"campaign:{campaign.name}")
        cnode = f"campaign:{campaign.key}"
        g.add_node(cnode, "campaign", label=campaign.name,
                   independent_reports=campaign.independent_report_count)
        pairs = [("actor", campaign.actor_names, "involves_actor"),
                 ("malware", campaign.malware_names, "uses_malware"),
                 ("cve", campaign.cve_ids, "exploits_cve"),
                 ("country", campaign.targeted_countries, "targets_country"),
                 ("technique", campaign.mitre_techniques, "uses_technique"),
                 ("ioc", campaign.iocs, "uses_infrastructure")]
        for nt, values, rel in pairs:
            for v in values:
                nid = f"{nt}:{v.lower()}"
                g.add_node(nid, nt, label=v)
                g.add_edge(cnode, nid, rel, article_ids=list(campaign.article_ids))
        return g


__all__ = ["CampaignGraphBuilder"]
