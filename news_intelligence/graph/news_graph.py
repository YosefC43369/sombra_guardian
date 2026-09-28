"""
news_intelligence.graph.news_graph — the full article↔entity↔source graph.

Builds the complete provenance graph from a set of articles: article, source,
threat-actor, campaign, malware, CVE, organization, country, IOC and technique nodes,
with edges from each article to its source and to every entity it mentions. Edges
carry the article id as provenance so any relationship can be traced to its source.
"""

from __future__ import annotations

from typing import List, Optional

from ..models.article import Article
from ..models.entity import EntityType
from .base import NewsGraph, BaseGraphBuilder

_ENTITY_NODE_TYPE = {
    EntityType.THREAT_ACTOR: "actor",
    EntityType.CAMPAIGN: "campaign",
    EntityType.MALWARE_FAMILY: "malware",
    EntityType.CVE: "cve",
    EntityType.ORGANIZATION: "organization",
    EntityType.COMPANY: "organization",
    EntityType.GOVERNMENT_AGENCY: "agency",
    EntityType.COUNTRY: "country",
    EntityType.DOMAIN: "ioc",
    EntityType.IP: "ioc",
    EntityType.URL: "ioc",
    EntityType.EMAIL: "ioc",
    EntityType.HASH: "ioc",
    EntityType.ASN: "ioc",
    EntityType.ATTACK_TECHNIQUE: "technique",
    EntityType.REPOSITORY: "repository",
}


class NewsGraphBuilder(BaseGraphBuilder):
    def build(self, articles: List[Article], *, include_iocs: bool = True,
              name: str = "news_graph") -> NewsGraph:
        g = NewsGraph(name)
        for a in articles:
            if a.duplicate_of:
                continue
            aid = a.article_id
            g.add_node(aid, "article", label=a.title[:80],
                       url=a.canonical_url or a.url,
                       published=a.publication_date)
            if a.source_domain:
                g.add_node(a.source_domain, "source", label=a.source_name
                           or a.source_domain)
                g.add_edge(aid, a.source_domain, "published_by",
                           article_ids=[aid])
            for m in a.entity_mentions:
                nt = _ENTITY_NODE_TYPE.get(m.entity_type)
                if nt is None:
                    continue
                if nt == "ioc" and not include_iocs:
                    continue
                node_id = f"{nt}:{m.value.lower()}"
                g.add_node(node_id, nt, label=m.value)
                g.add_edge(aid, node_id, "mentions", weight=m.weight,
                           article_ids=[aid], signals=[m.extractor])
        return g

    def build_and_export(self, articles: List[Article], *, fmt: str = "json",
                         **kw) -> str:
        return self.build(articles, **kw).export(fmt)


__all__ = ["NewsGraphBuilder"]
