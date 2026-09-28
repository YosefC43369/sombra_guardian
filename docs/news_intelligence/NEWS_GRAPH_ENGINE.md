# News Graph Engine

The graph layer (`news_intelligence/graph/`) builds provenance-carrying
relationship graphs from the corpus and exports them to JSON, GraphML, GEXF and
DOT with **stdlib only** (no networkx required), matching the formats the platform's
Graph Engine and Maltego/Gephi tooling consume.

## Node & edge model

- **Nodes**: article, source, actor, malware, CVE, organization, agency, country,
  city, IOC, technique, campaign, repository, alias, topic.
- **Edges** always carry provenance: the `article_ids` and `signals` that justify
  the edge, plus an accumulated `weight`. An edge you cannot trace to an article is
  never created.

`NewsGraph.add_node` / `add_edge` are idempotent and accumulate weight and
provenance on repeat, so the graph is safe to build incrementally.

## Builders

| Builder | Graph |
|---|---|
| `NewsGraphBuilder` | full article ↔ source ↔ entity graph (`mentions`, `published_by`) |
| `ActorGraphBuilder` | actor ego-graph: malware, CVEs, countries, techniques + `reported_as` alias nodes |
| `CampaignGraphBuilder` | campaign → actors/malware/CVEs/countries/techniques/IOCs |
| `TopicGraphBuilder` | topic co-occurrence graph (entities discussed together) |

## Exports

```python
from news_intelligence.graph.news_graph import NewsGraphBuilder
g = NewsGraphBuilder(store).build(articles)
g.to_json()      # node/edge JSON with stats
g.to_dot()       # Graphviz
g.to_graphml()   # yEd / Gephi
g.to_gexf()      # Gephi
g.export("graphml")
```

Via the engine facade:

```python
engine.graph(kind="actor", subject="APT29", days=14, fmt="graphml")
```

## Provenance guarantee

Because every edge stores the article ids behind it, any relationship in the graph
can be expanded back to the exact public articles that support it — the same
evidence discipline the rest of the engine enforces, carried into the graph.
