# Graph Engine

`entity_fusion/graph.py` builds the relationship graph of correlated entities
and exports it in several formats.

## Backend

`networkx` is **optional**. With it installed the graph is a
`networkx.MultiDiGraph` and networkx's own writers are used; without it a small
pure-stdlib directed multigraph (`_StdlibGraph`) provides the identical public
surface and hand-rolled exporters. Callers never branch on the backend;
`IdentityGraph.stats()["backend"]` reports which is active.

## Nodes and edges

- **Nodes** are entities, carrying `label`, `type`, `color` (by type),
  `confidence`, `aliases`, `providers`.
- **Edges** are the typed relationships from `entity.Relationship` plus the
  `same_as` edges fusion emits to wire a cluster together.

Edge/relationship types: `owns`, `mentions`, `shares_email`, `shares_avatar`,
`shares_domain`, `shares_wallet`, `shares_org`, `shares_certificate`,
`shares_phone`, `historical_reference`, `appeared_in`, `resolves_to`, `same_as`.

## Construction

```python
from entity_fusion.graph import IdentityGraph
g = IdentityGraph().build_from_entities(entities)   # nodes + declared edges
g.link_cluster(identity.member_ids)                 # star of same_as edges
print(g.stats())   # {"backend": "...", "nodes": N, "edges": M}
```

`build_from_entities` auto-adds bare nodes for relationship targets outside the
set, so no edge dangles. `link_cluster` uses a star topology (hub → others) so
edge count stays linear in cluster size.

## Exports

| Method | Format | Availability |
| --- | --- | --- |
| `to_json()` / `to_node_link()` | node-link JSON (sorted, deterministic) | always |
| `to_dot()` | GraphViz DOT | always |
| `to_graphml()` | GraphML | always (richer via networkx) |
| `to_gexf()` | GEXF (Gephi) | always (richer via networkx) |
| `render("svg"/"png")` | rendered bytes | only if the GraphViz `dot` binary is on PATH; else `None` |

The `reports/graphviz.py` renderer wraps `to_dot()` / `render()` at the report
layer (`render`, `render_svg`, `render_png`).
