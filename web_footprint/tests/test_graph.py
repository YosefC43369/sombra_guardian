import unittest

from web_footprint import graph as g


class TestGraph(unittest.TestCase):
    def test_add_and_dedup(self):
        G = g.AttackSurfaceGraph("example.com")
        G.add_node("example.com", "domain")
        G.add_node("api.example.com", "subdomain")
        e1 = G.add_edge("example.com", "api.example.com", g.EDGE_HAS_SUBDOMAIN)
        e2 = G.add_edge("example.com", "api.example.com", g.EDGE_HAS_SUBDOMAIN)
        self.assertIs(e1, e2)  # same edge key deduplicated
        self.assertEqual(G.node_count, 2)
        self.assertEqual(G.edge_count, 1)

    def test_self_loop_and_empty_ignored(self):
        G = g.AttackSurfaceGraph()
        self.assertIsNone(G.add_edge("a", "a", "x"))
        self.assertIsNone(G.add_edge("", "b", "x"))

    def test_neighbors(self):
        G = g.AttackSurfaceGraph()
        G.add_edge("a", "b", "e")
        G.add_edge("a", "c", "e")
        self.assertEqual(G.neighbors("a"), ["b", "c"])

    def test_pivot_depth_bounded(self):
        G = g.AttackSurfaceGraph()
        # chain a -> b -> c -> d
        G.add_edge("a", "b", "e")
        G.add_edge("b", "c", "e")
        G.add_edge("c", "d", "e")
        depth1 = {r["node"] for r in G.pivot("a", max_depth=1)}
        self.assertEqual(depth1, {"b"})
        depth2 = {r["node"] for r in G.pivot("a", max_depth=2)}
        self.assertEqual(depth2, {"b", "c"})
        # pivot never runs past the internal clamp
        alln = {r["node"] for r in G.pivot("a", max_depth=99)}
        self.assertEqual(alln, {"b", "c", "d"})

    def test_pivot_edge_kind_filter(self):
        G = g.AttackSurfaceGraph()
        G.add_edge("a", "b", "keep")
        G.add_edge("a", "c", "skip")
        res = {r["node"] for r in G.pivot("a", max_depth=1, edge_kinds=["keep"])}
        self.assertEqual(res, {"b"})

    def test_exports(self):
        G = g.AttackSurfaceGraph("example.com")
        G.add_edge("example.com", "api.example.com", g.EDGE_HAS_SUBDOMAIN)
        d = G.to_dict()
        self.assertEqual(d["node_count"], 2)
        self.assertEqual(d["edge_count"], 1)
        dot = G.to_dot()
        self.assertIn("digraph attack_surface", dot)
        self.assertIn("api.example.com", dot)


if __name__ == "__main__":
    unittest.main()
