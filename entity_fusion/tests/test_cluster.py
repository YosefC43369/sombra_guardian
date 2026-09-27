"""Tests for entity_fusion.clustering — union-find, blocking, and end-to-end
cluster formation."""

import pytest

from entity_fusion.clustering import UnionFind, Clusterer
from entity_fusion.entity import Entity, EntityType


class TestUnionFind:
    def test_from_generator_not_consumed_twice(self):
        # regression: __init__ must materialise a generator for both dicts
        uf = UnionFind(x for x in ("a", "b", "c"))
        assert uf.find("a") == "a"
        uf.union("a", "b")
        assert uf.find("a") == uf.find("b")

    def test_transitive_union(self):
        uf = UnionFind(["a", "b", "c", "d"])
        uf.union("a", "b")
        uf.union("b", "c")
        assert uf.find("a") == uf.find("c")
        assert uf.find("a") != uf.find("d")

    def test_groups(self):
        uf = UnionFind(["a", "b", "c"])
        uf.union("a", "b")
        groups = uf.groups()
        sizes = sorted(len(v) for v in groups.values())
        assert sizes == [1, 2]

    def test_add_new_item(self):
        uf = UnionFind()
        uf.add("z")
        assert uf.find("z") == "z"


def _u(value, **meta):
    e = Entity(type=EntityType.USERNAME, value=value)
    e.normalized = value.lower().replace(".", "").replace("_", "")
    e.metadata.update(meta)
    return e


class TestClusterer:
    def test_identical_records_cluster(self):
        ents = [_u("johndoe", display_name="John Doe"),
                _u("john.doe", display_name="John Doe"),
                _u("alice", display_name="Alice")]
        report = Clusterer(threshold=0.82).cluster(ents)
        multi = [c for c in report.clusters if c.size > 1]
        assert len(multi) == 1
        assert multi[0].size == 2

    def test_singletons_reported(self):
        ents = [_u("alice"), _u("bob"), _u("carol")]
        report = Clusterer(threshold=0.82).cluster(ents)
        assert report.singletons == 3
        assert report.stats()["multi_member"] == 0

    def test_blocking_limits_comparisons(self):
        # 6 handles with distinct skeletons AND cores share no block key, so
        # blocking avoids the full 15 pairwise comparisons entirely.
        ents = [_u(v) for v in ("alice", "bob", "carol", "dave", "erin", "frank")]
        report = Clusterer(threshold=0.82).cluster(ents)
        assert report.comparisons < 15

    def test_transitive_cluster(self):
        # a~b and b~c should place a,b,c in one cluster via union-find
        ents = [_u("johndoe", display_name="John Doe"),
                _u("john.doe", display_name="John Doe"),
                _u("john_doe", display_name="John Doe")]
        report = Clusterer(threshold=0.8).cluster(ents)
        biggest = max(report.clusters, key=lambda c: c.size)
        assert biggest.size == 3

    def test_links_recorded(self):
        ents = [_u("johndoe", display_name="John Doe"),
                _u("johndoe", display_name="John Doe")]
        report = Clusterer(threshold=0.82).cluster(ents)
        biggest = max(report.clusters, key=lambda c: c.size)
        assert biggest.links  # the similarity result that justified the merge

    def test_empty_input(self):
        report = Clusterer().cluster([])
        assert report.clusters == []
