"""Tests for entity_fusion.similarity — string metrics and the explainable
multi-factor entity scorer."""

import pytest

from entity_fusion import similarity as sim
from entity_fusion.entity import Entity, EntityType


class TestStringMetrics:
    def test_levenshtein_basics(self):
        assert sim.levenshtein("kitten", "sitting") == 3
        assert sim.levenshtein("abc", "abc") == 0
        assert sim.levenshtein("", "abc") == 3

    def test_levenshtein_ratio_bounds(self):
        assert sim.levenshtein_ratio("abc", "abc") == 1.0
        assert 0.0 <= sim.levenshtein_ratio("abc", "xyz") < 0.5

    def test_jaro_winkler_prefix_boost(self):
        # shared prefix should score higher than a non-prefixed near-match
        assert sim.jaro_winkler("martha", "marhta") > 0.9
        assert sim.jaro_winkler("abc", "abc") == 1.0

    def test_token_jaccard_order_independent(self):
        assert sim.token_jaccard("john q doe", "doe john q") == 1.0
        assert sim.token_jaccard("a b", "a c") == pytest.approx(1 / 3)

    def test_ngram_cosine(self):
        assert sim.ngram_cosine("hello world", "hello world") == pytest.approx(1.0)
        assert sim.ngram_cosine("abcdef", "uvwxyz") < 0.2

    def test_jaccard_collections(self):
        assert sim.jaccard(["a", "b"], ["b", "c"]) == pytest.approx(1 / 3)
        assert sim.jaccard([], ["a"]) == 0.0


class TestEntityScoring:
    def _u(self, value, **meta):
        e = Entity(type=EntityType.USERNAME, value=value)
        e.normalized = value.lower().replace(".", "").replace("_", "")
        e.metadata.update(meta)
        return e

    def test_identical_username_hard_match(self):
        a = self._u("johndoe")
        b = self._u("johndoe")
        res = sim.SimilarityEngine().score_entities(a, b)
        assert res.hard_match
        assert res.percent >= 97

    def test_similar_usernames_high(self):
        a = self._u("johndoe", display_name="John Doe")
        b = self._u("johndoe", display_name="John Doe")
        res = sim.SimilarityEngine().score_entities(a, b)
        assert res.score >= 0.9

    def test_unrelated_low(self):
        a = self._u("alice", display_name="Alice A")
        b = self._u("bob", display_name="Bob B")
        res = sim.SimilarityEngine().score_entities(a, b)
        assert res.score < 0.5

    def test_hard_identifier_avatar_hash(self):
        a = Entity(type=EntityType.USERNAME, value="a")
        b = Entity(type=EntityType.USERNAME, value="b")
        a.metadata["avatar_sha256"] = "deadbeef" * 8
        b.metadata["avatar_sha256"] = "deadbeef" * 8
        res = sim.SimilarityEngine().score_entities(a, b)
        assert res.hard_match
        assert res.percent >= 97

    def test_explanation_lists_signals(self):
        a = self._u("johndoe", display_name="John Doe", organization="Acme")
        b = self._u("john.doe", display_name="John Doe", organization="Acme Inc")
        res = sim.SimilarityEngine().score_entities(a, b)
        assert "score=" in res.explanation()
        assert res.to_dict()["signals"]

    def test_soft_signals_never_reach_certainty(self):
        # only soft signals (name/org), no hard identifier
        a = self._u("jdoe", display_name="John Doe")
        b = self._u("jdoe2", display_name="John Doe")
        res = sim.SimilarityEngine().score_entities(a, b)
        assert res.score <= 0.95

    def test_weights_injectable(self):
        eng = sim.SimilarityEngine(weights={"display_name": 100.0})
        assert eng.weights["display_name"] == 100.0
