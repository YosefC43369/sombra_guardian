"""Tests for entity_fusion.confidence — explainable scoring, bands, corroboration
and conflict handling."""

import pytest

from entity_fusion.entity import Entity, EntityType, SourceRef
from entity_fusion.clustering import Clusterer
from entity_fusion.confidence import ConfidenceEngine, BANDS


def _u(value, provider, **meta):
    e = Entity(type=EntityType.USERNAME, value=value)
    e.normalized = value.lower().replace(".", "").replace("_", "")
    e.add_source(SourceRef(provider=provider))
    e.metadata.update(meta)
    return e


def _cluster(entities, threshold=0.8):
    report = Clusterer(threshold=threshold).cluster(entities)
    return max(report.clusters, key=lambda c: c.size)


class TestConfidence:
    def test_singleton_is_insufficient(self):
        cl = _cluster([_u("alice", "s1")])
        rep = ConfidenceEngine().assess(cl)
        assert rep.band == "insufficient"
        assert rep.score == 0.0

    def test_strong_match_high_band(self):
        cl = _cluster([_u("johndoe", "sherlock", display_name="John Doe"),
                       _u("john.doe", "github", display_name="John Doe")])
        rep = ConfidenceEngine().assess(cl)
        assert rep.score >= 75
        assert rep.band in ("strong", "conclusive")

    def test_corroboration_from_multiple_providers(self):
        cl = _cluster([_u("johndoe", "a", display_name="John Doe"),
                       _u("johndoe", "b", display_name="John Doe")])
        rep = ConfidenceEngine().assess(cl)
        labels = [p.label for p in rep.positives]
        assert any("corroboration" in l for l in labels)

    def test_conflict_penalizes_and_lists(self):
        a = _u("johndoe", "a", display_name="John Doe", country="US")
        b = _u("johndoe", "b", display_name="John Doe", country="RU")
        cl = _cluster([a, b])
        rep = ConfidenceEngine().assess(cl)
        assert rep.conflicts
        assert any("country" in c for c in rep.conflicts)
        assert any(n.kind == "negative" for n in rep.negatives)

    def test_explanation_is_human_readable(self):
        cl = _cluster([_u("johndoe", "a", display_name="John Doe"),
                       _u("john.doe", "b", display_name="John Doe")])
        rep = ConfidenceEngine().assess(cl)
        assert "confidence" in rep.human_explanation.lower()
        assert "analyst review" in rep.human_explanation.lower()

    def test_machine_dict_shape(self):
        cl = _cluster([_u("johndoe", "a"), _u("johndoe", "b")])
        m = ConfidenceEngine().assess(cl).machine
        assert set(m) >= {"cluster_id", "score", "band", "positives",
                          "negatives", "conflicts"}

    def test_bands_cover_zero_to_hundred(self):
        # every score in [0,100] resolves to some band
        eng = ConfidenceEngine()
        for score in (0, 34, 35, 54, 55, 74, 75, 89, 90, 100):
            band = eng._band(float(score))
            assert band in {name for _, name in BANDS}
