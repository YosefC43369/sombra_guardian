"""Tests for entity_fusion.entity — the universal model, provenance-preserving
mutators, merge, and serialization round-trips."""

import pytest

from entity_fusion.entity import (Entity, EntityType, RelationType, SourceRef,
                                   Evidence, Relationship, merge_entities)


class TestEntityBasics:
    def test_type_coercion(self):
        assert EntityType.coerce("EMAIL") == EntityType.EMAIL
        assert EntityType.coerce("nonsense") == EntityType.UNKNOWN
        assert EntityType.coerce(EntityType.IP) == EntityType.IP

    def test_prenormalization_fallback(self):
        e = Entity(type=EntityType.USERNAME, value="  John  ")
        assert e.normalized == "john"

    def test_add_alias_dedups_and_ignores_self(self):
        e = Entity(type=EntityType.USERNAME, value="john")
        e.add_alias("john")        # equals value → ignored
        e.add_alias("johnny")
        e.add_alias("johnny")      # dup
        assert e.aliases == {"johnny"}

    def test_add_source_dedups_on_key(self):
        e = Entity(type=EntityType.DOMAIN, value="x.com")
        e.add_source(SourceRef(provider="crtsh", url="u", observed_at=100))
        e.add_source(SourceRef(provider="crtsh", url="u", observed_at=50))
        assert len(e.sources) == 1
        assert e.first_seen <= 50

    def test_add_relationship_keeps_strongest_weight(self):
        e = Entity(type=EntityType.USERNAME, value="john")
        e.add_relationship(Relationship(target_id="t", type=RelationType.OWNS, weight=0.5))
        e.add_relationship(Relationship(target_id="t", type=RelationType.OWNS, weight=0.9))
        assert len(e.relationships) == 1
        assert e.relationships[0].weight == 0.9

    def test_providers_property(self):
        e = Entity(type=EntityType.USERNAME, value="john")
        e.add_source(SourceRef(provider="github"))
        e.add_source(SourceRef(provider="gravatar"))
        assert e.providers == {"github", "gravatar"}


class TestMerge:
    def test_merge_preserves_provenance(self):
        a = Entity(type=EntityType.USERNAME, value="johndoe")
        a.add_source(SourceRef(provider="github"))
        b = Entity(type=EntityType.USERNAME, value="john.doe")
        b.add_source(SourceRef(provider="twitter"))
        a.merge(b)
        assert "john.doe" in a.aliases
        assert a.providers == {"github", "twitter"}
        assert any(ev.kind == "entity_merge" for ev in a.evidence)

    def test_merge_upgrades_unknown_type(self):
        a = Entity(type=EntityType.UNKNOWN, value="x")
        b = Entity(type=EntityType.EMAIL, value="x@y.com")
        a.merge(b)
        assert a.type == EntityType.EMAIL

    def test_merge_entities_helper(self):
        ents = [Entity(type=EntityType.USERNAME, value=f"j{i}") for i in range(3)]
        merged = merge_entities(ents)
        assert merged is ents[0]
        assert "j1" in merged.aliases and "j2" in merged.aliases

    def test_merge_entities_empty(self):
        assert merge_entities([]) is None


class TestSerialization:
    def test_roundtrip(self):
        e = Entity(type=EntityType.EMAIL, value="a@b.com")
        e.add_alias("alt@b.com")
        e.add_source(SourceRef(provider="p", url="u"))
        e.add_evidence(Evidence(kind="k", value="v", weight=0.5))
        e.add_relationship(Relationship(target_id="t", type=RelationType.OWNS))
        e.metadata["display_name"] = "Alice"
        restored = Entity.from_dict(e.to_dict())
        assert restored.id == e.id
        assert restored.type == EntityType.EMAIL
        assert "alt@b.com" in restored.aliases
        assert restored.sources[0].provider == "p"
        assert restored.evidence[0].kind == "k"
        assert restored.relationships[0].type == RelationType.OWNS
        assert restored.metadata["display_name"] == "Alice"

    def test_from_record(self):
        rec = {"type": "domain", "value": "Example.com", "source": "crtsh",
               "extra_field": 123}
        e = Entity.from_record(rec)
        assert e.type == EntityType.DOMAIN
        assert e.has_provider("crtsh")
        assert e.metadata["extra_field"] == 123

    def test_summary_string(self):
        e = Entity(type=EntityType.USERNAME, value="john")
        e.add_alias("johnny")
        assert "username:john" in e.summary()
