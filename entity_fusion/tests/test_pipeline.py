"""Tests for entity_fusion.pipeline (recursive discovery) and the FusionEngine
orchestrator. Async tests run via asyncio.run so no pytest-asyncio is needed."""

import asyncio
import pytest

from entity_fusion.entity import Entity, EntityType, Relationship, RelationType
from entity_fusion.pipeline import RecursivePipeline, PipelineConfig
from entity_fusion.authorization import AuthorizationContext, FusionGate
from entity_fusion.orchestrator import FusionEngine


def run(coro):
    return asyncio.run(coro)


DEV = AuthorizationContext(dev_unsafe_allow_all=True)


class TestRecursivePipeline:
    def test_linear_expansion(self):
        # username → website → domain, one hop each
        async def expand_username(entity, client):
            return [Entity(type=EntityType.WEBSITE, value="https://example.com")]

        async def expand_website(entity, client):
            return [Entity(type=EntityType.DOMAIN, value="example.com")]

        pipe = RecursivePipeline(gate=FusionGate(),
                                 config=PipelineConfig(max_depth=3))
        pipe.register("username", expand_username)
        pipe.register("website", expand_website)
        seed = Entity(type=EntityType.USERNAME, value="johndoe")
        result = run(pipe.run([seed], DEV))
        types = {e.type for e in result.discovered}
        assert EntityType.USERNAME in types
        assert EntityType.WEBSITE in types
        assert EntityType.DOMAIN in types

    def test_depth_limit_respected(self):
        async def expand(entity, client):
            # each username spawns another username → would recurse forever
            return [Entity(type=EntityType.USERNAME, value=entity.value + "x")]

        pipe = RecursivePipeline(config=PipelineConfig(max_depth=2))
        pipe.register("username", expand)
        seed = Entity(type=EntityType.USERNAME, value="a")
        result = run(pipe.run([seed], DEV))
        assert result.depth_reached <= 2

    def test_cycle_prevention(self):
        async def expand(entity, client):
            # A links B, B links A → must terminate
            other = "b" if entity.value == "a" else "a"
            return [Entity(type=EntityType.USERNAME, value=other)]

        pipe = RecursivePipeline(config=PipelineConfig(max_depth=10))
        pipe.register("username", expand)
        seed = Entity(type=EntityType.USERNAME, value="a")
        result = run(pipe.run([seed], DEV))
        # only 'a' and 'b' ever discovered despite depth budget of 10
        values = {e.normalized for e in result.discovered}
        assert values == {"a", "b"}

    def test_entity_budget(self):
        async def expand(entity, client):
            return [Entity(type=EntityType.USERNAME, value=entity.value + str(i))
                    for i in range(10)]

        pipe = RecursivePipeline(config=PipelineConfig(max_depth=5, max_entities=15))
        pipe.register("username", expand)
        result = run(pipe.run([Entity(type=EntityType.USERNAME, value="a")], DEV))
        assert len(result.discovered) <= 15

    def test_scope_gate_denies_without_program(self):
        async def expand(entity, client):
            return []
        pipe = RecursivePipeline()
        pipe.register("username", expand)
        ctx = AuthorizationContext()  # no program, person scope off → deny
        seed = Entity(type=EntityType.USERNAME, value="a")
        result = run(pipe.run([seed], ctx))
        assert result.discovered == []
        assert result.denied and not result.denied[0].allowed

    def test_expander_failure_isolated(self):
        async def boom(entity, client):
            raise RuntimeError("provider down")
        pipe = RecursivePipeline()
        pipe.register("username", boom)
        seed = Entity(type=EntityType.USERNAME, value="a")
        result = run(pipe.run([seed], DEV))
        # seed still discovered; failure did not crash the run
        assert len(result.discovered) == 1


class TestFusionEngineIntegration:
    def test_full_fuse_merges_duplicates(self):
        records = [
            {"type": "username", "value": "John.Doe", "source": "s1",
             "display_name": "John Doe"},
            {"type": "username", "value": "johndoe", "source": "s2",
             "display_name": "John Doe"},
            {"type": "username", "value": "alice", "source": "s3",
             "display_name": "Alice"},
        ]
        res = FusionEngine().fuse(records, ctx=DEV)
        multi = [i for i in res.identities if len(i.member_ids) > 1]
        assert len(multi) == 1
        assert multi[0].score >= 90

    def test_denied_without_authorization(self):
        records = [{"type": "username", "value": "johndoe", "source": "s"}]
        res = FusionEngine().fuse(records, ctx=AuthorizationContext())
        assert res.identities == []
        assert len(res.denied) == 1

    def test_bio_email_extracted_as_entity(self):
        records = [{"type": "username", "value": "jdoe", "source": "s",
                    "bio": "contact me at jdoe@example.com"}]
        res = FusionEngine().fuse(records, ctx=DEV)
        all_types = {t for i in res.identities for t in i.values_by_type}
        assert "email" in all_types

    def test_crypto_address_extracted(self):
        btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        records = [{"type": "username", "value": "jdoe", "source": "s",
                    "bio": f"donations: {btc}"}]
        res = FusionEngine().fuse(records, ctx=DEV)
        wallets = [v for i in res.identities for v in i.values_by_type.get("wallet", [])]
        assert btc in wallets

    def test_report_dict_serializable(self):
        import json
        records = [{"type": "domain", "value": "example.com", "source": "s"}]
        res = FusionEngine().fuse(records, ctx=DEV)
        json.dumps(res.to_dict())  # must not raise

    def test_discover_and_fuse(self):
        async def expand_username(entity, client):
            return [Entity(type=EntityType.USERNAME, value="johndoe",
                           metadata={"display_name": "John Doe"})]
        pipe = RecursivePipeline()
        pipe.register("username", expand_username)
        seed = Entity(type=EntityType.USERNAME, value="john.doe",
                      metadata={"display_name": "John Doe"})
        pres, fres = run(pipe.discover_and_fuse([seed], DEV))
        assert len(pres.discovered) >= 1
        assert fres.identities
