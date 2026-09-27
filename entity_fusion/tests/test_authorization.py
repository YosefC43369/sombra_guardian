"""Tests for entity_fusion.authorization — the fail-closed scope gate.

These verify the *safety-critical* behaviour: nothing correlates without
authorization, person-scope is off by default, and every ambiguous case denies.
They do not require the scope_policy DB to be populated — the gate must deny
(not error) when authorization is absent."""

import pytest

from entity_fusion.entity import Entity, EntityType
from entity_fusion.authorization import (AuthorizationContext, FusionGate,
                                         GateReason, INFRA_TYPES, PERSON_TYPES)


GATE = FusionGate(audit=False)


def _e(etype, value):
    e = Entity(type=etype, value=value)
    e.normalized = value.lower()
    return e


class TestFailClosed:
    def test_no_program_denies_infra(self):
        ctx = AuthorizationContext()   # nothing configured
        d = GATE.authorize(ctx, _e(EntityType.DOMAIN, "example.com"))
        assert not d.allowed

    def test_no_program_denies_person(self):
        ctx = AuthorizationContext()
        d = GATE.authorize(ctx, _e(EntityType.USERNAME, "johndoe"))
        assert not d.allowed
        assert d.reason == GateReason.DENY_PERSON_SCOPE_DISABLED.value

    def test_person_scope_off_by_default_even_with_program(self):
        # allow_person_scope defaults False → person entity denied regardless
        ctx = AuthorizationContext(program_id=999999)
        d = GATE.authorize(ctx, _e(EntityType.EMAIL, "a@b.com"))
        assert not d.allowed
        assert d.reason == GateReason.DENY_PERSON_SCOPE_DISABLED.value

    def test_unknown_type_denies(self):
        ctx = AuthorizationContext(dev_unsafe_allow_all=False, program_id=1)
        e = Entity(type=EntityType.UNKNOWN, value="???")
        d = GATE.authorize(ctx, e)
        assert not d.allowed
        assert d.reason == GateReason.DENY_UNKNOWN_TYPE.value


class TestDevOverride:
    def test_dev_override_allows_everything(self):
        ctx = AuthorizationContext(dev_unsafe_allow_all=True)
        for etype in (EntityType.DOMAIN, EntityType.USERNAME, EntityType.WALLET):
            d = GATE.authorize(ctx, _e(etype, "x"))
            assert d.allowed
            assert d.reason == GateReason.ALLOWED_DEV_OVERRIDE.value


class TestPartition:
    def test_partition_splits_allowed_and_denied(self):
        ctx = AuthorizationContext(dev_unsafe_allow_all=True)
        ents = [_e(EntityType.DOMAIN, "a.com"), _e(EntityType.USERNAME, "u")]
        allowed, denied = GATE.partition(ctx, ents)
        assert len(allowed) == 2 and denied == []

    def test_partition_denies_when_unauthorized(self):
        ctx = AuthorizationContext()
        ents = [_e(EntityType.DOMAIN, "a.com"), _e(EntityType.USERNAME, "u")]
        allowed, denied = GATE.partition(ctx, ents)
        assert allowed == [] and len(denied) == 2


class TestTypeClassification:
    def test_type_sets_are_disjoint(self):
        assert not (INFRA_TYPES & PERSON_TYPES)

    def test_infra_types_include_domain(self):
        assert EntityType.DOMAIN in INFRA_TYPES

    def test_person_types_include_username(self):
        assert EntityType.USERNAME in PERSON_TYPES
