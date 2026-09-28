"""Tests for the fail-closed authorization gate — the ethical spine."""

from __future__ import annotations

import pytest

from behavioral_intelligence.authorization import (BehaviorGate, AuthorizationContext,
                                                   Subject, require)


@pytest.fixture
def gate():
    return BehaviorGate(audit=False)


def test_person_scope_denied_by_default(gate):
    # no program, no explicit person scope -> DENY (fail closed)
    d = gate.authorize(AuthorizationContext(), Subject.ACCOUNT, "alice")
    assert not d.allowed
    assert d.reason == "DENY_PERSON_SCOPE_DISABLED"


def test_person_scope_requires_authorized_program(gate):
    # explicit person scope but no authorized program -> still DENY
    d = gate.authorize(AuthorizationContext(allow_person_scope=True), Subject.PERSON,
                       "alice")
    assert not d.allowed
    assert d.reason in ("DENY_PROGRAM_NOT_AUTHORIZED", "DENY_NO_PROGRAM")


def test_unknown_subject_denied(gate):
    d = gate.authorize(AuthorizationContext(dev_unsafe_allow_all=False),
                       Subject.UNKNOWN, "x")
    assert not d.allowed
    assert d.reason == "DENY_UNKNOWN_SUBJECT"


def test_dev_override_allows(gate):
    d = gate.authorize(AuthorizationContext(dev_unsafe_allow_all=True),
                       Subject.ACCOUNT, "alice")
    assert d.allowed
    assert d.reason == "ALLOWED_DEV_OVERRIDE"


def test_require_raises_on_denial(gate):
    with pytest.raises(PermissionError):
        require(AuthorizationContext(), Subject.ACCOUNT, "alice", gate=gate)


def test_require_passes_with_dev_override(gate):
    d = require(AuthorizationContext(dev_unsafe_allow_all=True), Subject.ACCOUNT,
                "alice", gate=gate)
    assert d.allowed


def test_infra_subject_without_scope_policy_denied(gate):
    # domain (infra) with no program -> DENY (no scope policy program supplied)
    d = gate.authorize(AuthorizationContext(), Subject.DOMAIN, "example.com")
    assert not d.allowed
