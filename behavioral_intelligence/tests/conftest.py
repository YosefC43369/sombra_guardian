"""
Shared fixtures and synthetic-data builders for the behavioural test suite.

The builders produce deterministic ``Observation`` sets so every statistical
assertion is reproducible: a fixed seed, fixed epoch base, and explicit patterns
(a nightly poster, a burst, a language switch) the tests can assert against.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List

import pytest

from behavioral_intelligence.models import (Observation, ObservationBatch,
                                            ContentType)
from behavioral_intelligence.authorization import AuthorizationContext

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def at(day: int, hour: int = 20, minute: int = 0) -> float:
    return (BASE + timedelta(days=day, hours=hour, minutes=minute)).timestamp()


def make_observations(*, days: int = 60, per_day: int = 3, hour: int = 20,
                      platform: str = "mastodon", account: str = "alice",
                      language: str = "en", text: str = "osint cybersecurity #osint",
                      entity_id: str = "actor7", source: str = "rss") -> List[Observation]:
    obs: List[Observation] = []
    for d in range(days):
        for i in range(per_day):
            obs.append(Observation(
                platform=platform, account_id=account,
                timestamp=at(d, hour, i * 7), text=text, language=language,
                hashtags=["osint"], mentions=["bob"],
                urls=["https://github.com/alice/tool"],
                content_type=ContentType.REPLY if i == 0 else ContentType.POST,
                entity_id=entity_id, source=source))
    return obs


@pytest.fixture
def nightly_batch() -> ObservationBatch:
    return ObservationBatch(make_observations(), entity_id="actor7", label="@alice")


@pytest.fixture
def dev_ctx() -> AuthorizationContext:
    """A context that bypasses scope for pure-analysis tests. Authorization is
    tested separately in test_authorization.py."""
    return AuthorizationContext(dev_unsafe_allow_all=True)
