"""
purple_range/tests/conftest.py — offline fixtures.

One temp sqlite DB is shared by the legacy engine modules (security / scope_policy /
redteam / purpleteam — whose DB path is a module global bound from security.DB_PATH) and
by purple_range. We point them all at the temp DB, init their tables, apply migrations,
and hand back a service plus a real engagement. No Telegram, no network.
"""

from __future__ import annotations

import dataclasses

import pytest

import migrations
from purple_range.config import PurpleRangeConfig
from purple_range.service import PurpleRangeService

CHAT = -1002002002


@pytest.fixture()
def legacy_db(tmp_path):
    db = str(tmp_path / "range_test.db")
    import security, scope_policy, redteam, purpleteam
    for mod in (security, scope_policy, redteam, purpleteam):
        mod.DB_PATH = db
    security.security_db_init()
    scope_policy.scope_policy_db_init()
    redteam.redteam_db_init()
    purpleteam.purpleteam_db_init()
    migrations.apply_startup_migrations(db)
    return db


@pytest.fixture()
def config():
    return dataclasses.replace(PurpleRangeConfig.load(), enabled=True,
                               soc_bridge_enabled=False)


@pytest.fixture()
def service(legacy_db, config):
    return PurpleRangeService(legacy_db, config=config)


@pytest.fixture()
def engagement(legacy_db):
    import redteam
    res = redteam.create_engagement(CHAT, "Lab Engagement", 42, goal="validate detections")
    assert res.ok, res.reason
    return res.id
