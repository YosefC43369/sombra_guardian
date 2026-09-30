"""
group_soc/tests/conftest.py — shared fixtures.

Every fixture is offline: a fresh temp sqlite DB migrated with the real migration
runner, a config with the master switch forced on, and a runtime with the group
activated. No Telegram, no network. Async pipeline tests use ``run_async`` (asyncio.run)
so no pytest-asyncio plugin is required.
"""

from __future__ import annotations

import asyncio
import dataclasses

import pytest

import migrations
from group_soc.config import SocConfig
from group_soc.storage import StorageBundle
from group_soc.runtime import SocRuntime

CHAT = -1001234567890


@pytest.fixture()
def db_path(tmp_path):
    path = str(tmp_path / "soc_test.db")
    migrations.apply_startup_migrations(path)
    return path


@pytest.fixture()
def config():
    return dataclasses.replace(
        SocConfig.load(),
        enabled=True, ingest_enabled=True, correlation_enabled=True,
        detection_enabled=True, alerting_enabled=True, emit_soc_events=True,
        join_burst_threshold=3, join_burst_window_s=3600,
        similar_message_threshold=3, similar_message_window_s=3600,
        sequence_window_s=3600, correlation_window_s=3600,
        alert_cooldown_s=0, escalation_repeat_threshold=3,
    )


@pytest.fixture()
def storage(db_path):
    return StorageBundle(db_path)


@pytest.fixture()
def runtime(db_path, config):
    rt = SocRuntime(db_path, config=config)
    rt.storage.set_policy(CHAT, enabled=True, mode="alert")
    return rt


@pytest.fixture()
def emitted():
    return []


def run_async(coro):
    return asyncio.run(coro)
