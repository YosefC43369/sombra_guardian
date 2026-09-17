"""
plugins/manager.py — discover, load, enable/disable and health-check plugins.

Failure isolation is the whole point: if plugin A raises in ``setup()`` or a
healthcheck, A is marked FAILED and B and C keep running — and so does the
bot. Nothing a plugin does at load time can crash startup.

The manager never touches the live Telegram Application itself. It collects
the CommandSpecs plugins register and exposes them via
``iter_command_specs()``; sg_platform is what actually binds them onto the
app (with the permission gate). This keeps the plugin layer free of Telegram
imports and testable on its own.
"""

import time
import logging
import sqlite3
from typing import Iterable, List, Optional

from .base import BasePlugin, PluginContext, PluginState, HealthStatus, CommandSpec
from .registry import PluginRegistry, PluginRecord
from . import loader

logger = logging.getLogger("modbot.plugins.manager")


class PluginManager:
    def __init__(self, db_path: Optional[str] = None, engine=None,
                 action_registry=None, event_bus=None, config: Optional[dict] = None):
        self.db_path = db_path
        self.engine = engine
        self.action_registry = action_registry
        self.event_bus = event_bus
        self.config = config or {}
        self.registry = PluginRegistry()

    # ---- discovery / loading ----

    def discover(self, plugins: Optional[Iterable[BasePlugin]] = None,
                 external_dir: str = None) -> List[PluginRecord]:
        """Register plugin instances (given, or auto-discovered). Duplicate
        names are skipped with a warning rather than raising."""
        if plugins is None:
            plugins = loader.discover_all(external_dir)
        records = []
        for plugin in plugins:
            try:
                records.append(self.registry.add(plugin))
            except ValueError as exc:
                logger.warning("PLUGIN | %s", exc)
        return records

    def load_all(self) -> None:
        """Call setup() on every discovered plugin, isolating failures and
        honouring persisted enable/disable state."""
        for record in self.registry.all():
            if record.state not in (PluginState.DISCOVERED,):
                continue
            self._load_one(record)

    def _load_one(self, record: PluginRecord) -> None:
        plugin = record.plugin
        # Respect a persisted "disabled" decision: still LOADED (so metadata
        # shows), but not ENABLED, and its commands are not activated.
        if self._persisted_enabled(plugin.name) is False:
            record.state = PluginState.DISABLED
            record.loaded_at = int(time.time())
            logger.info("PLUGIN | %s loaded but DISABLED (persisted)", plugin.name)
            return

        ctx = PluginContext(
            plugin_name=plugin.name, db_path=self.db_path, engine=self.engine,
            action_registry=self.action_registry, event_bus=self.event_bus,
            logger=logging.getLogger(f"modbot.plugins.{plugin.name}"),
            config=self.config.get(plugin.name, {}),
        )
        try:
            plugin.setup(ctx)
        except Exception as exc:
            logger.exception("PLUGIN FAILED | %s.setup() raised", plugin.name)
            self.registry.mark(plugin.name, PluginState.FAILED, error=str(exc))
            return

        # Drain what the plugin registered — but only after setup() fully
        # succeeded, so a half-configured plugin contributes nothing.
        record.commands = list(ctx._commands)
        self._drain_actions(ctx)
        self._drain_subscriptions(ctx)
        self.registry.mark(plugin.name, PluginState.ENABLED)
        record.loaded_at = int(time.time())
        logger.info("PLUGIN LOADED | %s v%s (%d command(s))",
                    plugin.name, plugin.version, len(record.commands))

    def _drain_actions(self, ctx: PluginContext) -> None:
        if self.action_registry is None:
            return
        for action in ctx._actions:
            try:
                self.action_registry.register(action, replace=True)
            except Exception:
                logger.exception("PLUGIN | %s action registration failed",
                                 ctx.plugin_name)

    def _drain_subscriptions(self, ctx: PluginContext) -> None:
        if self.event_bus is None:
            return
        for handler, event_type in ctx._event_subs:
            try:
                self.event_bus.subscribe(handler, event_type)
            except Exception:
                logger.exception("PLUGIN | %s event subscription failed",
                                 ctx.plugin_name)

    # ---- enable / disable / unload ----

    def enable(self, name: str, actor: Optional[int] = None) -> bool:
        record = self.registry.get(name)
        if record is None:
            return False
        self._persist_enabled(name, True, actor)
        if record.state in (PluginState.DISABLED, PluginState.STOPPED, PluginState.FAILED):
            record.state = PluginState.DISCOVERED
            record.error = None
            self._load_one(record)
        return True

    def disable(self, name: str, actor: Optional[int] = None) -> bool:
        record = self.registry.get(name)
        if record is None:
            return False
        self._persist_enabled(name, False, actor)
        self._shutdown_one(record)
        record.state = PluginState.DISABLED
        record.commands = []
        return True

    def unload(self, name: str) -> bool:
        record = self.registry.get(name)
        if record is None:
            return False
        self._shutdown_one(record)
        record.state = PluginState.STOPPED
        record.commands = []
        return True

    def _shutdown_one(self, record: PluginRecord) -> None:
        try:
            record.plugin.shutdown()
        except Exception:
            logger.exception("PLUGIN | %s.shutdown() raised (ignored)", record.name)

    def shutdown_all(self) -> None:
        for record in self.registry.all():
            if record.state in (PluginState.ENABLED, PluginState.LOADED):
                self._shutdown_one(record)
                record.state = PluginState.STOPPED

    # ---- health / introspection ----

    def healthcheck(self, name: str) -> Optional[HealthStatus]:
        record = self.registry.get(name)
        if record is None:
            return None
        if record.state == PluginState.FAILED:
            status = HealthStatus.unhealthy(record.error or "plugin failed to load")
        elif record.state == PluginState.DISABLED:
            status = HealthStatus.unhealthy("disabled")
        else:
            try:
                status = record.plugin.healthcheck()
            except Exception as exc:
                logger.exception("PLUGIN | %s.healthcheck() raised", name)
                status = HealthStatus.unhealthy(f"healthcheck raised: {exc}")
        record.last_health = status
        return status

    def healthcheck_all(self) -> dict:
        return {r.name: self.healthcheck(r.name) for r in self.registry.all()}

    def iter_command_specs(self) -> List[CommandSpec]:
        specs: List[CommandSpec] = []
        for record in self.registry.all():
            if record.state == PluginState.ENABLED:
                specs.extend(record.commands)
        return specs

    def metadata(self) -> List[dict]:
        return [r.as_dict() for r in self.registry.all()]

    def summary(self) -> dict:
        states: dict = {}
        for record in self.registry.all():
            states[record.state] = states.get(record.state, 0) + 1
        return {
            "total": len(self.registry.all()),
            "by_state": states,
            "failed": [r.name for r in self.registry.by_state(PluginState.FAILED)],
        }

    # ---- persisted state (plugin_state table from migration 0002) ----

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _persisted_enabled(self, name: str) -> Optional[bool]:
        if not self.db_path:
            return None
        try:
            conn = self._conn()
            row = conn.execute(
                "SELECT enabled FROM plugin_state WHERE name=?", (name,)
            ).fetchone()
            conn.close()
            return None if row is None else bool(row["enabled"])
        except sqlite3.Error:
            return None

    def _persist_enabled(self, name: str, enabled: bool, actor: Optional[int]) -> None:
        if not self.db_path:
            return
        try:
            conn = self._conn()
            conn.execute(
                "INSERT INTO plugin_state (name, enabled, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, "
                "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (name, 1 if enabled else 0, int(time.time()), actor),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            logger.exception("PLUGIN | could not persist state for %s", name)
