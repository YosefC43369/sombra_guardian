"""
plugins/registry.py — bookkeeping for discovered/loaded plugins.

Holds one :class:`PluginRecord` per plugin: the instance, its lifecycle
state, the commands it contributed, and the last error/health seen. The
manager mutates records; commands and status views read them.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .base import BasePlugin, PluginState, CommandSpec, HealthStatus


@dataclass
class PluginRecord:
    plugin: BasePlugin
    state: str = PluginState.DISCOVERED
    error: Optional[str] = None
    commands: List[CommandSpec] = field(default_factory=list)
    last_health: Optional[HealthStatus] = None
    loaded_at: Optional[int] = None

    @property
    def name(self) -> str:
        return self.plugin.name

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state,
            "version": self.plugin.version,
            "description": self.plugin.description,
            "error": self.error,
            "commands": [c.name for c in self.commands],
            "health": None if self.last_health is None else {
                "healthy": self.last_health.healthy,
                "detail": self.last_health.detail,
            },
        }


class PluginRegistry:
    def __init__(self):
        self._records: Dict[str, PluginRecord] = {}

    def add(self, plugin: BasePlugin) -> PluginRecord:
        if plugin.name in self._records:
            raise ValueError(f"duplicate plugin name {plugin.name!r}")
        record = PluginRecord(plugin=plugin)
        self._records[plugin.name] = record
        return record

    def get(self, name: str) -> Optional[PluginRecord]:
        return self._records.get(name)

    def all(self) -> List[PluginRecord]:
        return [self._records[n] for n in sorted(self._records)]

    def by_state(self, state: str) -> List[PluginRecord]:
        return [r for r in self.all() if r.state == state]

    def mark(self, name: str, state: str, error: Optional[str] = None) -> None:
        record = self._records.get(name)
        if record is None:
            return
        record.state = state
        record.error = error
        if state in (PluginState.LOADED, PluginState.ENABLED) and record.loaded_at is None:
            record.loaded_at = int(time.time())
