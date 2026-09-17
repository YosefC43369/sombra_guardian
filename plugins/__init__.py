"""
plugins/ — the Plugin Architecture for Sombra Guardian.

Lets features register commands, workflow actions and event subscriptions
without adding another hard-coded block to app.py. The design goal is that
one plugin misbehaving never takes down the others or the bot:

    Plugin A -> FAILED
    Plugin B -> ENABLED
    Plugin C -> ENABLED
    (bot keeps running)

Public surface
--------------
``BasePlugin`` / ``PluginContext``     what a plugin subclasses / uses
``PermissionLevel`` / ``HealthStatus`` / ``CommandSpec`` / ``PluginState``
``PluginManager``                      discover / load / enable / health
``PluginRegistry`` / ``PluginRecord``  bookkeeping
"""

from .base import (
    BasePlugin, PluginContext, PermissionLevel, PluginState,
    HealthStatus, CommandSpec,
)
from .registry import PluginRegistry, PluginRecord
from .manager import PluginManager

__all__ = [
    "BasePlugin", "PluginContext", "PermissionLevel", "PluginState",
    "HealthStatus", "CommandSpec", "PluginRegistry", "PluginRecord",
    "PluginManager",
]
