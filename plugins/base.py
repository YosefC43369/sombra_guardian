"""
plugins/base.py — the plugin contract.

A plugin is a self-contained feature bundle that registers commands, workflow
actions and/or event subscriptions without app.py having to grow another
hard-coded block. The interface is small and every hook is optional:

    class MyPlugin(BasePlugin):
        name = "my-plugin"
        version = "1.0.0"
        description = "..."
        def setup(self, ctx): ...        # register things via ctx
        def shutdown(self): ...          # release resources (optional)
        def healthcheck(self) -> HealthStatus: ...   # optional

Permission model — reuses the bot's existing authority
------------------------------------------------------
There is no new auth system here. A command a plugin registers carries a
:class:`PermissionLevel`; when it is ADMIN/OWNER/SYSTEM the platform gates it
with app.py's existing ``is_admin`` check (Telegram admin/owner status).
PUBLIC and MODERATOR run for everyone the bot already lets use it. The levels
exist so a plugin can *declare* intent; enforcement stays with the one
authority the bot already trusts.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional


class PermissionLevel(IntEnum):
    """Ordered so ``level >= PermissionLevel.ADMIN`` is meaningful."""
    PUBLIC = 0
    MODERATOR = 1
    ADMIN = 2
    OWNER = 3
    SYSTEM = 4

    @classmethod
    def parse(cls, value) -> "PermissionLevel":
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            return cls.ADMIN  # default to a safe (restrictive) level


class PluginState(str):
    """Lifecycle states a plugin moves through in the registry."""
    DISCOVERED = "DISCOVERED"
    LOADED = "LOADED"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


@dataclass
class HealthStatus:
    healthy: bool
    detail: str = "ok"

    @classmethod
    def ok(cls, detail: str = "ok") -> "HealthStatus":
        return cls(True, detail)

    @classmethod
    def unhealthy(cls, detail: str) -> "HealthStatus":
        return cls(False, detail)


@dataclass
class CommandSpec:
    """A command a plugin wants registered. ``handler`` is a
    python-telegram-bot style ``async def handler(update, context)``."""
    name: str
    handler: Callable
    permission: PermissionLevel = PermissionLevel.PUBLIC
    description: str = ""
    plugin: str = ""


@dataclass
class PluginContext:
    """Handed to ``setup()``. The single surface a plugin uses to register
    into the platform, so plugins never import app.py or the engine directly.

    Registration is buffered here and drained by the PluginManager, which
    keeps setup() pure (no side effects on the live Application) and lets one
    plugin's failure be isolated before anything it registered goes live.
    """
    plugin_name: str
    db_path: Optional[str] = None
    engine: Any = None                    # workflows.WorkflowEngine (or None)
    action_registry: Any = None           # workflows.ActionRegistry (or None)
    event_bus: Any = None                 # workflows.EventBus (or None)
    logger: Any = None
    config: Dict[str, Any] = field(default_factory=dict)

    # buffers drained by the manager
    _commands: List[CommandSpec] = field(default_factory=list)
    _event_subs: List[tuple] = field(default_factory=list)
    _actions: List[Any] = field(default_factory=list)

    def register_command(self, name: str, handler: Callable,
                         permission=PermissionLevel.PUBLIC,
                         description: str = "") -> None:
        self._commands.append(CommandSpec(
            name=name, handler=handler,
            permission=PermissionLevel.parse(permission),
            description=description, plugin=self.plugin_name,
        ))

    def register_workflow_action(self, action) -> None:
        """Add a WorkflowAction so workflows can use it by name."""
        self._actions.append(action)

    def subscribe_event(self, handler: Callable, event_type: str = None) -> None:
        """Subscribe an async handler to the event bus (all events, or one
        type). Plugins use this to react to events without a workflow."""
        self._event_subs.append((handler, event_type))


class BasePlugin:
    """Subclass this. Only ``name`` is strictly required; ``setup`` is where
    the plugin registers its commands/actions/subscriptions."""

    name: str = ""
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    # Minimum authority to *administer* this plugin via /plugins. Individual
    # commands set their own PermissionLevel independently.
    permission: PermissionLevel = PermissionLevel.ADMIN

    def setup(self, ctx: PluginContext) -> None:
        """Register commands/actions/subscriptions via ``ctx``. Default:
        nothing. Raising here marks the plugin FAILED and isolates it — other
        plugins and the bot itself keep running."""

    def shutdown(self) -> None:
        """Release resources. Default: nothing."""

    def healthcheck(self) -> HealthStatus:
        """Report health for /plugins health. Default: healthy."""
        return HealthStatus.ok()

    def metadata(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "permission": PermissionLevel.parse(self.permission).name,
        }
