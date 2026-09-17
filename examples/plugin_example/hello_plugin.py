"""
examples/plugin_example/hello_plugin.py — a complete, safe example plugin.

Drop a copy of this file into a directory and point the environment variable
``SG_PLUGINS_DIR`` at that directory; the plugin manager discovers it at
startup alongside the built-ins. It demonstrates every plugin hook:

  * a Telegram command (``/hello``) — PUBLIC, so anyone may run it,
  * a workflow action (``greet``) any workflow can list, and
  * an event subscription that counts ``member.joined`` events,
  * a healthcheck surfaced by ``/plugins health``.

Nothing here contains a secret, touches another module's tables, or performs
moderation — an example plugin must be safe to run as-is.
"""

from plugins.base import BasePlugin, PluginContext, HealthStatus, PermissionLevel


class _GreetAction:
    """A workflow action (duck-typed: ``name`` + async ``execute``)."""
    name = "greet"

    async def execute(self, context):
        from workflows.models import ActionResult
        who = context["event"].payload.get("display_name", "friend")
        context["logger"].info("hello-plugin greet | %s", who)
        return ActionResult.success(self.name, f"greeted {who}")


class HelloPlugin(BasePlugin):
    name = "hello-example"
    version = "1.0.0"
    description = "Example plugin: a /hello command, a greet action, and health."
    author = "you"
    permission = PermissionLevel.ADMIN   # who may administer it via /plugins

    def __init__(self):
        self._joins_seen = 0

    def setup(self, ctx: PluginContext) -> None:
        ctx.register_command("hello", self._cmd_hello,
                             permission=PermissionLevel.PUBLIC,
                             description="say hello")
        ctx.register_workflow_action(_GreetAction())
        ctx.subscribe_event(self._on_join, "member.joined")

    async def _cmd_hello(self, update, context):
        await update.message.reply_text("👋 Hello from the example plugin!")

    async def _on_join(self, event):
        self._joins_seen += 1

    def healthcheck(self) -> HealthStatus:
        return HealthStatus.ok(f"seen {self._joins_seen} join event(s)")
