# Example plugin

`hello_plugin.py` is a complete, safe Sombra Guardian plugin. It shows all
three plugin hooks: a command, a workflow action, and an event subscription,
plus a healthcheck.

## Try it

```bash
export SG_PLUGINS_DIR=/absolute/path/to/examples/plugin_example
python app.py
```

At boot the plugin manager discovers the file, calls its `setup()`, and:

- registers `/hello` (a PUBLIC command),
- adds a `greet` workflow action (usable from any workflow definition),
- subscribes to `member.joined` events.

Then, in a chat where the bot is admin:

```
/plugins list        # hello-example shows as 🟢 ENABLED
/plugins health      # shows its healthcheck line
/plugins info hello-example
/hello               # 👋 Hello from the example plugin!
```

## Writing your own

1. Subclass `plugins.base.BasePlugin`, set `name` / `version` / `description`.
2. Implement `setup(ctx)` and register what you need via `ctx`:
   - `ctx.register_command(name, handler, permission=..., description=...)`
   - `ctx.register_workflow_action(action)`  (`action.name` + async `execute`)
   - `ctx.subscribe_event(async_handler, event_type=None)`
3. Optionally implement `healthcheck()` (return `HealthStatus.ok(...)` /
   `HealthStatus.unhealthy(...)`) and `shutdown()`.

If your `setup()` raises, the manager marks the plugin `FAILED` and keeps
every other plugin — and the bot — running. Never put secrets in a plugin
file; read them from the environment instead.
