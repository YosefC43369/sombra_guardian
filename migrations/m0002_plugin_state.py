"""
migrations/m0002_plugin_state.py — persisted plugin enable/disable state.

The plugin manager keeps runtime state in memory, but an admin's
``/plugins disable <name>`` should survive a restart. This one small table
records the last explicit enable/disable decision per plugin; the manager
reads it on load and honours it. Absence of a row means "use the plugin's
default", so nothing changes for plugins an admin never touched.
"""

from .base import Migration


class PluginStateMigration(Migration):
    version = "0002"
    description = "persisted plugin enable/disable state"
    destructive = False

    def upgrade(self, conn) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS plugin_state (
                name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL,
                updated_by INTEGER
            )"""
        )

    def downgrade(self, conn) -> None:
        conn.execute("DROP TABLE IF EXISTS plugin_state")
