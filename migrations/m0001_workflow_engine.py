"""
migrations/m0001_workflow_engine.py — schema for the Workflow Automation Engine.

Creates the tables the engine needs to run safely and auditably:

    wf_workflow_state   per-workflow enabled/disabled flag (persisted so an
                        admin's /workflow disable survives a restart)
    wf_executions       one row per workflow run: unique execution id,
                        correlation id, dedup key, state, retry/depth counters
    wf_execution_log    per-execution step log (action-by-action trail)
    wf_audit            high-level audit trail (started/completed/failed/...)

All tables are prefixed ``wf_`` and are created with IF NOT EXISTS, so this
migration never touches any pre-existing table owned by another module.
"""

from .base import Migration


class WorkflowEngineMigration(Migration):
    version = "0001"
    description = "workflow automation engine tables"
    destructive = False

    def upgrade(self, conn) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS wf_workflow_state (
                name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL,
                updated_by INTEGER
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS wf_executions (
                execution_id TEXT PRIMARY KEY,
                workflow_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                correlation_id TEXT,
                dedup_key TEXT,
                state TEXT NOT NULL,
                depth INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                finished_at INTEGER,
                error TEXT,
                context_json TEXT
            )"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_wf_executions_workflow
                ON wf_executions (workflow_name, created_at)"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_wf_executions_dedup
                ON wf_executions (workflow_name, dedup_key)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS wf_execution_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                level TEXT NOT NULL,
                action TEXT,
                message TEXT
            )"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_wf_execution_log_exec
                ON wf_execution_log (execution_id)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS wf_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                workflow_name TEXT,
                event_type TEXT,
                execution_id TEXT,
                correlation_id TEXT,
                severity TEXT,
                actor TEXT,
                detail TEXT
            )"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_wf_audit_created
                ON wf_audit (created_at)"""
        )

    def downgrade(self, conn) -> None:
        # Drops are destructive, but this migration is only rolled back by an
        # explicit, admin-confirmed /migration down, which the runner already
        # gates. The tables hold operational logs, not the bot's core data.
        for table in ("wf_execution_log", "wf_audit", "wf_executions",
                      "wf_workflow_state"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
