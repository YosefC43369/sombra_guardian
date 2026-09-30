"""
migrations/m0007_purple_range.py — schema for the Purple Range module.

Every table is ``pr_``-prefixed, chat-scoped, created with ``IF NOT EXISTS`` and paired
with a real ``downgrade`` — NON-destructive and reversible. Only DDL here.

The purple-team *engine* tables (pt_exercises/pt_emulations/pt_detections/pt_tuning) are
owned by purpleteam.py and are NOT touched. These tables only hold Purple Range's own
additive content: custom plans, plan→exercise instantiation links, and coverage snapshots.
"""

from .base import Migration


class PurpleRangeMigration(Migration):
    version = "0007"
    description = "Purple Range: custom plans, plan steps, instantiations, coverage snapshots"
    destructive = False

    _TABLES = ("pr_coverage_snapshots", "pr_instantiations", "pr_plan_steps", "pr_plans")

    def upgrade(self, conn) -> None:
        c = conn.execute

        # custom (operator-registered) plans; builtin plans live as fixtures, not here
        c("""CREATE TABLE IF NOT EXISTS pr_plans (
            code        TEXT PRIMARY KEY,
            chat_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            description TEXT,
            risk_level  TEXT NOT NULL DEFAULT 'LOW',
            framework   TEXT NOT NULL DEFAULT 'MITRE_ATTACK',
            source      TEXT NOT NULL DEFAULT 'custom',
            tags        TEXT,
            created_by  INTEGER,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_pr_plans_chat ON pr_plans(chat_id)")

        c("""CREATE TABLE IF NOT EXISTS pr_plan_steps (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_code    TEXT NOT NULL,
            step_order   INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            tactic       TEXT,
            name         TEXT,
            description  TEXT,
            expectation  TEXT,
            UNIQUE(plan_code, step_order)
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_pr_steps_plan ON pr_plan_steps(plan_code)")

        # link a plan to the purpleteam exercise it was instantiated into
        c("""CREATE TABLE IF NOT EXISTS pr_instantiations (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id       INTEGER NOT NULL,
            plan_code     TEXT NOT NULL,
            exercise_id   INTEGER NOT NULL,
            exercise_code TEXT,
            engagement_id INTEGER NOT NULL,
            operator_id   INTEGER,
            step_count    INTEGER NOT NULL DEFAULT 0,
            created_at    INTEGER NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_pr_inst_chat ON pr_instantiations(chat_id, created_at)")
        c("CREATE INDEX IF NOT EXISTS ix_pr_inst_ex ON pr_instantiations(exercise_id)")
        c("CREATE INDEX IF NOT EXISTS ix_pr_inst_plan ON pr_instantiations(plan_code)")

        # point-in-time program coverage snapshots
        c("""CREATE TABLE IF NOT EXISTS pr_coverage_snapshots (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id   INTEGER NOT NULL,
            taken_at  INTEGER NOT NULL,
            taken_by  INTEGER,
            matrix    TEXT,
            summary   TEXT
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_pr_cov_chat ON pr_coverage_snapshots(chat_id, taken_at)")

    def downgrade(self, conn) -> None:
        for table in self._TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
