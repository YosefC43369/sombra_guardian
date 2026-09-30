"""
purple_range/storage/repository.py — persistence for the module's own content.

Short-lived connections, WAL, sqlite3.Row, parameterized SQL (repo idiom). Schema is
owned by migration 0007. This store never reads or writes the purpleteam pt_* tables;
those are reached only through the purpleteam public API.
"""

from __future__ import annotations

import sqlite3
import logging
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from ..models import Plan, PlanStep, Expectation
from ..exceptions import StorageError
from ..util import now, json_dump, json_load, bounded_limit
from ..constants import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT

logger = logging.getLogger("modbot.purple_range.storage")


class PurpleRangeStore:
    def __init__(self, db_path: str = "bot.db"):
        self.db_path = db_path

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise StorageError(str(exc), code="PR_STORAGE_ERROR") from exc
        finally:
            conn.close()

    # ---- custom plans ----
    def save_plan(self, plan: Plan, chat_id: int = 0, created_by: Optional[int] = None) -> None:
        ts = now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO pr_plans (code, chat_id, name, description, risk_level,
                       framework, source, tags, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'custom', ?, ?, ?, ?)
                   ON CONFLICT(code) DO UPDATE SET name=excluded.name,
                       description=excluded.description, risk_level=excluded.risk_level,
                       framework=excluded.framework, tags=excluded.tags,
                       updated_at=excluded.updated_at""",
                (plan.code, int(chat_id), plan.name, plan.description, plan.risk_level,
                 plan.framework, json_dump(plan.tags), created_by, ts, ts))
            conn.execute("DELETE FROM pr_plan_steps WHERE plan_code=?", (plan.code,))
            for step in plan.steps:
                conn.execute(
                    """INSERT INTO pr_plan_steps (plan_code, step_order, technique_id,
                           tactic, name, description, expectation)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (plan.code, step.order, step.technique_id, step.tactic, step.name,
                     step.description, json_dump(step.expectation.as_dict())))

    def get_plan(self, code: str) -> Optional[Plan]:
        code = (code or "").strip().lower()
        with self._conn() as conn:
            prow = conn.execute("SELECT * FROM pr_plans WHERE code=?", (code,)).fetchone()
            if prow is None:
                return None
            srows = conn.execute(
                "SELECT * FROM pr_plan_steps WHERE plan_code=? ORDER BY step_order", (code,)
            ).fetchall()
        steps = [PlanStep(order=int(s["step_order"]), technique_id=s["technique_id"],
                          tactic=s["tactic"] or "", name=s["name"] or "",
                          description=s["description"] or "",
                          expectation=Expectation.from_dict(json_load(s["expectation"])))
                 for s in srows]
        if not steps:
            return None
        return Plan(code=prow["code"], name=prow["name"],
                    description=prow["description"] or "",
                    risk_level=prow["risk_level"], framework=prow["framework"],
                    source="custom", tags=list(json_load(prow["tags"]) or []), steps=steps)

    def list_plans(self, limit: int = MAX_PAGE_LIMIT) -> List[Plan]:
        with self._conn() as conn:
            codes = [r["code"] for r in conn.execute(
                "SELECT code FROM pr_plans ORDER BY code LIMIT ?",
                (bounded_limit(limit, MAX_PAGE_LIMIT, MAX_PAGE_LIMIT),)).fetchall()]
        return [p for p in (self.get_plan(c) for c in codes) if p is not None]

    # ---- instantiations ----
    def record_instantiation(self, chat_id: int, plan_code: str, exercise_id: int,
                             exercise_code: str, engagement_id: int,
                             operator_id: Optional[int], step_count: int) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO pr_instantiations (chat_id, plan_code, exercise_id,
                       exercise_code, engagement_id, operator_id, step_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (int(chat_id), plan_code, int(exercise_id), exercise_code,
                 int(engagement_id), operator_id, int(step_count), now()))
            return cur.lastrowid or 0

    def list_instantiations(self, chat_id: int, limit: int = DEFAULT_PAGE_LIMIT) -> List[Dict[str, Any]]:
        n = bounded_limit(limit, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT)
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM pr_instantiations WHERE chat_id=? ORDER BY created_at DESC LIMIT ?",
                (int(chat_id), n)).fetchall()]

    # ---- coverage snapshots ----
    def save_coverage_snapshot(self, chat_id: int, taken_by: Optional[int],
                               matrix: Any, summary: Any) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO pr_coverage_snapshots (chat_id, taken_at, taken_by, matrix, summary)
                   VALUES (?, ?, ?, ?, ?)""",
                (int(chat_id), now(), taken_by, json_dump(matrix), json_dump(summary)))
            return cur.lastrowid or 0

    def latest_coverage_snapshot(self, chat_id: int) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pr_coverage_snapshots WHERE chat_id=? ORDER BY taken_at DESC LIMIT 1",
                (int(chat_id),)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["matrix"] = json_load(d.get("matrix"))
        d["summary"] = json_load(d.get("summary"))
        return d
