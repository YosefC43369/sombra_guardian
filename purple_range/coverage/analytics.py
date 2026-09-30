"""
purple_range/coverage/analytics.py — program-wide ATT&CK coverage.

Aggregates per-exercise coverage (from ``purpleteam.get_technique_coverage``) across all
exercises in a chat into one program view: for each technique, the BEST coverage state
observed and how many exercises touched it. Optionally overlays the plan library so
techniques that are planned-but-never-exercised show up as gaps.

Read-only over purpleteam data; reuses the ATT&CK catalog for names/tactics. No writes
except an explicit snapshot.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ..models import CoverageCell
from ..attack import get_catalog
from ..constants import TACTICS_ORDERED

logger = logging.getLogger("modbot.purple_range.coverage")

# purpleteam Coverage states ranked worst→best
_COVERAGE_RANK = {"NONE": 0, "TELEMETRY": 1, "PARTIAL": 2, "DETECTION": 3}
_RANK_COVERAGE = {v: k for k, v in _COVERAGE_RANK.items()}


class CoverageAnalytics:
    def __init__(self, store=None, plan_registry=None):
        self.store = store
        self.plans = plan_registry
        self._pt = None

    def _engine(self):
        if self._pt is None:
            import purpleteam
            self._pt = purpleteam
        return self._pt

    def program_matrix(self, chat_id: int, include_library: bool = True) -> List[CoverageCell]:
        pt = self._engine()
        catalog = get_catalog()
        agg: Dict[str, dict] = {}

        for ex in pt.list_exercises(int(chat_id)) or []:
            ex_id = ex.get("exercise_id") if isinstance(ex, dict) else None
            if ex_id is None:
                continue
            for row in pt.get_technique_coverage(int(ex_id)) or []:
                tid = row.get("technique_id")
                if not tid:
                    continue
                rank = _COVERAGE_RANK.get(str(row.get("coverage", "NONE")), 0)
                m = agg.setdefault(tid, {"rank": -1, "count": 0,
                                         "tactic": row.get("tactic") or "",
                                         "name": row.get("technique_name") or ""})
                m["count"] += 1
                if rank > m["rank"]:
                    m["rank"] = rank
                if not m["tactic"] and row.get("tactic"):
                    m["tactic"] = row["tactic"]
                if not m["name"] and row.get("technique_name"):
                    m["name"] = row["technique_name"]

        if include_library and self.plans is not None:
            for plan in self.plans.list_all():
                for step in plan.steps:
                    if step.technique_id not in agg:
                        agg[step.technique_id] = {"rank": -1, "count": 0,
                                                  "tactic": step.tactic,
                                                  "name": step.name}

        cells: List[CoverageCell] = []
        for tid, m in agg.items():
            tactic = m["tactic"] or (catalog.technique_tactics(tid)[:1] or [""])[0]
            name = m["name"] or catalog.technique_name(tid)
            rank = m["rank"]
            cells.append(CoverageCell(
                technique_id=tid, tactic=tactic, technique_name=name,
                exercised=(m["count"] > 0),
                best_coverage=_RANK_COVERAGE.get(rank, "NONE") if rank >= 0 else "NONE",
                exercise_count=m["count"]))
        cells.sort(key=lambda c: (self._tactic_order(c.tactic), c.technique_id))
        return cells

    @staticmethod
    def _tactic_order(tactic: str) -> int:
        try:
            return TACTICS_ORDERED.index(tactic)
        except ValueError:
            return len(TACTICS_ORDERED)

    def summarize(self, cells: List[CoverageCell]) -> dict:
        total = len(cells)
        exercised = sum(1 for c in cells if c.exercised)
        detected = sum(1 for c in cells if c.best_coverage == "DETECTION")
        by_state: Dict[str, int] = {}
        by_tactic: Dict[str, dict] = {}
        for c in cells:
            by_state[c.best_coverage] = by_state.get(c.best_coverage, 0) + 1
            t = by_tactic.setdefault(c.tactic or "unknown", {"total": 0, "detection": 0})
            t["total"] += 1
            if c.best_coverage == "DETECTION":
                t["detection"] += 1
        return {
            "total_techniques": total,
            "exercised": exercised,
            "detection": detected,
            "exercised_pct": round(100.0 * exercised / total, 1) if total else 0.0,
            "detection_pct": round(100.0 * detected / total, 1) if total else 0.0,
            "by_state": by_state,
            "by_tactic": by_tactic,
        }

    def snapshot(self, chat_id: int, taken_by: Optional[int] = None) -> dict:
        cells = self.program_matrix(chat_id)
        summary = self.summarize(cells)
        matrix = [c.as_dict() for c in cells]
        if self.store is not None:
            try:
                self.store.save_coverage_snapshot(chat_id, taken_by, matrix, summary)
                from security import write_audit_log
                from ..constants import AUDIT_COVERAGE_SNAPSHOT
                write_audit_log(int(chat_id), int(taken_by or 0), actor="user",
                                action=AUDIT_COVERAGE_SNAPSHOT,
                                detail=f"techniques={summary['total_techniques']} "
                                       f"detection_pct={summary['detection_pct']}")
            except Exception:
                logger.debug("coverage snapshot not persisted", exc_info=True)
        return {"matrix": matrix, "summary": summary}
