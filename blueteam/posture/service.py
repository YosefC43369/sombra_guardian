"""
blueteam/posture/service.py — Posture orchestration.

Computes a snapshot from a :class:`SignalsProvider` (control_id -> status, derived
from the bot's own config/state — never by scanning raw events), persists snapshots
and hourly **rollups** for trend, builds the client report, seals its SHA-256 to the
integrity ledger (injected port) and verifies it. Multi-group **portfolio** rolls
several chats up for an MSSP view. Depends only on ports + the pure core.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Protocol

from .domain import (Assessment, Control, ScoreResult, compute_score, explain,
                     whatif, STATUS_SCORE)
from .report import (Branding, ReportModel, render_html, render_markdown,
                     render_json, render_csv, report_sha256, maybe_pdf)


class PostureRepository(Protocol):
    def save_snapshot(self, snapshot_id: str, tenant_id: str, chat_id: int,
                      score: float, grade: str, coverage: float, breakdown: str,
                      now: float) -> None: ...
    def latest_snapshot(self, chat_id: int) -> Optional[Dict[str, Any]]: ...
    def snapshots(self, chat_id: int, limit: int) -> List[Dict[str, Any]]: ...
    def add_rollup(self, chat_id: int, metric: str, hour: int, value: float) -> None: ...
    def rollups(self, chat_id: int, metric: str, since_hour: int) -> List[Dict[str, Any]]: ...
    def save_report(self, report_id: str, tenant_id: str, chat_id: int, profile: str,
                    fmt: str, sha256: str, now: float) -> None: ...
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]: ...
    def get_branding(self, tenant_id: str) -> Dict[str, Any]: ...
    def set_branding(self, tenant_id: str, fields: Dict[str, Any]) -> None: ...


class SignalsProvider(Protocol):
    def assess(self, chat_id: int) -> Dict[str, str]: ...   # control_id -> status


class PostureService:
    def __init__(self, repo: PostureRepository, *, catalog: Dict[str, Control],
                 signals: SignalsProvider, clock: Callable[[], float] = time.time,
                 metrics=None, emit: Optional[Callable[[Any], None]] = None,
                 sealer: Optional[Callable[[str, dict], str]] = None,
                 tenant_of: Optional[Callable[[int], str]] = None):
        self._repo = repo
        self._catalog = catalog
        self._signals = signals
        self._clock = clock
        self._metrics = metrics
        self._emit = emit or (lambda e: None)
        self._sealer = sealer
        self._tenant_of = tenant_of or (lambda cid: f"chat:{cid}")

    # ---------------- scoring ----------------
    def _assessments(self, chat_id: int) -> Dict[str, Assessment]:
        raw = self._signals.assess(chat_id) or {}
        out: Dict[str, Assessment] = {}
        for cid in self._catalog:
            status = raw.get(cid, "unknown")
            if status not in STATUS_SCORE:
                status = "unknown"
            out[cid] = Assessment(cid, status)
        return out

    def score(self, chat_id: int) -> ScoreResult:
        return compute_score(self._catalog, self._assessments(chat_id))

    def explain(self, chat_id: int, top: int = 8) -> Dict[str, Any]:
        return explain(self._catalog, self._assessments(chat_id), top=top)

    def whatif(self, chat_id: int, changes: Dict[str, str]) -> Dict[str, Any]:
        return whatif(self._catalog, self._assessments(chat_id), changes)

    def record_snapshot(self, chat_id: int) -> Dict[str, Any]:
        now = self._clock()
        res = self.score(chat_id)
        tenant = self._tenant_of(chat_id)
        sid = uuid.uuid4().hex
        import json
        self._repo.save_snapshot(sid, tenant, chat_id, res.score, res.grade.value,
                                 res.coverage, json.dumps(res.to_dict(), ensure_ascii=False), now)
        hour = int(now // 3600)
        self._repo.add_rollup(chat_id, "score", hour, res.score)
        self._repo.add_rollup(chat_id, "coverage", hour, res.coverage * 100.0)
        prev = self._repo.latest_snapshot(chat_id)
        self._emit(_snapshot_created(tenant, chat_id, res.score, res.grade.value, res.coverage))
        if prev and prev.get("score", res.score) - res.score >= 10:
            self._emit(_score_dropped(tenant, chat_id, prev["score"], res.score))
        if self._metrics:
            self._metrics.gauge("bt_posture_score", res.score, chat=str(chat_id))
        return {"snapshot_id": sid, **res.to_dict()}

    def trend(self, chat_id: int, hours: int = 168) -> List[float]:
        since = int(self._clock() // 3600) - hours
        rows = self._repo.rollups(chat_id, "score", since)
        return [round(r["value"], 1) for r in rows]

    # ---------------- portfolio ----------------
    def portfolio(self, chat_ids: List[int]) -> Dict[str, Any]:
        entries = []
        for cid in chat_ids:
            r = self.score(cid)
            entries.append({"chat_id": cid, "score": round(r.score, 1),
                            "grade": r.grade.value, "coverage": round(r.coverage, 3)})
        entries.sort(key=lambda e: e["score"])
        avg = round(sum(e["score"] for e in entries) / len(entries), 1) if entries else 0.0
        return {"count": len(entries), "avg_score": avg, "groups": entries,
                "weakest": entries[0] if entries else None}

    # ---------------- report ----------------
    def _categories(self, res: ScoreResult) -> Dict[str, float]:
        buckets: Dict[str, List[float]] = {}
        for c in res.contributions:
            if c.get("sub_score") is None:
                continue
            cat = self._catalog[c["control"]].category if c["control"] in self._catalog else "อื่นๆ"
            buckets.setdefault(cat, []).append(c["sub_score"] * 100.0)
        return {k: round(sum(v) / len(v), 1) for k, v in buckets.items() if v}

    def build_report_model(self, chat_id: int, *, profile: str = "internal",
                           subject_name: str = "") -> ReportModel:
        res = self.score(chat_id)
        exp = self.explain(chat_id)
        contributions = res.contributions
        subject = subject_name or (f"กลุ่ม #{abs(chat_id) % 100000}" if profile == "client"
                                   else str(chat_id))
        if profile == "client":
            # drop internal notes; keep only presentation fields
            contributions = [{"name": c["name"], "status": c["status"], "weight": c["weight"],
                              "sub_score": c["sub_score"], "critical": c["critical"]}
                             for c in contributions]
        from datetime import datetime, timezone
        gen = datetime.fromtimestamp(self._clock(), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return ReportModel(
            title="รายงานสถานะความปลอดภัยกลุ่ม", subject_label=subject, generated_at=gen,
            score=res.score, grade=res.grade.value, coverage=res.coverage,
            contributions=contributions, gates=res.gates,
            top_actions=exp["top_actions"], trend=self.trend(chat_id),
            categories=self._categories(res), profile=profile)

    def generate_report(self, chat_id: int, *, fmt: str = "html", profile: str = "internal",
                        subject_name: str = "") -> Dict[str, Any]:
        tenant = self._tenant_of(chat_id)
        branding = self._branding(tenant)
        model = self.build_report_model(chat_id, profile=profile, subject_name=subject_name)
        fmt = fmt.lower()
        if fmt == "md":
            content, mime = render_markdown(model, branding), "text/markdown"
        elif fmt == "json":
            content, mime = render_json(model), "application/json"
        elif fmt == "csv":
            content, mime = render_csv(model), "text/csv"
        else:
            content, mime = render_html(model, branding), "text/html"
            fmt = "html"
        sha = report_sha256(content)
        rid = uuid.uuid4().hex
        now = self._clock()
        self._repo.save_report(rid, tenant, chat_id, profile, fmt, sha, now)
        self._seal("posture_report", {"report_id": rid, "chat_id": chat_id,
                                       "sha256": sha, "profile": profile, "fmt": fmt})
        self._emit(_report_generated(tenant, rid, profile, fmt, sha))
        pdf = maybe_pdf(content) if fmt == "html" else None
        return {"report_id": rid, "fmt": fmt, "mime": mime, "sha256": sha,
                "content": content, "pdf_available": pdf is not None, "pdf": pdf}

    def verify_report(self, report_id: str, content: str) -> Dict[str, Any]:
        rec = self._repo.get_report(report_id)
        if not rec:
            return {"ok": False, "error": "unknown report"}
        actual = report_sha256(content)
        return {"ok": actual == rec["sha256"], "stored": rec["sha256"], "actual": actual}

    # ---------------- branding ----------------
    def _branding(self, tenant: str) -> Branding:
        b = self._repo.get_branding(tenant) or {}
        return Branding(brand_name=b.get("brand_name") or "Sombra Guardian",
                        brand_color=b.get("brand_color") or "#0b3d5c",
                        footer=b.get("brand_footer") or "")

    def set_branding(self, chat_id: int, **fields) -> None:
        self._repo.set_branding(self._tenant_of(chat_id), fields)

    def get_branding(self, chat_id: int) -> Branding:
        return self._branding(self._tenant_of(chat_id))

    def _seal(self, kind: str, payload: dict) -> None:
        if self._sealer is None:
            return
        try:
            self._sealer(kind, payload)
        except Exception:
            if self._metrics:
                self._metrics.incr("bt_posture_seal_error")


def _snapshot_created(tenant, chat_id, score, grade, coverage):
    from ..platform.events import PostureSnapshotCreated
    return PostureSnapshotCreated(tenant=tenant, chat_id=chat_id, score=score,
                                  grade=grade, coverage=coverage)


def _score_dropped(tenant, chat_id, old, new):
    from ..platform.events import PostureScoreDropped
    return PostureScoreDropped(tenant=tenant, chat_id=chat_id, old_score=old,
                               new_score=new, delta=new - old)


def _report_generated(tenant, rid, profile, fmt, sha):
    from ..platform.events import ReportGenerated
    return ReportGenerated(tenant=tenant, report_id=rid, profile=profile, fmt=fmt, sha256=sha)


__all__ = ["PostureService", "PostureRepository", "SignalsProvider"]
