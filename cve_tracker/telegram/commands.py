"""
cve_tracker.telegram.commands — the command logic, decoupled from Telegram.

Every command is a method that takes plain arguments and returns rendered text
(and optionally an inline keyboard token), so the whole surface is unit-testable
with no bot. :class:`CVEHandlers` (in handlers.py) is the thin Telegram adapter
that calls these. Commands map onto the project's existing command architecture
via the plugin suite (rule §20), and administrative ones (sync/test) are gated
by the host's is_admin through the permission checker.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional, Tuple

from ..constants import EMOJI, SEVERITY_EMOJI
from ..models import CVERecord
from ..storage.repository import CVERepository
from ..search.service import SearchService
from ..search.query import parse as parse_query
from ..alerts.formatter import format_new_cve, format_compact
from ..alerts import templates
from ..enrichment import timeline as timeline_engine
from ..intelligence.scoring import compute_breakdown
from ..enrichment.cwe import format_cwe_label
from ..enrichment.cpe import format_product_label
from ..enrichment.products import top_products
from ..utils import escape_html as esc, humanize_ago, now_epoch, thai_date
from .preferences import SubscriptionService
from . import pagination

logger = logging.getLogger("modbot.cve.commands")


class CVECommandService:
    def __init__(self, repo: CVERepository, config, *, runtime=None,
                 summarizer=None):
        self.repo = repo
        self.config = config
        self.runtime = runtime
        self.summarizer = summarizer
        self.search = SearchService(repo)
        self.subs = SubscriptionService(repo)
        # bounded query-token map for pagination callbacks
        self._tokens: dict = {}

    # ---------------- token helpers for pagination ----------------

    def _token_for(self, query: str) -> str:
        token = str(abs(hash(query)) % (10 ** 9))
        self._tokens[token] = (query, time.time())
        # prune old
        if len(self._tokens) > 500:
            cutoff = time.time() - 3600
            for k in [k for k, (_, t) in self._tokens.items() if t < cutoff]:
                self._tokens.pop(k, None)
        return token

    def query_for_token(self, token: str) -> Optional[str]:
        entry = self._tokens.get(token)
        return entry[0] if entry else None

    # ---------------- lookups ----------------

    def cmd_info(self, cve_id: str) -> str:
        rec = self.search.get_one(cve_id)
        if rec is None:
            return f"{EMOJI['unknown']} ไม่พบข้อมูล {esc(cve_id)} ในฐานข้อมูล"
        return self.render_detail(rec)

    def cmd_search(self, query_text: str, *, page: int = 1, page_size: int = 5) -> Tuple[str, Optional[str]]:
        if not query_text.strip():
            return "พิมพ์คำค้น เช่น /cve_search apache หรือ /cve_search severity:critical", None
        result = self.search.search(query_text, page=page, page_size=page_size)
        token = self._token_for(query_text)
        header = f"🔎 ผลการค้นหา: <code>{esc(query_text)}</code>"
        return pagination.render_page(result, header=header), token

    def cmd_search_page(self, token: str, page: int, *, page_size: int = 5):
        query = self.query_for_token(token)
        if query is None:
            return None, None, None
        result = self.search.search(query, page=page, page_size=page_size)
        header = f"🔎 ผลการค้นหา: <code>{esc(query)}</code>"
        return pagination.render_page(result, header=header), result, token

    async def cmd_ask(self, query_text: str, *, page_size: int = 5) -> str:
        """Natural-language search (rule §53). Uses the AI adapter to shape
        filters when available; the DB is always the source of truth."""
        if not query_text.strip():
            return "ถามเป็นภาษาธรรมชาติ เช่น /cve_ask ช่องโหว่ critical ของ Apache ที่เพิ่งประกาศ"
        adapter = getattr(self.summarizer, "adapter", None)
        result = await self.search.search_nl(query_text, adapter=adapter, page_size=page_size)
        q = result.query
        applied = []
        if q.severity:
            applied.append(f"severity={q.severity}")
        if q.min_cvss is not None:
            applied.append(f"cvss≥{q.min_cvss}")
        if q.vendor:
            applied.append(f"vendor={q.vendor}")
        if q.product:
            applied.append(f"product={q.product}")
        if q.cwe:
            applied.append(f"{q.cwe}")
        if q.kev_only:
            applied.append("KEV")
        if q.text:
            applied.append(f"'{q.text}'")
        header = "🔎 ตัวกรองที่ตีความได้: " + (", ".join(applied) if applied else "ล่าสุด")
        return pagination.render_page(result, header=esc(header))

    def cmd_history(self, cve_id: str) -> str:
        """Show a CVE's timeline (rule §38) plus its recorded change/events
        (rule §40) from the event log."""
        rec = self.search.get_one(cve_id)
        if rec is None:
            return f"{EMOJI['unknown']} ไม่พบข้อมูล {esc(cve_id)}"
        lines = [f"{EMOJI['timeline']} <b>ประวัติ {esc(rec.cve_id)}</b>", ""]
        tl = timeline_engine.render_thai(rec, limit=10)
        if tl:
            lines.append("<b>ไทม์ไลน์:</b>")
            for t in tl:
                lines.append(f"   {esc(t)}")
        events = [e for e in self.repo.recent_events(limit=50)
                  if e.get("cve_id") == rec.cve_id]
        if events:
            lines.append("")
            lines.append("<b>เหตุการณ์ที่บันทึก:</b>")
            for e in events[:10]:
                when = thai_date(e.get("created_at"), short=True)
                lines.append(f"   {esc(when)} — {esc(e.get('event_type', ''))}")
        if len(lines) <= 2:
            lines.append("ยังไม่มีประวัติเพิ่มเติม")
        return "\n".join(lines)

    def cmd_recent(self, limit: int = 10) -> str:
        recs = self.search.recent(limit=limit)
        if not recs:
            return "ยังไม่มี CVE ในฐานข้อมูล"
        lines = [f"{EMOJI['new']} <b>CVE ล่าสุด {len(recs)} รายการ</b>", ""]
        for i, r in enumerate(recs, 1):
            lines.append(f"{i}. {format_compact(r)}")
        return "\n".join(lines)

    def cmd_latest(self) -> str:
        recs = self.search.recent(limit=1)
        if not recs:
            return "ยังไม่มี CVE ในฐานข้อมูล"
        return self.render_detail(recs[0])

    def cmd_digest(self, *, window_days: int = 1) -> str:
        from ..alerts.digest import DigestBuilder
        return DigestBuilder(self.repo).build_default(window_days=max(1, window_days))

    def cmd_affected(self, args: List[str]) -> str:
        """`/cve_affected <product> <version> [vendor]` — which tracked CVEs
        affect a concrete product version (rule §18)."""
        if len(args) < 2:
            return ("ใช้: /cve_affected &lt;product&gt; &lt;version&gt; [vendor]\n"
                    "เช่น /cve_affected 'http server' 2.4.50 apache")
        product = args[0]
        version = args[1]
        vendor = args[2] if len(args) > 2 else ""
        from ..intelligence.correlation import CorrelationEngine
        recs = CorrelationEngine(self.repo).affected_by(product, version, vendor=vendor)
        if not recs:
            return (f"ไม่พบ CVE ที่ยืนยันว่ากระทบ {esc(product)} {esc(version)} "
                    f"ในฐานข้อมูล (อาจยังไม่มีข้อมูล หรือช่วงเวอร์ชันระบุไม่ได้)")
        lines = [f"{EMOJI['product']} <b>CVE ที่กระทบ {esc(product)} {esc(version)} "
                 f"({len(recs)} รายการ)</b>", ""]
        for i, r in enumerate(recs, 1):
            lines.append(f"{i}. {format_compact(r)}")
        return "\n".join(lines)

    def cmd_kev(self, limit: int = 10) -> str:
        recs = self.repo.kev_records(limit=limit)
        if not recs:
            return "ยังไม่มี CVE ที่อยู่ใน CISA KEV ในฐานข้อมูล"
        lines = [f"{EMOJI['kev']} <b>CISA KEV ล่าสุด {len(recs)} รายการ</b>", ""]
        for i, r in enumerate(recs, 1):
            lines.append(f"{i}. {format_compact(r)}")
        return "\n".join(lines)

    # ---------------- stats / status / sources ----------------

    def cmd_stats(self, *, window_days: int = 7) -> str:
        s = self.repo.stats(since_epoch=now_epoch() - window_days * 86400)
        notif = self.repo.notification_stats(since_epoch=now_epoch() - window_days * 86400)
        lines = [f"📊 <b>สถิติ CVE</b>", ""]
        lines.append(f"ทั้งหมดในฐานข้อมูล: {s.get('total', 0)}")
        lines.append(f"ในรอบ {window_days} วัน: {s.get('since', 0)} "
                     f"(CRITICAL {s.get('critical_since', 0)})")
        lines.append(f"อยู่ใน CISA KEV: {s.get('kev', 0)}")
        by_sev = s.get("by_severity", {})
        if by_sev:
            sev_line = " ".join(
                f"{SEVERITY_EMOJI.get(k, '')}{k}:{v}"
                for k, v in sorted(by_sev.items(),
                                   key=lambda kv: -_sev_rank(kv[0])))
            lines.append(f"ตามระดับ: {sev_line}")
        if s.get("top_vendors"):
            tv = ", ".join(f"{esc(v['vendor'])}({v['count']})" for v in s["top_vendors"][:5])
            lines.append(f"ผู้ผลิตที่พบบ่อย: {tv}")
        if s.get("top_cwes"):
            tc = ", ".join(f"{esc(c['cwe'])}({c['count']})" for c in s["top_cwes"][:5])
            lines.append(f"CWE ที่พบบ่อย: {tc}")
        if notif:
            lines.append("")
            lines.append("การแจ้งเตือน: " + ", ".join(f"{k}={v}" for k, v in notif.items()))
        return "\n".join(lines)

    def cmd_report(self, *, window_days: int = 7) -> str:
        from ..monitoring.reporting import ReportBuilder
        rb = ReportBuilder(self.repo)
        return rb.render_thai(rb.build(window_days=window_days))

    def cmd_sources(self) -> str:
        states = self.repo.all_source_states()
        enabled = {s.name for s in self.config.enabled_sources()}
        lines = [f"🛰️ <b>แหล่งข้อมูล CVE</b>", ""]
        known = enabled | {s.source for s in states}
        for name in sorted(known):
            st = next((s for s in states if s.source == name), None)
            on = name in enabled
            if st is None:
                lines.append(f"{EMOJI['disabled'] if not on else '⚪'} {esc(name)} — "
                             f"{'พร้อม (ยังไม่ซิงค์)' if on else 'ปิดใช้งาน'}")
                continue
            emoji = {"healthy": EMOJI["healthy"], "degraded": EMOJI["degraded"],
                     "failing": EMOJI["failing"], "disabled": EMOJI["disabled"]}.get(
                         st.health, EMOJI["unknown"])
            last = humanize_ago(st.last_success_at) if st.last_success_at else "ยังไม่เคย"
            detail = f"ซิงค์ล่าสุด {last} | ใหม่ {st.records_new}"
            if st.last_error and st.health != "healthy":
                detail += f" | ข้อผิดพลาด: {esc(st.last_error[:60])}"
            lines.append(f"{emoji} <b>{esc(name)}</b> — {detail}")
        return "\n".join(lines)

    def cmd_status(self) -> str:
        enabled = self.config.enabled_sources()
        tracker_on = "เปิด" if self.config.enabled else "ปิด"
        ai_on = "เปิด" if self.config.ai.enabled else "ปิด"
        alerts_on = "เปิด" if self.config.alerts.enabled else "ปิด"
        lines = [f"🩺 <b>สถานะ CVE Tracker</b>", ""]
        lines.append(f"ตัวติดตาม: {tracker_on} | AI: {ai_on} | แจ้งเตือน: {alerts_on}")
        lines.append(f"รอบ polling: {self.config.poll_interval}s")
        lines.append(f"แหล่งที่เปิด: {', '.join(s.name for s in enabled) or '—'}")
        lines.append(f"CVE ในฐานข้อมูล: {self.repo.count()}")
        lines.append(f"ผู้รับการแจ้งเตือน: {len(self.repo.list_subscriptions())} ห้อง")
        if self.runtime is not None:
            try:
                h = self.runtime.health()
                lines.append("")
                lines.append(f"รอบล่าสุด: {h.get('last_run_summary', '—')}")
            except Exception:
                pass
        lines.append("")
        lines.append(self.cmd_sources())
        return "\n".join(lines)

    # ---------------- subscriptions ----------------

    def cmd_subscribe(self, chat_id: int, topic_id: int, args: List[str]) -> str:
        sub, notes = self.subs.subscribe(chat_id, topic_id, args)
        self.repo.audit("subscription_changed", cve_id="", metadata={
            "chat_id": chat_id, "notes": notes})
        return (f"✅ ตั้งค่าการแจ้งเตือน CVE แล้ว\n{esc(notes)}\n\n"
                f"ตัวกรองปัจจุบัน: {esc(self.subs.describe(sub))}")

    def cmd_unsubscribe(self, chat_id: int, topic_id: int = 0) -> str:
        self.subs.unsubscribe(chat_id, topic_id)
        self.repo.audit("subscription_changed", metadata={"chat_id": chat_id, "action": "off"})
        return "🔕 ปิดการแจ้งเตือน CVE สำหรับห้องนี้แล้ว"

    def cmd_preferences(self, chat_id: int, topic_id: int = 0) -> str:
        sub = self.repo.get_subscription(chat_id, topic_id)
        if sub is None:
            return ("ห้องนี้ยังไม่ได้ตั้งค่าการแจ้งเตือน CVE\n"
                    "ใช้ /cve_subscribe เพื่อเริ่ม เช่น /cve_subscribe critical หรือ "
                    "/cve_subscribe kev หรือ /cve_subscribe vendor microsoft")
        return f"⚙️ <b>การตั้งค่าการแจ้งเตือน CVE</b>\n{esc(self.subs.describe(sub))}"

    # ---------------- admin ----------------

    async def cmd_sync(self, *, source: str = "") -> str:
        if self.runtime is None:
            return "ยังไม่ได้เชื่อมต่อ engine — ไม่สามารถซิงค์ด้วยตนเองได้"
        try:
            result = await self.runtime.sync_now(source=source or None)
            return (f"🔄 ซิงค์เสร็จ: เห็น {result.get('seen', 0)} | ใหม่ {result.get('new', 0)} "
                    f"| อัปเดต {result.get('updated', 0)} | ล้มเหลว {result.get('failed', 0)}")
        except Exception as exc:
            logger.exception("manual sync failed")
            return f"ซิงค์ล้มเหลว: {esc(str(exc)[:200])}"

    async def cmd_test(self) -> str:
        """Render a sample alert from the most recent CVE, or a synthetic one, to
        verify formatting end-to-end without sending to subscribers."""
        recs = self.search.recent(limit=1)
        if recs:
            rec = recs[0]
        else:
            rec = _sample_record()
        ai = None
        if self.summarizer is not None:
            try:
                ai = await self.summarizer.summarize(rec)
            except Exception:
                ai = None
        chunks = format_new_cve(rec, ai)
        return chunks[0]

    # ---------------- detail renderer ----------------

    def render_detail(self, rec: CVERecord) -> str:
        lines: List[str] = []
        emoji = SEVERITY_EMOJI.get(rec.severity, EMOJI["unknown"])
        lines.append(f"{emoji} <b>{esc(rec.cve_id)}</b>")
        if rec.title:
            lines.append(f"<b>{esc(rec.title)}</b>")
        lines.append("")
        lines.append(templates.published_line(rec))
        lines.append(templates.severity_line(rec))
        conflict = templates.cvss_conflict_line(rec)
        if conflict:
            lines.append(conflict)
        if rec.cwe_ids:
            lines.append(f"{EMOJI['cwe']} <b>CWE:</b> " +
                         ", ".join(esc(format_cwe_label(c)) for c in rec.cwe_ids[:4]))
        if rec.products:
            labels = "; ".join(esc(format_product_label(p)) for p in top_products(rec.products, 5))
            lines.append(f"{EMOJI['product']} <b>ผลิตภัณฑ์:</b> {labels}")
        lines.append(templates.kev_line(rec))
        lines.append(templates.exploit_line(rec))
        epss = templates.epss_line(rec)
        if epss:
            lines.append(epss)
        # internal priority breakdown
        bd = compute_breakdown(rec)
        lines.append(f"{EMOJI['priority']} <b>ลำดับภายใน:</b> {esc(rec.priority)} "
                     f"({bd.total}/100) — ไม่ใช่ CVSS ทางการ")
        if bd.reasons:
            lines.append("   " + "; ".join(esc(r) for r in bd.reasons[:4]))
        # description
        if rec.description:
            from ..utils import truncate
            lines.append("")
            lines.append(f"{EMOJI['summary']} {esc(truncate(rec.description, 600))}")
        # timeline
        tl = timeline_engine.render_thai(rec, limit=5)
        if tl:
            lines.append("")
            lines.append(f"{EMOJI['timeline']} <b>ไทม์ไลน์:</b>")
            for t in tl:
                lines.append(f"   {esc(t)}")
        # references
        if rec.references:
            lines.append("")
            lines.append(f"{EMOJI['references']} <b>References ({len(rec.references)}):</b>")
            for ref in rec.references[:5]:
                lines.append(f"   • [{esc(ref.ref_type.replace('_',' '))}] {esc(ref.url)}")
        lines.append("")
        lines.append(f"แหล่งข้อมูล: {esc(', '.join(rec.source_names))}")
        lines.append(f"{EMOJI['references']} {esc(rec.primary_url)}")
        return "\n".join(lines)

    # ---------------- help ----------------

    def cmd_help(self) -> str:
        return (
            f"{EMOJI['new']} <b>CVE Intelligence & Tracking</b>\n\n"
            "<b>ค้นหา/ดูข้อมูล</b>\n"
            "/cve &lt;CVE-ID&gt; — ดูรายละเอียด CVE\n"
            "/cve_info &lt;CVE-ID&gt; — รายละเอียดแบบเต็ม\n"
            "/cve_history &lt;CVE-ID&gt; — ไทม์ไลน์และประวัติการเปลี่ยนแปลง\n"
            "/cve_search &lt;คำค้น&gt; — ค้นหา (เช่น apache, severity:critical, vendor:cisco, cwe:CWE-79)\n"
            "/cve_ask &lt;คำถาม&gt; — ถามเป็นภาษาธรรมชาติ เช่น 'ช่องโหว่ critical ของ Apache ที่เพิ่งประกาศ'\n"
            "/cve_recent — CVE ล่าสุด\n"
            "/cve_latest — CVE ล่าสุด 1 รายการแบบเต็ม\n"
            "/cve_kev — CVE ที่อยู่ใน CISA KEV\n"
            "/cve_affected &lt;product&gt; &lt;version&gt; [vendor] — CVE ที่กระทบเวอร์ชันนั้น\n"
            "/cve_digest [week] — สรุป CVE ประจำวัน/สัปดาห์\n"
            "/cve_stats — สถิติ\n\n"
            "<b>การแจ้งเตือน (ต่อห้อง)</b>\n"
            "/cve_subscribe [critical|high|kev|cvss N|vendor X|product Y|cwe CWE-N|keyword K]\n"
            "/cve_unsubscribe — ปิดการแจ้งเตือน\n"
            "/cve_preferences — ดูการตั้งค่าปัจจุบัน\n\n"
            "<b>ผู้ดูแล</b>\n"
            "/cve_status — สถานะระบบ\n"
            "/cve_sources — สถานะแหล่งข้อมูล\n"
            "/cve_sync — ซิงค์ด้วยตนเอง\n"
            "/cve_test — ทดสอบรูปแบบการแจ้งเตือน"
        )


def _sev_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)


def _sample_record() -> CVERecord:
    """A synthetic record for /cve_test when the DB is empty."""
    from ..enrichment import cvss, enrich
    from ..enrichment.cwe import make_weakness
    from ..models import AffectedProduct, KEVInfo, SourceRecord
    rec = CVERecord(
        cve_id="CVE-2026-00000",
        title="ตัวอย่าง: Buffer Overflow (สำหรับทดสอบรูปแบบ)",
        description="รายการทดสอบระบบ ไม่ใช่ช่องโหว่จริง",
        published_at=now_epoch())
    rec.cvss_scores = [cvss.parse_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source="nvd")]
    rec.weaknesses = [make_weakness("CWE-120")]
    rec.products = [AffectedProduct(vendor="ExampleVendor", product="ExampleProduct")]
    rec.sources = [SourceRecord(source="nvd")]
    enrich(rec)
    return rec
