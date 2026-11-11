# -*- coding: utf-8 -*-
"""เทสต์ evidence_management — ingestion, id, metadata validation, SHA-256, hash verify,
tamper detection, chain of custody, audit-chain verify, finding↔evidence mapping, multi-ref,
redaction, file-type/size/path-traversal, missing-artifact, historical retrieval, orchestrator
+ correlation integration, AI fallback, report, telegram permissions, unauthorized access.

รันด้วย: python -m unittest test_evidence_management  หรือ pytest (local fixtures, ไม่ต่อเน็ต)
"""

import asyncio
import os
import tempfile
import unittest

from evidence_management import (schema, redact, integrity, store, ingest, service,
                                 timeline, report)


def _sub(**kw):
    base = {"assessment_id": "RT-2026-000001", "source_module": "web_vulnerability_assessment",
            "evidence_type": "http_response", "title": "resp", "description": "d",
            "verification_status": "observed", "confidence": 0.6}
    base.update(kw)
    return base


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "evd.json")


# ---------------------------------------------------------------------------
# 1/2/3. ingestion, id generation, metadata validation
# ---------------------------------------------------------------------------
class IngestionTests(_Tmp):
    def test_ingest_returns_id(self):
        rec = service.submit(_sub(finding_ids=["FND-1"]), content="body", actor="t", path=self.path)
        self.assertTrue(rec["evidence_id"].startswith("EVD-"))
        self.assertEqual(rec["assessment_id"], "RT-2026-000001")
        self.assertEqual(rec["finding_ids"], ["FND-1"])

    def test_id_sequential(self):
        a = service.submit(_sub(), path=self.path)
        b = service.submit(_sub(), path=self.path)
        self.assertNotEqual(a["evidence_id"], b["evidence_id"])

    def test_validation_rejects_bad(self):
        self.assertEqual(service.submit({}, path=self.path)["reason"], "INVALID_ASSESSMENT_ID")
        self.assertEqual(service.submit(_sub(evidence_type="nope"), path=self.path)["reason"],
                         "INVALID_EVIDENCE_TYPE:nope")
        self.assertEqual(service.submit(_sub(confidence=5), path=self.path)["reason"],
                         "CONFIDENCE_OUT_OF_RANGE")
        self.assertEqual(service.submit(_sub(source_module=""), path=self.path)["reason"],
                         "MISSING_SOURCE_MODULE")

    def test_single_and_multi_refs_normalized(self):
        rec = service.submit(_sub(finding_id="FND-9", finding_ids=["FND-1", "FND-1"]),
                             path=self.path)
        self.assertEqual(sorted(rec["finding_ids"]), ["FND-1", "FND-9"])


# ---------------------------------------------------------------------------
# 4/5/6. SHA-256, hash verification, tamper detection
# ---------------------------------------------------------------------------
class HashTests(_Tmp):
    def test_sha256_computed(self):
        h, size = integrity.hash_content("hello")
        self.assertEqual(h, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(size, 5)

    def test_no_artifact_hash_none(self):
        rec = service.submit(_sub(), content=None, path=self.path)
        self.assertIsNone(rec["content_hash"])
        self.assertEqual(rec["integrity_status"], "no_artifact")

    def test_hash_match_and_tamper(self):
        rec = service.submit(_sub(evidence_type="json_record"), content="X", path=self.path)
        ok = service.verify(rec["evidence_id"], content="X", path=self.path)
        self.assertEqual(ok["verification_result"], "passed")
        self.assertTrue(ok["hash_match"])
        bad = service.verify(rec["evidence_id"], content="Y", path=self.path)
        self.assertEqual(bad["verification_result"], "failed")
        self.assertFalse(bad["hash_match"])
        # tamper marks compromised + preserves history
        after = store.get_record(rec["evidence_id"], self.path)
        self.assertEqual(after["integrity_status"], "compromised")
        self.assertEqual(len(after["integrity_history"]), 1)

    def test_verify_does_not_modify_content(self):
        rec = service.submit(_sub(evidence_type="json_record"), content="X", path=self.path)
        before = store.get_record(rec["evidence_id"], self.path)["content_hash"]
        service.verify(rec["evidence_id"], content="X", path=self.path)
        after = store.get_record(rec["evidence_id"], self.path)["content_hash"]
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------
# 7/8. chain of custody + audit-chain verification
# ---------------------------------------------------------------------------
class CustodyTests(_Tmp):
    def test_initial_custody_events(self):
        rec = service.submit(_sub(), path=self.path)
        kinds = [c["event_type"] for c in rec["custody"]]
        self.assertEqual(kinds, ["evidence_created", "evidence_collected",
                                 "evidence_validated", "evidence_stored"])

    def test_custody_chain_links(self):
        rec = service.submit(_sub(), path=self.path)
        chain = integrity.verify_custody_chain(rec["custody"])
        self.assertTrue(chain["ok"])
        self.assertIsNotNone(chain["merkle_root"])

    def test_custody_tamper_detected(self):
        rec = service.submit(_sub(), path=self.path)
        rec["custody"][1]["action"] = "TAMPERED"       # แก้เหตุการณ์กลางสาย
        chain = integrity.verify_custody_chain(rec["custody"])
        self.assertFalse(chain["ok"])
        self.assertEqual(chain["broken_at"], 1)

    def test_access_and_export_recorded(self):
        rec = service.submit(_sub(), path=self.path)
        service.access(rec["evidence_id"], "user:1", export=False, path=self.path)
        service.access(rec["evidence_id"], "user:1", export=True, path=self.path)
        after = store.get_record(rec["evidence_id"], self.path)
        kinds = [c["event_type"] for c in after["custody"]]
        self.assertIn("evidence_accessed", kinds)
        self.assertIn("evidence_exported", kinds)


# ---------------------------------------------------------------------------
# 9/10. finding↔evidence mapping + multiple references
# ---------------------------------------------------------------------------
class MappingTests(_Tmp):
    def test_evidence_for_finding_roles(self):
        service.submit(_sub(evidence_type="vulnerability_result", finding_ids=["FND-1"]),
                       path=self.path)
        service.submit(_sub(evidence_type="http_response", finding_ids=["FND-1"],
                            verification_status="verified"), path=self.path)
        m = service.evidence_for_finding("FND-1", path=self.path)
        self.assertEqual(m["evidence_count"], 2)
        self.assertTrue(m["roles"]["primary"])
        self.assertTrue(m["roles"]["verification"])

    def test_one_evidence_many_findings(self):
        rec = service.submit(_sub(finding_ids=["FND-1", "FND-2"]), path=self.path)
        self.assertIn("FND-1", rec["finding_ids"])
        self.assertEqual(len(service.evidence_for_finding("FND-1", path=self.path)["roles"]
                             ["supporting"])
                         + len(service.evidence_for_finding("FND-1", path=self.path)["roles"]
                               ["primary"]), 1)
        self.assertEqual(service.evidence_for_finding("FND-2", path=self.path)["evidence_count"], 1)

    def test_evidence_does_not_auto_confirm(self):
        service.submit(_sub(verification_status="observed", finding_ids=["FND-3"]), path=self.path)
        m = service.evidence_for_finding("FND-3", path=self.path)
        self.assertIn("ไม่ได้ยืนยัน", m["note"])


# ---------------------------------------------------------------------------
# 11. redaction
# ---------------------------------------------------------------------------
class RedactionTests(_Tmp):
    def test_sensitive_redacted(self):
        rec = service.submit(_sub(description="Authorization: Bearer abc123def456ghi789"),
                             content="cookie: session=secretvalue", path=self.path)
        self.assertNotIn("abc123def456ghi789", rec["description"])
        self.assertTrue(rec["redaction_applied"])
        self.assertTrue(rec["redaction_notes"])

    def test_clean_content_not_flagged(self):
        rec = service.submit(_sub(description="just a normal observation"), path=self.path)
        self.assertFalse(rec["redaction_applied"])

    def test_metadata_redacted(self):
        rec = service.submit(_sub(metadata={"note": "token=supersecretvalue123"}), path=self.path)
        self.assertNotIn("supersecretvalue123", str(rec["metadata"]))


# ---------------------------------------------------------------------------
# 12/13/14/15. file validation, size, path traversal, missing artifact
# ---------------------------------------------------------------------------
class FileSafetyTests(_Tmp):
    def setUp(self):
        super().setUp()
        self.base = tempfile.mkdtemp()
        self.good = os.path.join(self.base, "e.json")
        with open(self.good, "w") as f:
            f.write("{}")

    def test_allowed_file(self):
        ok, resolved = ingest.validate_artifact_path("e.json", self.base, 1024 * 1024)
        self.assertTrue(ok)

    def test_disallowed_type(self):
        p = os.path.join(self.base, "x.exe")
        open(p, "w").close()
        ok, reason = ingest.validate_artifact_path("x.exe", self.base, 1024 * 1024)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("DISALLOWED_FILE_TYPE"))

    def test_path_traversal_blocked(self):
        ok, reason = ingest.validate_artifact_path("../../etc/passwd", self.base, 1024 * 1024)
        self.assertFalse(ok)
        self.assertIn(reason, ("PATH_TRAVERSAL", "DISALLOWED_FILE_TYPE:(none)",
                               "ARTIFACT_NOT_FOUND"))

    def test_size_limit(self):
        big = os.path.join(self.base, "big.json")
        with open(big, "w") as f:
            f.write("x" * 2000)
        ok, reason = ingest.validate_artifact_path("big.json", self.base, 1000)
        self.assertFalse(ok)
        self.assertEqual(reason, "FILE_TOO_LARGE")

    def test_missing_artifact(self):
        ok, reason = ingest.validate_artifact_path("nope.json", self.base, 1024 * 1024)
        self.assertFalse(ok)
        self.assertEqual(reason, "ARTIFACT_NOT_FOUND")

    def test_verify_detects_missing_artifact(self):
        rec = service.submit(_sub(evidence_type="json_record",
                                  storage_reference="gone.json"), content="x", path=self.path)
        res = service.verify(rec["evidence_id"], base_dir=self.base, path=self.path)
        self.assertIn("ARTIFACT_MISSING", res["issues"])


# ---------------------------------------------------------------------------
# 16. historical / search retrieval
# ---------------------------------------------------------------------------
class RetrievalTests(_Tmp):
    def _seed(self):
        service.submit(_sub(evidence_type="dns_observation", source_module="passive_recon",
                            asset_ids=["example.com"]), path=self.path)
        service.submit(_sub(evidence_type="vulnerability_result", finding_ids=["FND-1"]),
                       path=self.path)

    def test_search_filters(self):
        self._seed()
        self.assertEqual(len(store.search(source_module="passive_recon", path=self.path)), 1)
        self.assertEqual(len(store.search(evidence_type="vulnerability_result", path=self.path)), 1)
        self.assertEqual(len(store.by_assessment("RT-2026-000001", path=self.path)), 2)
        self.assertEqual(len(store.by_finding("FND-1", path=self.path)), 1)

    def test_text_search(self):
        service.submit(_sub(description="unique-marker-xyz"), path=self.path)
        self.assertEqual(len(store.search(text="unique-marker-xyz", path=self.path)), 1)
        self.assertEqual(len(store.search(text="nomatch", path=self.path)), 0)


# ---------------------------------------------------------------------------
# 17/18. orchestrator + correlation engine integration
# ---------------------------------------------------------------------------
class IntegrationTests(_Tmp):
    def _task(self):
        return {"task_id": "RT-2026-000042", "target": "https://api.example.com",
                "plan": {"scope_authorized": True, "program_id": 7, "active_modules": ["wva"]},
                "started_iso": "2026-11-01T00:00:00+00:00",
                "finished_iso": "2026-11-01T00:10:00+00:00",
                "module_results": [{"module": "passive_recon", "status": "completed",
                                    "findings": [], "errors": [], "completed_at": "t"}],
                "findings": [{"finding_id": "FND-1", "category": "xss", "title": "reflection",
                              "severity": "HIGH", "affected_asset": "api.example.com",
                              "confidence": 0.6, "verification_status": "POTENTIAL",
                              "evidence_refs": ["<x>"], "detection_source": "wva"}]}

    def test_ingest_task(self):
        res = service.ingest_task(self._task(), path=self.path)
        self.assertGreaterEqual(res["count"], 2)   # operational + finding evidence
        recs = store.by_assessment("RT-2026-000042", path=self.path)
        types = {r["evidence_type"] for r in recs}
        self.assertIn("vulnerability_result", types)
        self.assertIn("authorization_decision", types)
        self.assertIn("module_status", types)

    def test_ingest_with_correlation(self):
        corr = {"result_id": "ASC-2026-000001", "generated_iso": "t",
                "counts": {"total_relationships": 1},
                "correlations": [{"correlation_id": "CORR-1", "relationship": "contains",
                                  "source": "ASSET-1", "target": "ASSET-2", "ownership": "confirmed",
                                  "hypothesis": False, "confidence": 1.0, "explanation": "x",
                                  "evidence": ["e"], "detected_iso": "t"}]}
        res = service.ingest_task(self._task(), correlation=corr, path=self.path)
        recs = store.search(evidence_type="correlation_reference", path=self.path)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["source_module"], "attack_surface_correlation")

    def test_hypothesis_correlation_marked_suspected(self):
        corr = {"result_id": "ASC-1", "correlations": [
            {"correlation_id": "CORR-2", "relationship": "shared_infrastructure",
             "source": "ASSET-1", "target": "ASSET-2", "ownership": "observed_shared_infra",
             "hypothesis": True, "confidence": 0.75, "explanation": "shared ip",
             "evidence": [], "detected_iso": "t"}]}
        subs = ingest.from_correlation_result(corr, "RT-1")
        self.assertEqual(subs[0]["verification_status"], "suspected")

    def test_timeline(self):
        service.ingest_task(self._task(), path=self.path)
        tl = service.get_timeline("RT-2026-000042", task=self._task(), path=self.path)
        kinds = {e["kind"] for e in tl["events"]}
        self.assertIn("assessment_started", kinds)
        self.assertIn("evidence_collected", kinds)
        self.assertIn("assessment_completed", kinds)
        self.assertIn("timestamp_inferred", tl["events"][0])


# ---------------------------------------------------------------------------
# 19. AI analysis fallback
# ---------------------------------------------------------------------------
class AiFallbackTests(_Tmp):
    def test_ai_fallback_without_key(self):
        service.submit(_sub(finding_ids=["FND-1"]), path=self.path)
        summary = asyncio.run(service.ai_explain_evidence("FND-1", path=self.path))
        # ไม่มี key -> None; storage/verify ยังทำงานได้ (ทดสอบไปแล้วด้านบน)
        self.assertIsNone(summary)

    def test_ai_no_evidence_returns_none(self):
        self.assertIsNone(asyncio.run(service.ai_explain_evidence("FND-none", path=self.path)))


# ---------------------------------------------------------------------------
# 20. report generation
# ---------------------------------------------------------------------------
class ReportTests(_Tmp):
    def test_executive_and_appendix(self):
        service.submit(_sub(evidence_type="vulnerability_result", finding_ids=["FND-1"],
                            description="Authorization: Bearer secrettoken123456"),
                       content="x", path=self.path)
        recs = store.by_assessment("RT-2026-000001", path=self.path)
        findings = [{"finding_id": "FND-1", "title": "XSS", "severity": "HIGH",
                     "affected_asset": "api.example.com", "description": "r",
                     "remediation": "encode"}]
        exe = report.executive_summary(recs, assessment_id="RT-2026-000001", findings=findings)
        app = report.technical_appendix(recs, assessment_id="RT-2026-000001")
        self.assertIn("Executive", exe)
        self.assertIn("XSS", exe)
        self.assertIn("EVD-", app)
        self.assertIn("SHA-256", app)
        self.assertNotIn("secrettoken123456", app)      # redaction holds in report
        self.assertIn("chain of custody", app)

    def test_verification_report(self):
        rec = service.submit(_sub(evidence_type="json_record"), content="x", path=self.path)
        res = service.verify(rec["evidence_id"], content="x", path=self.path)
        md = report.verification_report([res], assessment_id="RT-2026-000001")
        self.assertIn("passed", md)


# ---------------------------------------------------------------------------
# 21/22. telegram permissions + unauthorized access
# ---------------------------------------------------------------------------
class AccessControlTests(_Tmp):
    def test_access_records_custody_and_returns_record(self):
        rec = service.submit(_sub(), path=self.path)
        got = service.access(rec["evidence_id"], "user:5", path=self.path)
        self.assertEqual(got["evidence_id"], rec["evidence_id"])

    def test_access_unknown_evidence(self):
        self.assertEqual(service.access("EVD-nope", "user:1", path=self.path)["error"],
                         "EVIDENCE_NOT_FOUND")

    def test_commands_group_requires_admin(self):
        # จำลอง permission gate ของคำสั่ง (_allowed): กลุ่มต้อง is_admin, DM ผ่าน
        from evidence_management import commands

        class _Chat:
            def __init__(self, t): self.type = t

        class _U:
            def __init__(self, t): self.effective_chat = _Chat(t)

        async def _no(u, c): return False
        async def _yes(u, c): return True
        self.assertFalse(asyncio.run(commands._allowed(_U("group"), None, _no)))
        self.assertTrue(asyncio.run(commands._allowed(_U("group"), None, _yes)))
        self.assertTrue(asyncio.run(commands._allowed(_U("private"), None, _no)))

    def test_no_silent_delete_api(self):
        # ไม่มี API ลบ evidence ใน store (append-only) — กันลบโดยไม่ได้รับอนุญาต
        self.assertFalse(hasattr(store, "delete_record"))
        self.assertFalse(hasattr(store, "remove_record"))


# ---------------------------------------------------------------------------
# policy / disabled
# ---------------------------------------------------------------------------
class PolicyTests(_Tmp):
    def test_disabled_blocks_ingest(self):
        store.set_policy("enabled", False, self.path)
        self.assertEqual(service.submit(_sub(), path=self.path)["error"], "EVIDENCE_DISABLED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
