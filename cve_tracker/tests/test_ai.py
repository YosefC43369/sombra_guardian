"""Tests for the AI pipeline — prompt facts, hallucination validation, fallback."""

import asyncio
import json
import unittest

from cve_tracker.config import get_config
from cve_tracker.ai import prompt_builder
from cve_tracker.ai.validator import validate
from cve_tracker.ai.summarizer import CVESummarizer
from cve_tracker.ai.adapter import AIResult
from cve_tracker.enums import AIProcessingState
from cve_tracker import fixtures


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class PromptTest(unittest.TestCase):
    def test_facts_only_verified(self):
        facts = prompt_builder.build_facts(fixtures.record(kev=True))
        self.assertEqual(facts["cve_id"], "CVE-2026-93740")
        self.assertTrue(facts["cisa_kev"])
        self.assertEqual(facts["cvss"][0]["score"], 9.8)

    def test_prompt_wraps_description(self):
        prompt = prompt_builder.build_prompt(fixtures.record())
        self.assertIn("<CVE_DESCRIPTION>", prompt)
        self.assertIn("STRUCTURED_FACTS", prompt)

    def test_input_signature_stable(self):
        r = fixtures.record()
        self.assertEqual(prompt_builder.input_signature(r),
                         prompt_builder.input_signature(r))


class ValidatorTest(unittest.TestCase):
    def setUp(self):
        self.r = fixtures.record()

    def test_good_output(self):
        out = json.dumps({"title_th": "x", "summary_th": "พบช่องโหว่ buffer overflow",
                          "impact_th": "อาจถูกโจมตี", "recommendation_th": ["ตรวจสอบ"]})
        rep = validate(self.r, out)
        self.assertTrue(rep.ok, rep.problems)

    def test_fabricated_cvss_rejected(self):
        out = json.dumps({"title_th": "x",
                          "summary_th": "ช่องโหว่นี้มี CVSS 5.5", "recommendation_th": []})
        rep = validate(self.r, out)
        self.assertFalse(rep.ok)
        self.assertTrue(any("fabricated-cvss" in p for p in rep.problems))

    def test_real_cvss_allowed(self):
        out = json.dumps({"title_th": "x",
                          "summary_th": "ช่องโหว่ระดับ CVSS 9.8", "recommendation_th": []})
        rep = validate(self.r, out)
        self.assertTrue(rep.ok, rep.problems)

    def test_stray_cve_id_repaired(self):
        out = json.dumps({"title_th": "x",
                          "summary_th": "ดู CVE-2025-11111", "recommendation_th": []})
        rep = validate(self.r, out)
        self.assertTrue(rep.repaired)
        self.assertIn("CVE-2026-93740", rep.data["summary_th"])

    def test_over_claim_kev_rejected(self):
        r = fixtures.record(kev=False)
        r.exploit_maturity = "none"
        out = json.dumps({"title_th": "x",
                          "summary_th": "ช่องโหว่นี้ถูกใช้โจมตีจริงแล้ว", "recommendation_th": []})
        rep = validate(r, out)
        self.assertFalse(rep.ok)

    def test_not_json(self):
        rep = validate(self.r, "this is not json at all")
        self.assertFalse(rep.ok)


class SummarizerTest(unittest.TestCase):
    def test_fallback_when_no_ai(self):
        cfg = get_config()
        summ = CVESummarizer(cfg.ai)  # real adapter, no keys → unavailable
        result = _run(summ.summarize(fixtures.record()))
        self.assertTrue(result.fallback_used)
        self.assertIn(result.state, (AIProcessingState.UNAVAILABLE.value,
                                     AIProcessingState.FALLBACK.value,
                                     AIProcessingState.SKIPPED.value))
        self.assertTrue(result.recommendation_th)  # deterministic recs present

    def test_validated_path_with_fake_adapter(self):
        cfg = get_config()

        class FakeAdapter:
            def available(self):
                return True
            async def generate(self, prompt, system="", task="heavy"):
                return AIResult(True, text=json.dumps({
                    "title_th": "สรุปทดสอบ", "summary_th": "พบช่องโหว่ buffer overflow",
                    "impact_th": "อาจถูกโจมตี", "recommendation_th": ["ตรวจสอบอุปกรณ์"]}),
                    provider="fake", model="m")

        summ = CVESummarizer(cfg.ai, adapter=FakeAdapter())
        result = _run(summ.summarize(fixtures.record()))
        self.assertTrue(result.validated)
        self.assertFalse(result.fallback_used)
        self.assertEqual(result.provider, "fake")
        self.assertEqual(result.state, AIProcessingState.DONE.value)


if __name__ == "__main__":
    unittest.main()
