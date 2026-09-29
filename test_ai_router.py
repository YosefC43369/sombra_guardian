"""
test_ai_router.py — tests for the multi-provider AI router.

No network: provider calls are faked by monkeypatching ai_router._call_one, and
provider construction is exercised via environment variables.
(python -m unittest test_ai_router)
"""

import os
import asyncio
import unittest

import ai_router
from ai_router import Provider, LIGHT, HEAVY


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class ClassifyTest(unittest.TestCase):
    def test_light_vs_heavy(self):
        self.assertEqual(ai_router.classify_task("hi there"), LIGHT)
        self.assertEqual(ai_router.classify_task("เขียนโค้ด python อ่านไฟล์"), HEAVY)
        self.assertEqual(ai_router.classify_task("x" * 1000), HEAVY)
        self.assertEqual(ai_router.classify_task("anything", force=HEAVY), HEAVY)


class BuildProvidersTest(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("GROQ_API_KEY", "GPT_API_KEY", "GEMINI_API_KEY",
                        "MISTRAL_API_KEY", "CEREBRAS_API_KEY", "OPENROUTER_API_KEY",
                        "OPENAI_API_KEY")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_only_configured_providers(self):
        os.environ["GROQ_API_KEY"] = "x"
        os.environ["GEMINI_API_KEY"] = "y"
        provs = ai_router.build_providers()
        names = {p.name for p in provs}
        self.assertEqual(names, {"groq", "gemini"})
        tiers = {p.name: p.tier for p in provs}
        self.assertEqual(tiers["groq"], "fast")
        self.assertEqual(tiers["gemini"], "big")

    def test_ordering_by_task(self):
        fast = Provider("groq", "k", "m", "fast")
        big = Provider("gpt", "k", "m", "big")
        light_order = ai_router._ordered_for_task([big, fast], LIGHT)
        self.assertEqual(light_order[0].name, "groq")
        heavy_order = ai_router._ordered_for_task([fast, big], HEAVY)
        self.assertEqual(heavy_order[0].name, "gpt")


class RouteFallbackTest(unittest.TestCase):
    def test_fallback_to_second_provider(self):
        fast = Provider("groq", "k", "mf", "fast")
        big = Provider("gpt", "k", "mb", "big")

        calls = []

        async def fake_call(provider, messages, task, *, temperature):
            calls.append(provider.name)
            if provider.name == "groq":
                return False, "timeout", "retryable"
            return True, "hello from gpt", "ok"

        orig = ai_router._call_one
        ai_router._call_one = fake_call
        try:
            res = run(ai_router.route("hi", providers=[fast, big], task=LIGHT))
        finally:
            ai_router._call_one = orig

        self.assertTrue(res.ok)
        self.assertEqual(res.provider, "gpt")
        self.assertEqual(res.attempts, 2)
        self.assertEqual(calls, ["groq", "gpt"])

    def test_all_fail(self):
        p = Provider("groq", "k", "m", "fast")

        async def fake_call(provider, messages, task, *, temperature):
            return False, "boom", "fatal"

        orig = ai_router._call_one
        ai_router._call_one = fake_call
        try:
            res = run(ai_router.route("hi", providers=[p]))
        finally:
            ai_router._call_one = orig
        self.assertFalse(res.ok)
        self.assertIn("groq", res.reason)

    def test_no_provider(self):
        res = run(ai_router.route("hi", providers=[]))
        self.assertFalse(res.ok)
        self.assertEqual(res.reason, "no provider configured")


if __name__ == "__main__":
    unittest.main()
