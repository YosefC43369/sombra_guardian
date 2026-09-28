import unittest

from web_footprint import WebFootprintEngine, ReconContext, ScopeSpec, ReconMode
from ._fakes import run_async, cert_collector, page_collector


def _ctx():
    return ReconContext(scope=ScopeSpec(include=["*.example.com", "example.com"]),
                        dev_unsafe_allow_all=True, actor="tester")


class TestEngine(unittest.TestCase):
    def test_recon_sync(self):
        engine = WebFootprintEngine([cert_collector(), page_collector()])
        res = engine.recon_sync("example.com", _ctx(), mode=ReconMode.QUICK)
        self.assertTrue(res.gate.allowed)
        self.assertGreater(len(res.inventory), 0)

    def test_async_modes(self):
        engine = WebFootprintEngine([cert_collector(), page_collector()])
        for mode in (ReconMode.QUICK, ReconMode.STANDARD, ReconMode.DEEP):
            res = run_async(engine.recon("example.com", _ctx(), mode=mode))
            self.assertTrue(res.gate.allowed)
            self.assertEqual(res.config.mode, mode)

    def test_recon_sync_rejects_in_loop(self):
        engine = WebFootprintEngine([cert_collector()])

        async def _inner():
            with self.assertRaises(RuntimeError):
                engine.recon_sync("example.com", _ctx())
        run_async(_inner())

    def test_to_dict_serializable(self):
        import json
        engine = WebFootprintEngine([cert_collector(), page_collector()])
        res = run_async(engine.recon("example.com", _ctx(), mode=ReconMode.STANDARD))
        blob = json.dumps(res.to_dict(), default=str)
        self.assertIn("observed_surface", blob)
        self.assertIn("inventory", blob)


if __name__ == "__main__":
    unittest.main()
