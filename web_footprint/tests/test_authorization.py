import unittest

from web_footprint.authorization import (ReconContext, ReconGate, ScopeSpec,
                                          ScopeClassifier, GateReason)
from web_footprint.assets import Asset, AssetType, ScopeStatus


class TestScopeSpec(unittest.TestCase):
    def test_include_wildcard(self):
        s = ScopeSpec(include=["*.example.com"])
        self.assertEqual(s.classify_host("api.example.com"), ScopeStatus.IN_SCOPE)
        self.assertEqual(s.classify_host("example.com"), ScopeStatus.IN_SCOPE)
        self.assertEqual(s.classify_host("other.org"), ScopeStatus.UNKNOWN)

    def test_exclude_wins(self):
        s = ScopeSpec(include=["*.example.com"], exclude=["secret.example.com"])
        self.assertEqual(s.classify_host("secret.example.com"), ScopeStatus.OUT_OF_SCOPE)
        self.assertEqual(s.classify_host("api.example.com"), ScopeStatus.IN_SCOPE)

    def test_empty_include_is_unknown(self):
        self.assertEqual(ScopeSpec().classify_host("example.com"), ScopeStatus.UNKNOWN)


class TestScopeClassifier(unittest.TestCase):
    def test_apply_tags_assets(self):
        clf = ScopeClassifier(ScopeSpec(include=["*.example.com"],
                                        exclude=["out.example.com"]))
        a = Asset(AssetType.SUBDOMAIN, "api.example.com", subdomain="api.example.com")
        b = Asset(AssetType.SUBDOMAIN, "out.example.com", subdomain="out.example.com")
        c = Asset(AssetType.SUBDOMAIN, "third.org", subdomain="third.org")
        clf.apply([a, b, c])
        self.assertEqual(a.scope, ScopeStatus.IN_SCOPE)
        self.assertEqual(b.scope, ScopeStatus.OUT_OF_SCOPE)
        self.assertEqual(c.scope, ScopeStatus.UNKNOWN)

    def test_classify_website_by_url(self):
        clf = ScopeClassifier(ScopeSpec(include=["example.com"]))
        w = Asset(AssetType.WEBSITE, "https://api.example.com/x",
                  url="https://api.example.com/x")
        self.assertEqual(clf.classify(w), ScopeStatus.IN_SCOPE)


class TestReconGate(unittest.TestCase):
    def test_dev_override_allows(self):
        gate = ReconGate(audit=False)
        ctx = ReconContext(dev_unsafe_allow_all=True)
        d = gate.authorize_seed(ctx, "example.com")
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, GateReason.ALLOWED_DEV_OVERRIDE.value)

    def test_invalid_target_denied(self):
        gate = ReconGate(audit=False)
        d = gate.authorize_seed(ReconContext(dev_unsafe_allow_all=True), "not a target!!")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, GateReason.DENY_INVALID_TARGET.value)

    def test_no_program_denied_fail_closed(self):
        # Without a program_id and without dev override, the gate must DENY.
        gate = ReconGate(audit=False)
        d = gate.authorize_seed(ReconContext(program_id=None), "example.com")
        self.assertFalse(d.allowed)
        self.assertIn("DENY", d.reason)

    def test_unauthorized_program_denied(self):
        # A program_id that has no reviewed authorization (or no DB) fails closed.
        gate = ReconGate(audit=False)
        d = gate.authorize_seed(ReconContext(program_id=999999), "example.com")
        self.assertFalse(d.allowed)
        self.assertIn("DENY", d.reason)


if __name__ == "__main__":
    unittest.main()
