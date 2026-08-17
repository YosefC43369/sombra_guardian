"""
test_github_repo.py — unit test suite for github_repo.py.

Same isolation pattern as test_scope_policy.py/test_findings.py: every
test gets a fresh tempfile SQLite DB (security.DB_PATH / gr.DB import
monkeypatched) and a fresh tempdir workspace root (gr.WORKSPACE_ROOT
monkeypatched). `git` is never actually invoked — subprocess.run is
mocked in every test that reaches the clone path, and no test in this
file touches the network. A handful of real (non-network) filesystem
operations are exercised directly against the tempdir workspace root
(symlink stripping, size/count, cleanup) since those don't need git at
all.
"""

import os
import time
import shutil
import tempfile
import subprocess
from unittest.mock import path

import security
import github_repo as gr

def _mock_complete(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)
    
class GithubRepoTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close()
        self._db_path = db_path
        security.DB_PATH = db_path
        gr.DB_PATH = db_path
        security.security_db_init()
        gr.github_repo_db_init()
        
        self._workspace_root = tempfile.mkdtemp(prefix="gh_ws_root_")
        gr.WORKSPACE_ROOT = self._workspace_root
        
        gr._active_clone_count = 0
        gr.MAX_CONCURRENT_CLONES = 2
        gr.MAX_FILE_COUNT = 5000
        gr.MAX_REPOSITORY_SIZE_BYTES = 250 * 1024 * 1024
        gr.MAX_TOTAL_WORKSPACE_BYTES = 2048 * 1024 * 1024
        gr.MAX_CLONE_TIME_SECONDS = 120
        
    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass
        shutil.rmtree(self._workspace_root, ignore_errors=True)
        
    # ---- helpers ----
    
    def _write_fake_clone(self, workspace_path, num_files=3, file_size=10):
        os.makedirs(workspace_path, exist_ok=True)
        os.makedirs(os.path.join(workspace_path, ".git"), exist_ok=True)
        with open(os.path.join(workspace_path, ".git", "HEAD"), "w") as f:
             f.write("ref: refs/heads/main\n")
        for i in range(num_files):
            with open(os.path.join(workspace_path, f"file{i}.txt"), "w") as f:
                 f.write("x" * file_size)
                
    # ================= validate_repository_url (Phase 3 / items 1-8) =================
    
    def test_01_valid_github_url(self):
        r = gr.validate_repository_url("https://github.com/octocat/Hello-World")
        self.assertIsNotNone(r)
        self.assertEqual(r.owner, "octocat")
        self.assertEqual(r.name, "Hello-World")
        self.assertEqual(r.clone_url, "https://github.com/octocat/Hello-World.git")
        
    def test_02_invalid_garbage_url(self):
        self.assertIsNone(gr.validate_repository_url("not a url at all"))
        self.assertIsNone(gr.validate_repository_url(""))
        self.assertIsNone(gr.validate_repository_url(None))

    def test_03_non_github_url(self):
        self.assertIsNone(gr.validate_repository_url("https://gitlab.com/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://github.com.evil.com/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://evil.com/github.com/owner/repo"))

    def test_04_dot_git_url(self):
        r = gr.validate_repository_url("https://github.com/owner/repository.git")
        self.assertIsNotNone(r)
        self.assertEqual(r.name, "repository")
        self.assertEqual(r.clone_url, "https://github.com/owner/repository.git")

    def test_05_malformed_repository_path(self):
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/repo/blob/main/x.py"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/repo?x=1"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/repo#frag"))

    def test_06_path_traversal_in_url(self):
        self.assertIsNone(gr.validate_repository_url("https://github.com/../../etc/passwd"))
        self.assertIsNone(gr.validate_repository_url("https://github.com/owner/../../../etc"))

    def test_07_localhost_and_internal_ip_rejected(self):
        self.assertIsNone(gr.validate_repository_url("http://localhost/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://localhost/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://127.0.0.1/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://192.168.1.10/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("https://169.254.169.254/owner/repo"))
        # userinfo trick: hostname parses as evil.com, "github.com" becomes username
        self.assertIsNone(gr.validate_repository_url("https://github.com@evil.com/owner/repo"))

    def test_08_unsupported_protocol_rejected(self):
        self.assertIsNone(gr.validate_repository_url("ssh://git@github.com/owner/repo.git"))
        self.assertIsNone(gr.validate_repository_url("git://github.com/owner/repo.git"))
        self.assertIsNone(gr.validate_repository_url("file:///etc/passwd"))
        self.assertIsNone(gr.validate_repository_url("ftp://github.com/owner/repo"))
        self.assertIsNone(gr.validate_repository_url("http://github.com/owner/repo"))  # http, not https
        
    # ================= workspace isolation (item 9) =================

    def test_09_workspace_isolation_unique_dirs(self):
        _id1, path1 = gr._new_workspace_path()
        _id2, path2 = gr._new_workspace_path()
        self.assertNotEqual(path1, path2)
        self.assertTrue(gr._is_within_workspace_root(path1))
        self.assertTrue(gr._is_within_workspace_root(path2))
        self.assertFalse(gr._is_within_workspace_root("/etc/passwd"))
        self.assertFalse(gr._is_within_workspace_root(os.path.join(self._workspace_root, "..", "escape")))

    # ================= size / file-count limits (items 10-11) =================
    
    @path("github_repo.subprocess.run")
    async def test_10_repository_size_limit_enforced(self, mock_run):
        gr.MAX_REPOSITORY_SIZE_BYTES = 50 # tiny cap so our fake clone exceeds it
        
        def fake_run(cmd, **kwargs):
            if cmd[1] == "clone"