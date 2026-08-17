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