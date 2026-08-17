"""
github_repo.py — sandboxed GitHub repository cloning for code review.

Clones a public GitHub repository into an isolated, size- and count-capped
workspace directory so its files can be listed and read for static review
(e.g. by detection.py / findings.py). This module answers exactly one
question — "fetch this repository's files safely" — and nothing else.

This module does NOT perform, and must never be extended to perform,
anything that runs code found inside a cloned repository: no dynamic code
evaluation, no invocation of a cloned repo's build/install/test scripts,
no dynamic module loading of cloned content, and no command interpreter
substitution when invoking git. Every subprocess call passes an argument
list (never a single interpreted string), always separates git's own
flags from the untrusted URL/path with a literal "--", and never enables
shell interpretation of the command.

Safety layers:
- validate_repository_url(): allow-lists https://github.com/<owner>/<repo>
  only — exact hostname match (no suffix/subdomain tricks), no userinfo,
  no query/fragment, path must be exactly two segments, rejects "..",
  ".", and empty segments. This also closes off localhost / private-IP /
  cloud-metadata targets, since nothing but the literal host "github.com"
  is ever accepted.
- Workspace isolation: every clone gets its own randomly named directory
  under WORKSPACE_ROOT; path containment is checked before any read or
  delete, so a crafted subpath or symlink can never reach outside its own
  workspace (or outside WORKSPACE_ROOT entirely).
- Size, file-count, and wall-clock timeout caps enforced after clone,
  before the repository is marked usable.
- Symlinks that resolve outside a workspace are stripped after clone.
- Every clone attempt (start/complete/fail) and every deletion is written
  to security.py's shared audit log.

Design constraints (matches security.py / scope_policy.py / findings.py):
- Standard library only, plus the "git" binary via subprocess with an
  explicit argument list.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table — no second database, no second audit system.
"""