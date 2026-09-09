"""
config.py — the single place that resolves AI provider configuration.

Why this module exists
----------------------
gemini.py talks to OpenAI: it constructs `AsyncOpenAI(...)` with no
base_url override, and its model defaults are GPT model names. The module
filename and several of its constants still say "Gemini" for historical
reasons, and the .env file that shipped with the repository set
GEMINI_API_KEY / GEMINI_MODEL — names the code never read. The result was
that every AI path logged "GPT_API_KEY is not set" and returned its
fallback message, so /imagine, mention replies, the spam classifier and
news AI summaries were all silently inactive on a deployment that looked
correctly configured.

Rather than rename environment variables and break running deployments,
this module defines one canonical name per setting and an explicit,
ordered fallback chain. A legacy name still works, and using one emits a
single warning naming the canonical replacement.

Scope
-----
AI provider configuration only. Modules with unambiguous, single-name
settings (news.py, github_repo.py, repository_sandbox.py, chain.py,
quota.py, search.py, scrape.py, coordinator.py) keep their own
os.getenv() calls; centralising those would be churn with no defect to
fix. ENV_REGISTRY below documents them so .env.example can be checked
against the code.

Imports stdlib only, so any module can import it without creating a
cycle. Values are read at call time, never at import time, because
app.py calls load_dotenv() after its import block.
"""