"""
cve_tracker.ai.adapter — provider-agnostic bridge to the project's AI.

The CVE subsystem must reuse the existing AI integration and not care which
backend serves it (rules §13, §33). This adapter exposes ONE coroutine —
:meth:`AIProviderAdapter.generate` — over the two AI entry points the project
already ships:

  * ``ai_router.route`` (multi-provider with fallback), preferred when configured
  * ``gemini.ask_gemini`` (single OpenAI-compatible client), the baseline

It never raises (both underlying calls are already exception-safe) and returns a
small :class:`AIResult`. Credentials/config stay owned by the host project; this
adapter only chooses a route and passes text.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("modbot.cve.ai")


@dataclass
class AIResult:
    ok: bool
    text: str = ""
    provider: str = ""
    model: str = ""
    reason: str = ""


class AIProviderAdapter:
    """Wraps the host project's AI. Construct with the CVE AIConfig."""

    def __init__(self, config):
        self.config = config
        self._router_ok: Optional[bool] = None

    # ---------------- availability ----------------

    def available(self) -> bool:
        """True if *some* AI backend is configured. Cheap; reads env via the
        host modules' own helpers."""
        if not self.config.enabled:
            return False
        if self.config.prefer_router and self._router_available():
            return True
        return self._gemini_available()

    def _router_available(self) -> bool:
        try:
            import ai_router
            return ai_router.router_configured()
        except Exception:
            return False

    def _gemini_available(self) -> bool:
        try:
            import gemini  # noqa: F401
            import config as bot_config
            # gemini uses config.resolve_model()/_get_client(); treat presence of
            # any API key name as 'configured'.
            names = getattr(bot_config, "API_KEY_NAMES", [])
            import os
            return any(os.getenv(n) for n in names) if names else True
        except Exception:
            # If we can't introspect, assume gemini may still work; the call is
            # exception-safe and will report failure honestly.
            return True

    # ---------------- generation ----------------

    async def generate(self, prompt: str, *, system: str = "",
                       task: str = "heavy") -> AIResult:
        """Send ``prompt`` with ``system`` instruction to the best available
        backend, with a cross-backend fallback. Returns an AIResult."""
        if not self.config.enabled:
            return AIResult(False, reason="ai-disabled")

        order = []
        if self.config.prefer_router:
            order = ["router", "gemini"]
        else:
            order = ["gemini", "router"]

        last_reason = "no-backend"
        for backend in order:
            if backend == "router":
                res = await self._via_router(prompt, system, task)
            else:
                res = await self._via_gemini(prompt, system)
            if res.ok:
                return res
            last_reason = res.reason or last_reason
        return AIResult(False, reason=last_reason)

    async def _via_router(self, prompt: str, system: str, task: str) -> AIResult:
        try:
            import ai_router
        except Exception:
            return AIResult(False, reason="router-unavailable")
        if not ai_router.router_configured():
            return AIResult(False, reason="router-not-configured")
        try:
            result = await ai_router.route(
                prompt, system=system or None,
                task=task if task in ("light", "heavy") else None,
                temperature=self.config.temperature,
            )
            if result.ok:
                return AIResult(True, text=result.text, provider=result.provider,
                                model=result.model)
            return AIResult(False, reason=f"router:{result.reason}")
        except Exception as exc:
            logger.warning("CVE AI router error: %s", exc)
            return AIResult(False, reason=f"router-exc:{type(exc).__name__}")

    async def _via_gemini(self, prompt: str, system: str) -> AIResult:
        try:
            import gemini
        except Exception:
            return AIResult(False, reason="gemini-unavailable")
        try:
            ok, text = await gemini.ask_gemini(
                prompt,
                system_instruction=system or None,
                max_input_chars=self.config.max_input_chars,
            )
            if ok:
                model = ""
                try:
                    import config as bot_config
                    model = bot_config.resolve_model()
                except Exception:
                    pass
                return AIResult(True, text=text, provider="gemini", model=model)
            # gemini returns a Thai user-facing error string on failure.
            return AIResult(False, reason=f"gemini:{text[:120]}")
        except Exception as exc:
            logger.warning("CVE AI gemini error: %s", exc)
            return AIResult(False, reason=f"gemini-exc:{type(exc).__name__}")
