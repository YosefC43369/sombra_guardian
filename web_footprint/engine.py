"""
web_footprint.engine — the public facade of the Web Footprint Intelligence Engine.

This is the single entry point most callers want. It wires the passive recon
pipeline to the three run modes (spec §56–58) and exposes both an async API
(``recon``) and a blocking convenience (``recon_sync``) for command handlers that
are not already in an event loop.

POSTURE (unchanged from the rest of the package). The engine is 80% red-team
passive reconnaissance / 20% blue-team defensive monitoring. The primary output
is an evidence-backed, source-attributed, confidence-aware map of an
organization's publicly observable web footprint — and it stops at
reconnaissance. It performs no exploitation, credential access, authentication
bypass, stealth, evasion, CAPTCHA/rate-limit bypass, or unauthorized access; the
seed is gated fail-closed against ``scope_policy`` before anything runs.
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional

from .authorization import ReconContext, ReconGate
from .config import ReconConfig, ReconMode
from .collectors.base import Collector
from .pipeline import ReconPipeline, ReconResult
from .blue.monitor import BlueTeamMonitor


class WebFootprintEngine:
    """Facade over the passive recon pipeline plus the blue-team monitor."""

    def __init__(self, collectors: Optional[List[Collector]] = None, *,
                 gate: Optional[ReconGate] = None) -> None:
        self.pipeline = ReconPipeline(collectors, gate=gate)

    async def recon(self, target: str, ctx: ReconContext, *,
                    mode: ReconMode = ReconMode.STANDARD,
                    config: Optional[ReconConfig] = None,
                    client: Optional[Any] = None) -> ReconResult:
        """Run a passive recon and return the full :class:`ReconResult`."""
        cfg = config or ReconConfig(mode=ReconMode.coerce(mode))
        return await self.pipeline.run(target, ctx, config=cfg, client=client)

    async def quick(self, target: str, ctx: ReconContext, **kw: Any) -> ReconResult:
        return await self.recon(target, ctx, mode=ReconMode.QUICK, **kw)

    async def standard(self, target: str, ctx: ReconContext, **kw: Any) -> ReconResult:
        return await self.recon(target, ctx, mode=ReconMode.STANDARD, **kw)

    async def deep(self, target: str, ctx: ReconContext, **kw: Any) -> ReconResult:
        return await self.recon(target, ctx, mode=ReconMode.DEEP, **kw)

    def recon_sync(self, target: str, ctx: ReconContext, *,
                   mode: ReconMode = ReconMode.STANDARD,
                   config: Optional[ReconConfig] = None) -> ReconResult:
        """Blocking wrapper for non-async callers. Raises if already inside a
        running event loop (use :meth:`recon` there instead)."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.recon(target, ctx, mode=mode, config=config))
        raise RuntimeError("recon_sync cannot run inside an active event loop; "
                           "await engine.recon(...) instead")

    def monitor(self) -> BlueTeamMonitor:
        """A blue-team monitor bound to this engine (defensive 20%)."""
        return BlueTeamMonitor(self)
