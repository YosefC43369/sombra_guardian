"""
web_footprint/ — the Web Footprint Intelligence Engine for Sombra Guardian.

WHAT THIS IS
------------
A passive attack-surface reconnaissance engine. Given a seed target (a domain,
website, or organization identifier), it maps the organization's *publicly
observable* web footprint — domains, subdomains, websites, public APIs and
documentation, technologies, DNS and certificate intelligence, hosting and cloud
references, public documents and repositories, the developer footprint, and the
historical footprint — correlates them into an attack-surface graph, scores
their relevance, and renders an evidence-backed red-team report.

It is built for the same authorized use as the rest of this repository: red-team
reconnaissance and attack-surface mapping of infrastructure you are authorized to
assess, OSINT investigations, and defensive asset discovery — using PUBLIC
information only, before any active testing begins.

POSTURE — 80% RED TEAM / 20% BLUE TEAM
--------------------------------------
The engine is primarily a deep *passive reconnaissance* capability for authorized
red-team engagements (its 80%): the pipeline, collectors, analyzers, graph,
scoring and the 22-section report all serve that goal. A deliberately smaller
defensive companion (``web_footprint.blue``, the 20%) reuses the same passive
output for asset inventory, exposure-change monitoring, brand/impersonation
detection, IOC enrichment hand-off and factual posture signals.

HARD SCOPE LINE (enforced in code, not just documented)
-------------------------------------------------------
This engine stops at reconnaissance. It implements NONE of the following, by
construction:

  * exploitation, credential attacks, or authentication bypass,
  * stealth, evasion, CAPTCHA bypass, or rate-limit bypass,
  * private-account access or unauthorized scanning / active probing.

Every network collector reads already-public data (certificate transparency,
public DNS over DoH, the Wayback web archive, the target's own published
``/.well-known`` files, public repository metadata). The seed target is gated
fail-closed through :class:`web_footprint.authorization.ReconGate`, which defers
to the repository's reviewed-authorization tables in ``scope_policy`` exactly as
``entity_fusion`` and ``/bbscan`` do; discovered assets are tagged
IN_SCOPE / OUT_OF_SCOPE / UNKNOWN against the declared engagement scope. Secret
-like strings found in public text are redacted and classified, never validated
or used. Discovery never asserts ownership without evidence, and an observed
version is never turned into a vulnerability claim.

DESIGN
------
Async- and stdlib-first, layered on the ``osint`` framework's HTTP backbone
(shared rate limiting / retry / request budget). ``httpx`` and ``networkx`` are
optional: the pure core — normalization, the inventory model, the offline
analyzers, the graph, scoring, history and the reports — runs and is fully
tested with zero third-party dependencies; the network collectors activate when
the HTTP stack is present, and a networkx export activates when networkx is.

QUICK START
-----------
    from web_footprint import WebFootprintEngine, ReconContext, ScopeSpec, ReconMode
    from web_footprint.reports import red_team

    engine = WebFootprintEngine()
    ctx = ReconContext(program_id=7,                       # a scope_policy program
                       scope=ScopeSpec(include=["*.example.com"]))
    result = await engine.recon("example.com", ctx, mode=ReconMode.STANDARD)
    print(red_team.render(result))
"""

from .config import ReconMode, ReconLimits, ReconConfig
from .assets import (Asset, AssetType, DomainClass, SignalState, ExposureCategory,
                     ScopeStatus, Evidence, AttackSurfaceInventory)
from .authorization import (ReconContext, ReconGate, GateDecision, ScopeSpec,
                            ScopeClassifier, HAVE_SCOPE_POLICY)
from .graph import AttackSurfaceGraph, HAVE_NETWORKX
from .pipeline import ReconPipeline, ReconResult, run_recon
from .engine import WebFootprintEngine
from .blue import BlueTeamMonitor, Alert, AlertKind
from . import normalize, scoring, history

__all__ = [
    "ReconMode", "ReconLimits", "ReconConfig",
    "Asset", "AssetType", "DomainClass", "SignalState", "ExposureCategory",
    "ScopeStatus", "Evidence", "AttackSurfaceInventory",
    "ReconContext", "ReconGate", "GateDecision", "ScopeSpec", "ScopeClassifier",
    "HAVE_SCOPE_POLICY",
    "AttackSurfaceGraph", "HAVE_NETWORKX",
    "ReconPipeline", "ReconResult", "run_recon",
    "WebFootprintEngine",
    "BlueTeamMonitor", "Alert", "AlertKind",
    "normalize", "scoring", "history",
]

__version__ = "1.0.0"
