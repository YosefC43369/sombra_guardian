"""blueteam.posture — Security Posture Score & Client Report (v0.8.0).

Transparent scoring (Σ(w·s·c)/Σ(w·c), UNKNOWN excluded, deterministic + monotonic
+ gated) with explainability and what-if. Self-contained HTML/MD/JSON/CSV reports
(self-drawn SVG, no JS), sealed to the integrity ledger. Layering: ``domain`` +
``report`` (pure) -> ``service`` (ports) -> ``adapters`` (SQLite) / ``commands``.
"""

from .domain import (Control, Assessment, ScoreResult, Grade, compute_score,
                     explain, whatif, load_catalog)
from .report import Branding, ReportModel, render_html, report_sha256

__all__ = ["Control", "Assessment", "ScoreResult", "Grade", "compute_score",
           "explain", "whatif", "load_catalog", "Branding", "ReportModel",
           "render_html", "report_sha256"]
