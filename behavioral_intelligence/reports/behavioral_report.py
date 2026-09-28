"""
behavioral_intelligence.reports.behavioral_report — the report builder / facade.

Bundles the individual renderers behind one ``BehavioralReportBuilder`` and the
``render_report`` dispatcher used by ``BehavioralEngine.generate_report``. Chooses
the renderer by format name and threads the privacy configuration through so
every rendered artefact honours the same data-minimisation posture.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional

from ..models.behavior import BehaviorProfile
from ..configuration import BehavioralConfig, PrivacyConfig
from . import (markdown_report, json_report, csv_report, html_report,
               executive_summary, evidence_report)

_RENDERERS: "Dict[str, Callable[..., str]]" = {
    "markdown": markdown_report.render,
    "md": markdown_report.render,
    "json": json_report.render,
    "csv": csv_report.render,
    "html": html_report.render,
    "summary": executive_summary.render,
    "executive": executive_summary.render,
    "evidence": evidence_report.render,
}


def render_report(profile: BehaviorProfile, *, fmt: str = "markdown",
                  config: Optional[BehavioralConfig] = None,
                  privacy: Optional[PrivacyConfig] = None) -> str:
    """Render a profile in the requested format. Unknown formats fall back to
    markdown. Privacy config is taken from the argument, then the engine config,
    then a default."""
    priv = privacy or (config.privacy if config else None) or PrivacyConfig()
    renderer = _RENDERERS.get(fmt.lower(), markdown_report.render)
    return renderer(profile, privacy=priv)


class BehavioralReportBuilder:
    def __init__(self, config: Optional[BehavioralConfig] = None):
        self.config = config
        self.privacy = config.privacy if config else PrivacyConfig()

    def markdown(self, profile: BehaviorProfile) -> str:
        return markdown_report.render(profile, privacy=self.privacy)

    def json(self, profile: BehaviorProfile) -> str:
        return json_report.render(profile, privacy=self.privacy)

    def csv(self, profile: BehaviorProfile) -> str:
        return csv_report.render(profile, privacy=self.privacy)

    def html(self, profile: BehaviorProfile) -> str:
        return html_report.render(profile, privacy=self.privacy)

    def executive_summary(self, profile: BehaviorProfile) -> str:
        return executive_summary.render(profile, privacy=self.privacy)

    def evidence(self, profile: BehaviorProfile) -> str:
        return evidence_report.render(profile, privacy=self.privacy)

    def all_formats(self, profile: BehaviorProfile) -> dict:
        return {"markdown": self.markdown(profile), "json": self.json(profile),
                "csv": self.csv(profile), "html": self.html(profile),
                "summary": self.executive_summary(profile),
                "evidence": self.evidence(profile)}
