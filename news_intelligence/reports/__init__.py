"""
news_intelligence.reports — evidence-graded intelligence products + renderers.

Builders assemble a ``NewsReport`` (a view over stored, evidenced facts — nothing is
re-computed at render time); renderers turn it into Markdown / HTML / JSON / CSV. Every
report carries the standing limitations so no product ships without its caveats.
"""

from .base import render_report, BaseReportBuilder
from .markdown_report import render_markdown
from .html_report import render_html
from .json_report import render_json
from .csv_report import render_csv
from .daily_brief import DailyBriefBuilder
from .weekly_brief import WeeklyBriefBuilder
from .actor_report import ActorReportBuilder
from .malware_report import MalwareReportBuilder
from .cve_report import CVEReportBuilder
from .campaign_report import CampaignReportBuilder
from .executive_report import ExecutiveReportBuilder

__all__ = [
    "render_report", "BaseReportBuilder", "render_markdown", "render_html",
    "render_json", "render_csv", "DailyBriefBuilder", "WeeklyBriefBuilder",
    "ActorReportBuilder", "MalwareReportBuilder", "CVEReportBuilder",
    "CampaignReportBuilder", "ExecutiveReportBuilder",
]
