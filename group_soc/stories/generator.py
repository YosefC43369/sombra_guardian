"""
group_soc/stories/generator.py — turn an incident + its timeline into a Story.

The story keeps four registers strictly separate (rule §13):
  FACTS           observed timeline events (no interpretation)
  ANALYSIS        what the correlation/detection layer concluded (signal summaries)
  HYPOTHESIS      what *might* be happening, by classification (explicitly uncertain)
  RECOMMENDATION  suggested, non-destructive next steps for an admin

Confidence is surfaced as an analytic measure, never as proof of intent.
"""

from __future__ import annotations

import time
from typing import List

from ..models.story import Story
from ..models.incident import Incident
from ..constants import IncidentClass
from ..util import now
from ..timeline.builder import TimelineBuilder


_HYPOTHESES = {
    IncidentClass.SPAM_CAMPAIGN.value: [
        "The identical messages across multiple accounts may indicate a coordinated "
        "promotional/spam campaign.",
    ],
    IncidentClass.RAID.value: [
        "The rapid influx of joins may indicate a raid or a botnet onboarding.",
    ],
    IncidentClass.MALICIOUS_LINK.value: [
        "A newly-joined account posting an external link shortly after joining is a "
        "common scam delivery pattern.",
    ],
    IncidentClass.IOC_EXPOSURE.value: [
        "An indicator matched a threat-intel feed; the group may have been exposed to a "
        "known-bad resource.",
    ],
    IncidentClass.COORDINATED_ACTIVITY.value: [
        "Multiple correlated signals around the same actors/indicators may indicate "
        "coordinated activity rather than isolated incidents.",
    ],
}

_RECOMMENDATIONS = {
    IncidentClass.SPAM_CAMPAIGN.value: [
        "Review the involved messages and, if confirmed, remove them and restrict the "
        "posting accounts.",
        "Consider enabling slow mode and the Link/Scam Guard for this group.",
    ],
    IncidentClass.RAID.value: [
        "Consider enabling Join Guard / verification challenges and slow mode.",
        "Review the recent joiners before taking bulk action.",
    ],
    IncidentClass.MALICIOUS_LINK.value: [
        "Review the posted link (defanged) before acting; restrict the account if confirmed.",
        "Add the domain to the watchlist to catch reuse.",
    ],
    IncidentClass.IOC_EXPOSURE.value: [
        "Review the matched indicator and any message that carried it.",
        "Confirm the feed match is a true positive before restricting anyone.",
    ],
    IncidentClass.COORDINATED_ACTIVITY.value: [
        "Open a case and pivot on the shared actors/indicators to confirm the link.",
    ],
}
_DEFAULT_RECS = ["Review the linked alerts and confirm before taking any action."]


class StoryGenerator:
    def __init__(self, storage):
        self.storage = storage
        self.timeline = TimelineBuilder(storage)

    def for_incident(self, incident: Incident) -> Story:
        entries = self.timeline.build_for_incident(incident)
        facts: List[str] = []
        for e in entries:
            if e.kind in ("event", "incident"):
                facts.append(f"{time.strftime('%H:%M:%S', time.gmtime(e.ts))} — {e.summary}")

        analysis: List[str] = []
        seen = set()
        for corr in incident.correlation_ids:
            for sig in self.storage.signals.by_correlation(corr):
                if sig.signal_id in seen:
                    continue
                seen.add(sig.signal_id)
                analysis.append(f"{sig.title}: {sig.summary}")
        if not analysis:
            analysis.append("Correlated/detected signals contributed to this incident.")

        hyps = list(_HYPOTHESES.get(incident.classification,
                                    ["The available signals are consistent with the "
                                     "assigned classification, but intent is unconfirmed."]))
        recs = list(_RECOMMENDATIONS.get(incident.classification, _DEFAULT_RECS))

        return Story(
            chat_id=incident.chat_id,
            subject=incident.incident_id,
            headline=f"{incident.classification.replace('_', ' ').title()} — {incident.title}",
            facts=facts or ["No individual events were recorded for this incident."],
            analysis=analysis,
            hypotheses=hyps,
            recommendations=recs,
            confidence=round(incident.dimensions.confidence, 2),
            current_state=incident.status.upper(),
            generated_at=now(),
        )
