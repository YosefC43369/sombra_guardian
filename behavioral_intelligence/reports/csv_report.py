"""
behavioral_intelligence.reports.csv_report — tabular export.

Flattens the tabular parts of a ``BehaviorProfile`` (assertions, keywords,
hashtags, domains, interactions, anomalies, change points) into CSV sections for
spreadsheet analysis. Each section is a labelled block so one file carries every
table; the assertion table keeps the epistemic ``kind`` column so the observed/
correlated/inferred distinction survives the export.
"""

from __future__ import annotations

import csv
import io
from typing import Optional

from ..models.behavior import BehaviorProfile
from ..configuration import PrivacyConfig


def render(profile: BehaviorProfile, *, privacy: Optional[PrivacyConfig] = None
           ) -> str:
    out = io.StringIO()
    w = csv.writer(out)

    w.writerow(["# behavioral-intelligence report", profile.entity_id or profile.label])
    w.writerow([])

    w.writerow(["## assertions"])
    w.writerow(["kind", "confidence", "statement"])
    for a in profile.assertions:
        w.writerow([a.kind.value, f"{a.score:.3f}" if a.confidence else "",
                    a.statement])
    w.writerow([])

    w.writerow(["## keywords"])
    w.writerow(["term", "frequency", "tfidf", "burst_score"])
    for k in profile.keywords:
        w.writerow([k.term, k.frequency, f"{k.tfidf:.4f}", f"{k.burst_score:.3f}"])
    w.writerow([])

    w.writerow(["## hashtags"])
    w.writerow(["tag", "frequency", "trend"])
    for h in profile.hashtags:
        w.writerow([h.tag, h.frequency, h.trend])
    w.writerow([])

    w.writerow(["## domains"])
    w.writerow(["domain", "frequency", "is_shortener"])
    for d in profile.domains:
        w.writerow([d.domain, d.frequency, d.is_shortener])
    w.writerow([])

    w.writerow(["## interactions"])
    w.writerow(["source", "target", "count"])
    if profile.interactions:
        for e in profile.interactions.edges:
            w.writerow([e.source, e.target, e.count])
    w.writerow([])

    w.writerow(["## anomalies"])
    w.writerow(["at", "kind", "severity", "description"])
    for an in profile.anomalies:
        w.writerow([f"{an.at:.0f}", an.kind, an.severity, an.description])
    w.writerow([])

    w.writerow(["## change_points"])
    w.writerow(["at", "kind", "method", "magnitude"])
    for c in profile.change_points:
        w.writerow([f"{c.at:.0f}", c.kind, c.method, f"{c.magnitude:.3f}"])

    return out.getvalue()
