"""
group_soc/stories/formatter.py — render a Story to plain text.

Follows the spec's SECURITY STORY layout with the four registers labelled, and always
appends the confidence caveat so a reader never mistakes an analytic confidence for a
finding of intent.
"""

from __future__ import annotations

from ..models.story import Story


def format_story(story: Story) -> str:
    lines = ["SECURITY STORY", f"Subject: {story.subject}", story.headline, ""]

    lines.append("FACTS")
    lines.extend(f"  {f}" for f in story.facts)
    lines.append("")

    lines.append("ANALYSIS")
    lines.extend(f"  {a}" for a in story.analysis)
    lines.append("")

    lines.append("HYPOTHESIS")
    lines.extend(f"  {h}" for h in story.hypotheses)
    lines.append("")

    lines.append("RECOMMENDATION")
    lines.extend(f"  {r}" for r in story.recommendations)
    lines.append("")

    lines.append(f"Current State: {story.current_state}")
    lines.append(f"Confidence: {story.confidence:.2f}")
    lines.append("Note: Confidence is an analytical signal, not proof of malicious intent.")
    return "\n".join(lines)
