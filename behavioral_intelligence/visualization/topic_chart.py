"""
behavioral_intelligence.visualization.topic_chart — keyword / hashtag bar charts
(spec §42).
"""

from __future__ import annotations

from typing import Any, Dict, Sequence

from ..models.topic import Keyword, Hashtag
from ._svg import bar_chart_svg


def keywords_svg(keywords: Sequence[Keyword], *, top_n: int = 15) -> str:
    pairs = [(k.term, k.frequency) for k in keywords[:top_n]]
    return bar_chart_svg(pairs, label="top keywords")


def hashtags_svg(hashtags: Sequence[Hashtag], *, top_n: int = 15) -> str:
    pairs = [(f"#{h.tag}", h.frequency) for h in hashtags[:top_n]]
    return bar_chart_svg(pairs, label="top hashtags")


def to_dict(keywords: Sequence[Keyword], hashtags: Sequence[Hashtag]
            ) -> Dict[str, Any]:
    return {"keywords": [k.to_dict() for k in keywords],
            "hashtags": [h.to_dict() for h in hashtags]}
