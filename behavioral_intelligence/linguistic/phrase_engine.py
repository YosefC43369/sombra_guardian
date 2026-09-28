"""
behavioral_intelligence.linguistic.phrase_engine — recurring phrase detection
(spec §13).

Extracts repeated n-grams (bi- through 5-grams) over normalised text. Phrases
are built from the same tokeniser as the keyword engine, so Thai/CJK content
contributes character-bigram sequences rather than being dropped. Only phrases
that recur (frequency ≥ ``min_count``) are returned, and the engine avoids
surfacing unnecessary sensitive raw text (spec §13) by exposing only the phrase
token sequence and its counts, not the surrounding post.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Sequence, Tuple

from ..models.observation import Observation
from ..models.topic import Phrase
from . import keyword_engine


def _ngrams(tokens: List[str], n: int) -> List[Tuple[str, ...]]:
    return [tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)]


def extract_phrases(observations: Sequence[Observation], *,
                    sizes: Sequence[int] = (2, 3, 4, 5),
                    min_count: int = 3, top_n: int = 30) -> List[Phrase]:
    counters: Dict[int, Counter] = {n: Counter() for n in sizes}
    first_seen: Dict[Tuple[str, ...], float] = {}
    last_seen: Dict[Tuple[str, ...], float] = {}

    for o in observations:
        toks = keyword_engine.tokenize(o.text)
        if len(toks) < min(sizes):
            continue
        for n in sizes:
            for gram in _ngrams(toks, n):
                counters[n][gram] += 1
                if o.has_time:
                    first_seen[gram] = min(first_seen.get(gram, o.timestamp), o.timestamp)
                    last_seen[gram] = max(last_seen.get(gram, o.timestamp), o.timestamp)

    phrases: List[Phrase] = []
    for n, counter in counters.items():
        for gram, freq in counter.items():
            if freq >= min_count:
                phrases.append(Phrase(
                    text=" ".join(gram), n=n, frequency=freq,
                    first_seen=first_seen.get(gram, 0.0),
                    last_seen=last_seen.get(gram, 0.0)))
    # prefer longer, more frequent phrases (length breaks frequency ties)
    phrases.sort(key=lambda p: (p.frequency, p.n), reverse=True)
    return phrases[:top_n]
