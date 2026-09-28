"""
behavioral_intelligence.linguistic.keyword_engine — recurring public keywords
(spec §12).

Extracts terms with frequency, TF-IDF salience (each observation is a document),
a burst score (recent vs. earlier concentration), first/last-seen provenance,
platform spread and co-occurrence. Tokenisation is Unicode-aware and handles the
no-whitespace scripts the spec targets (Thai / Han / Kana) by emitting character
bigrams for those runs, so meaningful recurring units surface without an external
word segmenter.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Set

from ..models.observation import Observation
from ..models.topic import Keyword
from .. import util
from . import script_detector

# Space-delimited word tokens (letters only, keeps intra-word apostrophes off).
_WORD_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)
# Contiguous runs of no-space scripts, segmented into char bigrams downstream.
_CJKT_RE = re.compile(r"[฀-๿㐀-鿿぀-ヿ]{2,}")

# Merged multilingual stopword set (function words carry no topical signal).
_STOP: Set[str] = set()
for _words in [
    {"the", "and", "for", "you", "are", "with", "this", "that", "have", "was",
     "not", "but", "will", "can", "all", "your", "from", "they", "what", "when",
     "http", "https", "www", "com", "rt", "amp"},
    {"que", "los", "las", "una", "por", "con", "para", "más", "como"},
    {"les", "des", "une", "pour", "dans", "pas", "vous", "avec"},
    {"der", "die", "das", "und", "ist", "ein", "eine", "mit", "auf", "nicht"},
    {"yang", "dan", "itu", "dengan", "untuk", "tidak", "ini", "dari", "dalam"},
]:
    _STOP |= _words


def tokenize(text: str) -> List[str]:
    """Return casefolded content tokens. Latin-ish words come through directly;
    Thai/CJK runs are split into overlapping character bigrams as pseudo-tokens."""
    if not text:
        return []
    tokens: List[str] = []
    for w in _WORD_RE.findall(text):
        wl = w.casefold()
        if wl in _STOP or len(wl) < 2:
            continue
        # keep whole word only if it's not a no-space script run (handled below)
        if script_detector.dominant_script(wl) not in ("Thai", "Han", "Hiragana",
                                                        "Katakana"):
            tokens.append(wl)
    for run in _CJKT_RE.findall(text):
        for i in range(len(run) - 1):
            tokens.append(run[i:i + 2])
    return tokens


def extract_keywords(observations: Sequence[Observation], *, top_n: int = 25,
                     recent_fraction: float = 0.25) -> List[Keyword]:
    """Rank keywords by TF-IDF summed across documents. ``recent_fraction`` sets
    the tail of the (time-ordered) corpus used to compute the burst score."""
    docs: List[List[str]] = []
    doc_obs: List[Observation] = []
    for o in observations:
        toks = tokenize(o.text)
        if toks:
            docs.append(toks)
            doc_obs.append(o)
    n_docs = len(docs)
    if n_docs == 0:
        return []

    # document frequency for IDF
    df: Counter = Counter()
    for toks in docs:
        for t in set(toks):
            df[t] += 1

    # aggregate term frequency + provenance
    tf: Counter = Counter()
    first_seen: Dict[str, float] = {}
    last_seen: Dict[str, float] = {}
    platforms: Dict[str, Set[str]] = defaultdict(set)
    cooc: Dict[str, Counter] = defaultdict(Counter)
    for toks, o in zip(docs, doc_obs):
        uniq = set(toks)
        for t in toks:
            tf[t] += 1
        for t in uniq:
            if o.has_time:
                first_seen[t] = min(first_seen.get(t, o.timestamp), o.timestamp)
                last_seen[t] = max(last_seen.get(t, o.timestamp), o.timestamp)
            if o.platform:
                platforms[t].add(o.platform)
        for a in uniq:
            for b in uniq:
                if a != b:
                    cooc[a][b] += 1

    # burst score: term rate in the recent tail vs. overall rate
    timed_idx = sorted(range(n_docs),
                       key=lambda i: doc_obs[i].timestamp if doc_obs[i].has_time else 0)
    tail_n = max(1, int(n_docs * recent_fraction))
    recent_docs = timed_idx[-tail_n:]
    recent_tf: Counter = Counter()
    for i in recent_docs:
        for t in docs[i]:
            recent_tf[t] += 1

    scored: List[Keyword] = []
    for term, freq in tf.items():
        idf = math.log((1 + n_docs) / (1 + df[term])) + 1.0
        tfidf = freq * idf
        overall_rate = util.safe_div(freq, n_docs)
        recent_rate = util.safe_div(recent_tf.get(term, 0), tail_n)
        burst = util.safe_div(recent_rate, overall_rate) if overall_rate else 0.0
        scored.append(Keyword(
            term=term, frequency=freq, tfidf=tfidf, burst_score=burst,
            first_seen=first_seen.get(term, 0.0), last_seen=last_seen.get(term, 0.0),
            platforms=sorted(platforms.get(term, set())),
            cooccurring=[w for w, _ in cooc[term].most_common(5)]))
    scored.sort(key=lambda k: k.tfidf, reverse=True)
    return scored[:top_n]
