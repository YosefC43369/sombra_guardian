"""
cve_tracker.enrichment.cvss — CVSS vector parsing, scoring and explanation.

Supports CVSS v2.0, v3.0, v3.1 and v4.0 *vectors*. Two jobs:

  1. **Decode** a vector string into human-readable metric labels (Attack
     Vector = Network, etc.) and a qualitative severity band — used by the
     Thai formatter and the AI prompt so the model reasons over labels, not
     cryptic single letters.
  2. **Compute** a base score from a v3.x vector when the source gave a vector
     but no score. This uses the official first.org formulas. We NEVER compute
     a score the source did not implicitly provide via a vector, and we never
     override a source-provided numeric score with a computed one — a computed
     score fills a gap, it does not compete (rule §10: "do not invent scores").

The v4.0 base-score formula depends on a large official lookup table that is
not reproduced here; for v4.0 we decode the vector and *carry* the score the
source provides, but do not compute one ourselves. That is the honest behaviour
— a wrong computed v4 score is worse than none.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple

from ..constants import (
    CVSS2_VECTOR_RE,
    CVSS3_VECTOR_RE,
    CVSS4_VECTOR_RE,
)
from ..enums import (
    CVSSVersion,
    Severity,
    ATTACK_VECTOR,
    ATTACK_COMPLEXITY,
    PRIVILEGES_REQUIRED,
    USER_INTERACTION,
    SCOPE,
    IMPACT,
    V2_ACCESS_VECTOR,
    V2_ACCESS_COMPLEXITY,
    V2_AUTHENTICATION,
    V2_IMPACT,
)
from ..models import CVSSScore


# ---------------- vector parsing ----------------

def detect_version(vector: str) -> Optional[str]:
    """Which CVSS version a vector string is, or None if it isn't a vector."""
    if not vector:
        return None
    v = vector.strip()
    if CVSS4_VECTOR_RE.match(v):
        return CVSSVersion.V40.value
    if CVSS3_VECTOR_RE.match(v):
        return "3.1" if v.upper().startswith("CVSS:3.1") else "3.0"
    if CVSS2_VECTOR_RE.match(v) or _looks_like_v2(v):
        return CVSSVersion.V2.value
    return None


def _looks_like_v2(vector: str) -> bool:
    # v2 vectors are 'AV:.../AC:.../Au:.../C:.../I:.../A:...' with no CVSS: prefix
    metrics = _split_metrics(vector)
    return "AV" in metrics and "Au" in metrics and "AC" in metrics


def _split_metrics(vector: str) -> Dict[str, str]:
    """Parse 'AV:N/AC:L/...' (optionally with a 'CVSS:3.1/' prefix) into a dict.
    Unknown/duplicate metrics keep the last value; malformed pairs are skipped."""
    out: Dict[str, str] = {}
    if not vector:
        return out
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        key = key.strip()
        val = val.strip()
        if key.upper() == "CVSS":
            continue
        if key and val:
            out[key] = val
    return out


# ---------------- decode to labels ----------------

def _decode_v3(metrics: Dict[str, str]) -> Dict[str, str]:
    return {
        "attack_vector": ATTACK_VECTOR.get(metrics.get("AV", "").upper(), ""),
        "attack_complexity": ATTACK_COMPLEXITY.get(metrics.get("AC", "").upper(), ""),
        "privileges_required": PRIVILEGES_REQUIRED.get(metrics.get("PR", "").upper(), ""),
        "user_interaction": USER_INTERACTION.get(metrics.get("UI", "").upper(), ""),
        "scope": SCOPE.get(metrics.get("S", "").upper(), ""),
        "confidentiality": IMPACT.get(metrics.get("C", "").upper(), ""),
        "integrity": IMPACT.get(metrics.get("I", "").upper(), ""),
        "availability": IMPACT.get(metrics.get("A", "").upper(), ""),
    }


def _decode_v4(metrics: Dict[str, str]) -> Dict[str, str]:
    # v4 renames some metrics: AT (attack requirements), VC/VI/VA (vuln impact),
    # SC/SI/SA (subsequent system impact). We surface the base-equivalent set.
    return {
        "attack_vector": ATTACK_VECTOR.get(metrics.get("AV", "").upper(), ""),
        "attack_complexity": ATTACK_COMPLEXITY.get(metrics.get("AC", "").upper(), ""),
        "privileges_required": PRIVILEGES_REQUIRED.get(metrics.get("PR", "").upper(), ""),
        "user_interaction": USER_INTERACTION.get(metrics.get("UI", "").upper(), ""),
        "scope": "",  # v4 replaces Scope with subsequent-system metrics
        "confidentiality": IMPACT.get(metrics.get("VC", "").upper(), ""),
        "integrity": IMPACT.get(metrics.get("VI", "").upper(), ""),
        "availability": IMPACT.get(metrics.get("VA", "").upper(), ""),
    }


def _decode_v2(metrics: Dict[str, str]) -> Dict[str, str]:
    return {
        "attack_vector": V2_ACCESS_VECTOR.get(metrics.get("AV", "").upper(), ""),
        "attack_complexity": V2_ACCESS_COMPLEXITY.get(metrics.get("AC", "").upper(), ""),
        "privileges_required": V2_AUTHENTICATION.get(metrics.get("Au", "").upper(), ""),
        "user_interaction": "",
        "scope": "",
        "confidentiality": V2_IMPACT.get(metrics.get("C", "").upper(), ""),
        "integrity": V2_IMPACT.get(metrics.get("I", "").upper(), ""),
        "availability": V2_IMPACT.get(metrics.get("A", "").upper(), ""),
    }


# ---------------- v3.x base-score computation (official formula) ----------------

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    # PR depends on Scope; handled specially below.
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x: float) -> float:
    """CVSS v3.1 'roundup': ceil to one decimal via integer arithmetic on
    hundredths (per the spec, avoids float rounding surprises)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def compute_v3_base_score(metrics: Dict[str, str]) -> Optional[float]:
    """Compute the CVSS v3.x base score from decoded metrics using the official
    formula. Returns None if any required metric is missing/invalid — we do not
    guess."""
    try:
        av = _V3_WEIGHTS["AV"][metrics["AV"].upper()]
        ac = _V3_WEIGHTS["AC"][metrics["AC"].upper()]
        ui = _V3_WEIGHTS["UI"][metrics["UI"].upper()]
        scope_changed = metrics["S"].upper() == "C"
        pr_table = _V3_PR_CHANGED if scope_changed else _V3_PR_UNCHANGED
        pr = pr_table[metrics["PR"].upper()]
        c = _V3_WEIGHTS["C"][metrics["C"].upper()]
        i = _V3_WEIGHTS["I"][metrics["I"].upper()]
        a = _V3_WEIGHTS["A"][metrics["A"].upper()]
    except (KeyError, AttributeError):
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _roundup(base)


def compute_v3_subscores(metrics: Dict[str, str]) -> Tuple[Optional[float], Optional[float]]:
    """Return (exploitability_score, impact_score) rounded to 1 dp, or (None,
    None) if incomputable."""
    try:
        av = _V3_WEIGHTS["AV"][metrics["AV"].upper()]
        ac = _V3_WEIGHTS["AC"][metrics["AC"].upper()]
        ui = _V3_WEIGHTS["UI"][metrics["UI"].upper()]
        scope_changed = metrics["S"].upper() == "C"
        pr_table = _V3_PR_CHANGED if scope_changed else _V3_PR_UNCHANGED
        pr = pr_table[metrics["PR"].upper()]
        c = _V3_WEIGHTS["C"][metrics["C"].upper()]
        i = _V3_WEIGHTS["I"][metrics["I"].upper()]
        a = _V3_WEIGHTS["A"][metrics["A"].upper()]
    except (KeyError, AttributeError):
        return None, None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)) if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    return round(exploitability, 1), round(max(impact, 0.0), 1)


# ---------------- public API ----------------

def parse_vector(vector: str, *, source: str = "", provided_score: Optional[float] = None) -> Optional[CVSSScore]:
    """Parse a CVSS vector into a fully-decoded :class:`CVSSScore`.

    ``provided_score`` — if the source gave a numeric score, pass it: it wins
    the ``base_score`` slot and we do NOT recompute. When it is None and the
    version is v3.x, we compute the base score from the vector (filling a gap,
    per the module docstring). For v2/v4 with no provided score we leave the
    score None rather than guess.
    """
    version = detect_version(vector)
    if version is None:
        return None
    metrics = _split_metrics(vector)

    if version.startswith("3"):
        labels = _decode_v3(metrics)
        score = provided_score
        expl = imp = None
        if score is None:
            score = compute_v3_base_score(metrics)
        expl, imp = compute_v3_subscores(metrics)
    elif version.startswith("4"):
        labels = _decode_v4(metrics)
        score = provided_score  # not computed for v4
        expl = imp = None
    else:  # v2
        labels = _decode_v2(metrics)
        score = provided_score  # v2 base formula intentionally not computed here
        expl = imp = None

    severity = Severity.from_cvss_score(score, version=version) if score is not None else Severity.UNKNOWN

    return CVSSScore(
        version=version,
        base_score=round(score, 1) if score is not None else None,
        base_severity=severity.value,
        vector=vector.strip(),
        source=source,
        exploitability_score=expl,
        impact_score=imp,
        **labels,
    )


def build_score(
    *,
    version: str,
    base_score: Optional[float],
    vector: str = "",
    source: str = "",
    severity: str = "",
) -> CVSSScore:
    """Construct a CVSSScore from a source that gave a score (and maybe a
    vector) directly. Decodes the vector for labels when present; never
    computes or overrides the given score."""
    if vector:
        parsed = parse_vector(vector, source=source, provided_score=base_score)
        if parsed is not None:
            if severity:
                parsed.base_severity = severity.upper()
            elif base_score is not None:
                parsed.base_severity = Severity.from_cvss_score(
                    base_score, version=parsed.version).value
            return parsed
    sev = (severity.upper() if severity
           else Severity.from_cvss_score(base_score, version=version or "3.1").value)
    return CVSSScore(
        version=version or "3.1",
        base_score=round(base_score, 1) if base_score is not None else None,
        base_severity=sev,
        vector=vector,
        source=source,
    )


def pick_primary(scores: List[CVSSScore]) -> Optional[CVSSScore]:
    """Choose the CVSS score to display: newest spec version first, then a
    present numeric score, then a present vector. Returns None for empty."""
    if not scores:
        return None
    version_rank = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}

    def key(s: CVSSScore):
        return (
            version_rank.get(s.version, 0),
            1 if s.base_score is not None else 0,
            1 if s.vector else 0,
            s.base_score or 0.0,
        )

    return max(scores, key=key)


def explain(score: CVSSScore) -> List[str]:
    """A list of human-readable Thai/English lines explaining the metrics, for
    the Telegram detail view and the AI prompt context."""
    if score is None:
        return []
    lines: List[str] = []
    head = f"CVSS {score.version}"
    if score.base_score is not None:
        head += f": {score.base_score}"
    if score.base_severity and score.base_severity != Severity.UNKNOWN.value:
        head += f" ({score.base_severity})"
    lines.append(head)
    pairs = [
        ("Attack Vector", score.attack_vector),
        ("Attack Complexity", score.attack_complexity),
        ("Privileges Required", score.privileges_required),
        ("User Interaction", score.user_interaction),
        ("Scope", score.scope),
        ("Confidentiality", score.confidentiality),
        ("Integrity", score.integrity),
        ("Availability", score.availability),
    ]
    for label, value in pairs:
        if value:
            lines.append(f"{label}: {value}")
    return lines
