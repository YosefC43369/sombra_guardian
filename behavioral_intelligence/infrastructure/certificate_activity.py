"""
behavioral_intelligence.infrastructure.certificate_activity — public certificate
reference behaviour (spec §26 certificate IOCs).

Tracks references to TLS certificates in public content — SHA-1/SHA-256
fingerprints and certificate subjects/SANs carried in observation metadata (e.g.
from a crt.sh-style provider). Reports when a fingerprint first/last appeared and
the domains it is associated with. Where ``entity_fusion``'s certificate engine
is importable it can be consulted for correlation; the import is defensive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation

try:  # pragma: no cover - optional integration
    from entity_fusion.engines import certificate_engine as _cert_engine
    HAVE_CERT_ENGINE = True
except Exception:  # pragma: no cover
    _cert_engine = None  # type: ignore[assignment]
    HAVE_CERT_ENGINE = False

_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


@dataclass
class CertificateActivity:
    fingerprint: str = ""
    algorithm: str = ""            # sha1 | sha256
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    associated_domains: List[str] = field(default_factory=list)
    subjects: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"fingerprint": self.fingerprint, "algorithm": self.algorithm,
                "frequency": self.frequency, "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "associated_domains": self.associated_domains,
                "subjects": self.subjects}


def _fingerprints(o: Observation) -> List[tuple]:
    out: List[tuple] = []
    text = o.text or ""
    for fp in _SHA256_RE.findall(text):
        out.append(("sha256", fp.lower()))
    for fp in _SHA1_RE.findall(text):
        out.append(("sha1", fp.lower()))
    for cert in o.metadata.get("certificates", []) or []:
        if isinstance(cert, dict) and cert.get("fingerprint"):
            fp = str(cert["fingerprint"]).lower()
            algo = "sha256" if len(fp) == 64 else "sha1"
            out.append((algo, fp))
    return out


def analyze_certificate_activity(observations: Sequence[Observation], *,
                                 top_n: int = 50) -> List[CertificateActivity]:
    agg: Dict[str, CertificateActivity] = {}
    for o in observations:
        domains = o.all_domains()
        for algo, fp in _fingerprints(o):
            act = agg.get(fp)
            if act is None:
                act = CertificateActivity(fingerprint=fp, algorithm=algo)
                agg[fp] = act
            act.frequency += 1
            if o.has_time:
                act.first_seen = (o.timestamp if act.first_seen == 0
                                  else min(act.first_seen, o.timestamp))
                act.last_seen = max(act.last_seen, o.timestamp)
            for d in domains:
                if d not in act.associated_domains:
                    act.associated_domains.append(d)
            for cert in o.metadata.get("certificates", []) or []:
                if isinstance(cert, dict) and cert.get("subject"):
                    subj = str(cert["subject"])
                    if subj not in act.subjects:
                        act.subjects.append(subj)
    return sorted(agg.values(), key=lambda a: a.frequency, reverse=True)[:top_n]
