"""
threat_actor_intelligence.reports.csv_report — dossier → CSV tables.

A dossier is multi-section, so this renders a *set* of flat CSV tables (one per
useful section) that analysts load into a spreadsheet or SIEM. ``render`` returns
the evidence table by default (the most reused); ``render_all`` returns a dict of
named CSV strings. Pure stdlib ``csv``.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List


def _rows_to_csv(header: List[str], rows: List[List[Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(["" if c is None else c for c in r])
    return buf.getvalue()


def evidence_csv(dossier: Dict[str, Any]) -> str:
    rows = [[e.get("provider", ""), e.get("source_class", ""),
             e.get("title", ""), e.get("external_id", ""),
             e.get("observed_at", ""), e.get("source_url", ""),
             e.get("weight", "")] for e in dossier.get("evidence", [])]
    return _rows_to_csv(
        ["provider", "source_class", "title", "external_id", "observed_at",
         "source_url", "weight"], rows)


def ioc_csv(dossier: Dict[str, Any]) -> str:
    rows = [[i.get("type", ""), i.get("value", ""), i.get("defanged", ""),
             i.get("malware", ""), i.get("campaign", ""), i.get("actor", "")]
            for i in dossier.get("iocs", [])]
    return _rows_to_csv(["type", "value", "defanged", "malware", "campaign",
                         "actor"], rows)


def relationships_csv(dossier: Dict[str, Any]) -> str:
    rows = [[r.get("src_type", ""), r.get("src_id", ""), r.get("rel_type", ""),
             r.get("dst_type", ""), r.get("dst_id", ""), r.get("weight", ""),
             r.get("signal", "")] for r in dossier.get("relationships", [])]
    return _rows_to_csv(["src_type", "src_id", "rel_type", "dst_type", "dst_id",
                         "weight", "signal"], rows)


def aliases_csv(dossier: Dict[str, Any]) -> str:
    rows = [[a.get("name", ""), a.get("kind", ""), a.get("source", "")]
            for a in dossier.get("aliases", [])]
    return _rows_to_csv(["name", "kind", "source"], rows)


def render(dossier: Dict[str, Any]) -> str:
    return evidence_csv(dossier)


def render_all(dossier: Dict[str, Any]) -> Dict[str, str]:
    out = {"evidence": evidence_csv(dossier),
           "aliases": aliases_csv(dossier),
           "relationships": relationships_csv(dossier)}
    if dossier.get("iocs"):
        out["iocs"] = ioc_csv(dossier)
    return out


__all__ = ["render", "render_all", "evidence_csv", "ioc_csv", "relationships_csv",
           "aliases_csv"]
