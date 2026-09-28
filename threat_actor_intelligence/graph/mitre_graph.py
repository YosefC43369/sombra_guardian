"""
threat_actor_intelligence.graph.mitre_graph — ATT&CK coverage graph.

Wires an entity (actor or campaign) to its documented techniques, and each
technique to its tactic column and mitigations, producing the ATT&CK navigator-
style relationship view used in reports and ``/attack`` output.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..mitre.attack_engine import ATTACKEngine
from .base import CTIGraph


class MitreGraphBuilder:
    def __init__(self, attack: Optional[ATTACKEngine] = None):
        self.attack = attack

    def build(self, *, subject_id: str, subject_type: str,
              technique_ids: Sequence[str], subject_label: str = "") -> CTIGraph:
        g = CTIGraph(name=f"mitre:{subject_id}")
        g.add_node(subject_id, subject_type, subject_label or subject_id)
        for tid in technique_ids:
            tech = self.attack.technique(tid) if self.attack else None
            label = tech.name if tech else tid
            g.add_node(tid, "technique", f"{tid} {label}".strip())
            g.add_edge(subject_id, tid, "uses", signal="documented technique",
                       weight=0.5)
            if tech:
                for tactic in tech.tactics:
                    g.add_node(f"tactic:{tactic}", "tactic", tactic)
                    g.add_edge(tid, f"tactic:{tactic}", "subtechnique_of"
                               if tech.is_subtechnique else "associated_with",
                               signal="tactic", weight=0.3)
        return g


__all__ = ["MitreGraphBuilder"]
