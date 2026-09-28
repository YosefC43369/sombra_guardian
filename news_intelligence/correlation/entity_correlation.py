"""
news_intelligence.correlation.entity_correlation — co-mention entity correlation.

Correlates entities that co-occur across the corpus: which actors are reported
alongside which malware families, which CVEs alongside which vendors, which countries
alongside which actors. Each correlation is evidence-gated (only distinct source
domains count toward corroboration) and carries the articles that support it.

This is the general co-mention engine; ``article_correlation`` links articles,
``infrastructure_correlation`` handles shared IOCs, and the profile builders consume
these edges.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Dict, List, Optional, Tuple

from ..models.article import Article
from ..models.entity import EntityType
from ..models.evidence import EvidenceBundle, EvidenceRef
from .base import BaseCorrelator, NewsRelationship

# which (type-a, type-b) co-mentions produce which relation label
_PAIR_RELATIONS = {
    (EntityType.THREAT_ACTOR, EntityType.MALWARE_FAMILY): "actor_uses_malware",
    (EntityType.THREAT_ACTOR, EntityType.CVE): "actor_linked_cve",
    (EntityType.THREAT_ACTOR, EntityType.COUNTRY): "actor_linked_country",
    (EntityType.THREAT_ACTOR, EntityType.ATTACK_TECHNIQUE): "actor_uses_technique",
    (EntityType.MALWARE_FAMILY, EntityType.CVE): "malware_exploits_cve",
    (EntityType.MALWARE_FAMILY, EntityType.ATTACK_TECHNIQUE): "malware_uses_technique",
    (EntityType.CVE, EntityType.ORGANIZATION): "cve_affects_org",
    (EntityType.MALWARE_FAMILY, EntityType.COUNTRY): "malware_targets_country",
}


def _canon_pair(ta: EntityType, tb: EntityType):
    if (ta, tb) in _PAIR_RELATIONS:
        return (ta, tb), False
    if (tb, ta) in _PAIR_RELATIONS:
        return (tb, ta), True
    return None, False


class EntityCorrelator(BaseCorrelator):
    name = "entity"

    def correlate(self, articles: List[Article]) -> List[NewsRelationship]:
        articles = [a for a in articles if not a.duplicate_of]
        # (rel_type, src_val, dst_val) -> supporting article set
        pairs: Dict[Tuple[str, str, str], List[Article]] = defaultdict(list)
        keys: Dict[Tuple[str, str, str], Tuple[str, str, str, str]] = {}

        for a in articles:
            by_type: Dict[EntityType, List] = defaultdict(list)
            for m in a.entity_mentions:
                by_type[m.entity_type].append(m)
            for (ta, tb), rel in _PAIR_RELATIONS.items():
                for ma in by_type.get(ta, []):
                    for mb in by_type.get(tb, []):
                        k = (rel, ma.value.lower(), mb.value.lower())
                        pairs[k].append(a)
                        keys[k] = (ma.entity_key, ta.value, mb.entity_key, tb.value)

        rels: List[NewsRelationship] = []
        for (rel, sval, dval), arts in pairs.items():
            src_key, src_type, dst_key, dst_type = keys[(rel, sval, dval)]
            bundle = EvidenceBundle()
            for a in arts:
                for ev in a.evidence:
                    bundle.add(EvidenceRef.from_dict(ev))
            conf = self._score(bundle)
            if conf.score < self.min_confidence:
                continue
            rels.append(NewsRelationship(
                src_type=src_type, src_key=src_key, dst_type=dst_type,
                dst_key=dst_key, rel_type=rel,
                signals=[f"co-mention x{len(arts)}"],
                article_ids=[a.article_id for a in arts],
                source_domains=[a.source_domain for a in arts],
                weight=round(conf.score, 4), confidence=conf.to_dict(),
                detail={"src_value": sval, "dst_value": dval}))
        rels.sort(key=lambda r: r.weight, reverse=True)
        return rels


__all__ = ["EntityCorrelator"]
