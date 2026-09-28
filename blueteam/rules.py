"""
blueteam/rules.py — versioned rule-pack loader with checksum + schema validation.

Rules live as data, not code: ``reference_data/blueteam/*.json`` can be updated to
tune detection without a code change (กติกา: "อัปเดตกฎได้โดยไม่แก้โค้ด"). Each pack
is ``{schema, version, updated, checksum, data}``. The loader:

  * recomputes the SHA-256 over the canonical ``data`` and compares it to the
    declared ``checksum`` (integrity — a silently edited pack is flagged);
  * validates the shape per schema (brands/tld_risk/… each have a checker);
  * **ReDoS-lints** every scam regex (rejects nested quantifiers such as
    ``(a+)+``) and pre-compiles the survivors, so a bad pattern can never hang the
    event loop;
  * supports :meth:`reload` for a ``/…guard rules reload`` admin command.

A missing/corrupt pack degrades to empty rather than raising — detection with
fewer rules is acceptable; a crash is not.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple

from . import textkit

logger = logging.getLogger("modbot.blueteam.rules")

_HERE = os.path.dirname(os.path.abspath(__file__))
_PACK_DIR = os.path.join(os.path.dirname(_HERE), "reference_data", "blueteam")

# Longest input we will run the scam regexes over; caps worst-case regex cost.
MAX_SCAN_CHARS = 4000

# Reject obviously catastrophic-backtracking constructs at load time.
_REDOS_PATTERNS = [
    re.compile(r"\([^)]*[+*]\)[+*]"),          # (x+)+ or (x*)*
    re.compile(r"\([^)]*[+*]\)\{"),            # (x+){n,}
]


@dataclass(slots=True)
class ScamRule:
    id: str
    regex: Pattern
    weight: int
    category: str
    desc: str
    attack: str = "T1566"


@dataclass(slots=True)
class RulePack:
    schema: str
    version: str
    checksum_ok: bool
    data: Any
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": self.schema, "version": self.version,
                "checksum_ok": self.checksum_ok, "source": self.source}


def _canonical_checksum(data: Any) -> str:
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_pack(name: str, pack_dir: str = _PACK_DIR) -> Optional[RulePack]:
    path = os.path.join(pack_dir, name + ".json")
    if not os.path.exists(path):
        logger.info("BLUETEAM RULES | pack not found: %s", name)
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("BLUETEAM RULES | cannot read %s: %s", name, exc)
        return None
    data = doc.get("data")
    declared = doc.get("checksum", "")
    ok = bool(declared) and _canonical_checksum(data) == declared
    if not ok:
        logger.warning("BLUETEAM RULES | checksum mismatch for %s "
                       "(pack edited or corrupt); loading anyway", name)
    return RulePack(schema=doc.get("schema", name), version=doc.get("version", "0"),
                    checksum_ok=ok, data=data, source=path)


def _redos_safe(pattern: str) -> bool:
    return not any(rx.search(pattern) for rx in _REDOS_PATTERNS)


def _compile_scam_rules(items: Any) -> List[ScamRule]:
    rules: List[ScamRule] = []
    if not isinstance(items, list):
        return rules
    for it in items:
        if not isinstance(it, dict) or "pattern" not in it:
            continue
        pat = str(it["pattern"])
        if not _redos_safe(pat):
            logger.warning("BLUETEAM RULES | rejected ReDoS-risky rule %s",
                           it.get("id"))
            continue
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error as exc:
            logger.warning("BLUETEAM RULES | bad regex %s: %s", it.get("id"), exc)
            continue
        rules.append(ScamRule(
            id=str(it.get("id", "")), regex=rx,
            weight=int(it.get("weight", 10)), category=str(it.get("category", "")),
            desc=str(it.get("desc", "")), attack=str(it.get("attack", "T1566"))))
    return rules


class RuleRegistry:
    """Holds all loaded packs and exposes typed accessors. Reloadable."""

    def __init__(self, pack_dir: str = _PACK_DIR):
        self._dir = pack_dir
        self.brands: List[Dict[str, Any]] = []
        self.tld_risk: Dict[str, Dict[str, int]] = {}
        self.shorteners: Set[str] = set()
        self.free_hosting: Set[str] = set()
        self.scam_th: List[ScamRule] = []
        self.scam_en: List[ScamRule] = []
        self._packs: Dict[str, RulePack] = {}
        self.reload()

    def reload(self) -> Dict[str, Any]:
        """(Re)load every pack from disk. Returns a status summary."""
        packs: Dict[str, RulePack] = {}
        for name in ("brands", "tld_risk", "shorteners", "free_hosting",
                     "confusables", "scam_rules_th", "scam_rules_en"):
            p = load_pack(name, self._dir)
            if p is not None:
                packs[name] = p
        self._packs = packs

        self.brands = self._list(packs.get("brands"))
        self.tld_risk = self._dict(packs.get("tld_risk"))
        self.shorteners = set(self._list(packs.get("shorteners")))
        self.free_hosting = set(self._list(packs.get("free_hosting")))
        conf = packs.get("confusables")
        textkit.set_confusables(conf.data if conf and isinstance(conf.data, dict) else None)
        self.scam_th = _compile_scam_rules(packs.get("scam_rules_th").data
                                           if packs.get("scam_rules_th") else [])
        self.scam_en = _compile_scam_rules(packs.get("scam_rules_en").data
                                           if packs.get("scam_rules_en") else [])
        summary = self.status()
        logger.info("BLUETEAM RULES | loaded %s", summary)
        return summary

    @staticmethod
    def _list(pack: Optional[RulePack]) -> List[Any]:
        return pack.data if pack and isinstance(pack.data, list) else []

    @staticmethod
    def _dict(pack: Optional[RulePack]) -> Dict[str, Any]:
        return pack.data if pack and isinstance(pack.data, dict) else {}

    def scam_rules(self, lang: str = "both") -> List[ScamRule]:
        if lang == "th":
            return self.scam_th
        if lang == "en":
            return self.scam_en
        return self.scam_th + self.scam_en

    def tld_weight(self, tld: str) -> Tuple[int, str]:
        """Return (weight, band) for a TLD like '.zip'. 0/'' when unknown."""
        tld = tld.lower()
        if not tld.startswith("."):
            tld = "." + tld
        for band in ("high", "medium", "low"):
            table = self.tld_risk.get(band, {})
            if tld in table:
                return int(table[tld]), band
        return 0, ""

    def status(self) -> Dict[str, Any]:
        return {
            "brands": len(self.brands),
            "tld_risk": sum(len(v) for v in self.tld_risk.values()),
            "shorteners": len(self.shorteners),
            "free_hosting": len(self.free_hosting),
            "scam_th": len(self.scam_th),
            "scam_en": len(self.scam_en),
            "checksums_ok": all(p.checksum_ok for p in self._packs.values()),
            "versions": {n: p.version for n, p in self._packs.items()},
        }


# Process-wide singleton (cheap; packs are small). Reloadable via .reload().
_registry: Optional[RuleRegistry] = None


def get_registry() -> RuleRegistry:
    global _registry
    if _registry is None:
        _registry = RuleRegistry()
    return _registry


def reload_registry() -> Dict[str, Any]:
    return get_registry().reload()
