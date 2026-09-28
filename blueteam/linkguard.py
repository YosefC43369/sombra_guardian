"""
blueteam/linkguard.py — Link Guard analysis (tiers 1–2 synchronous, tier 3 deferred).

Turns an :class:`~blueteam.urlkit.ExtractedURL` into an explainable
:class:`~blueteam.models.Assessment`. Every signal states the fact it saw and adds
a weight; the score is only a triage ordering.

Tiers
-----
* **Tier 1 (offline, no network)** — lexical features (length/entropy/digit ratio/
  subdomain depth/phishy keywords), brand impersonation (confusable skeleton +
  Damerau-Levenshtein against the brand pack), risky TLD, URL shortener, abused
  free-hosting, obfuscation tells, dangerous scheme, punycode/mixed-script host,
  raw-IP host, and the killer signal: a ``text_link`` whose shown domain differs
  from its href.
* **Tier 2 (reputation)** — per-group allow/deny and public blocklist feeds.
  Allow short-circuits to SAFE; deny/feed force a high score.
* **Tier 3 (deferred)** — the SSRF-guarded active probe runs in the background and
  its signals are merged in later via :meth:`merge_probe`.

Tiers 1–2 are pure/in-memory and meet the <5 ms budget; the analyzer is designed to
run inside the message handler path.
"""

from __future__ import annotations

import math
import re
from typing import List, Optional, Tuple

from .models import Assessment, Signal, Verdict
from .reputation import ReputationChecker, RepVerdict
from .rules import RuleRegistry, get_registry
from .urlkit import ExtractedURL, extract_urls, etld1, host_scripts

# Phishy path/query keywords (Thai + English). Kept as a set for O(1) membership.
_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "confirm", "wallet", "claim", "airdrop", "bonus", "gift", "prize", "unlock",
    "recover", "password", "otp", "bank", "payment", "billing", "invoice",
    "ยืนยัน", "เข้าสู่ระบบ", "รับเงิน", "รับรางวัל", "กระเป๋า", "ธนาคาร",
}
_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in _KEYWORDS), re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class LinkGuard:
    def __init__(self, store=None, registry: Optional[RuleRegistry] = None):
        self._registry = registry or get_registry()
        self._store = store
        self._reputation = ReputationChecker(store) if store is not None else None

    # ---- top-level: analyse every URL in a message ----------------------
    def analyze_message(self, chat_id: int, text: str,
                        entities: Optional[list] = None
                        ) -> List[Tuple[ExtractedURL, Assessment]]:
        out = []
        for eu in extract_urls(text or "", entities):
            out.append((eu, self.analyze(chat_id, eu)))
        return out

    def worst(self, results: List[Tuple[ExtractedURL, Assessment]]
              ) -> Optional[Tuple[ExtractedURL, Assessment]]:
        if not results:
            return None
        return max(results, key=lambda r: r[1].score)

    # ---- analyse one URL (tiers 1 + 2) ----------------------------------
    def analyze(self, chat_id: Optional[int], eu: ExtractedURL) -> Assessment:
        a = Assessment("linkguard", subject=eu.key,
                       meta={"url": eu.url, "defanged": eu.defanged(),
                             "host": eu.host})

        # Tier 2 first: an explicit allow short-circuits everything to SAFE.
        if self._reputation is not None and chat_id is not None:
            rep = self._reputation.check(chat_id, eu)
            if rep.verdict == RepVerdict.ALLOW:
                a.meta["allow_listed"] = True
                return a  # score 0 / SAFE
            if rep.verdict == RepVerdict.DENY:
                a.add(Signal("deny_listed", 100, "reputation", rep.detail, "T1566"))
                return a
            if rep.verdict == RepVerdict.FEED:
                a.add(Signal("blocklist_feed", 70, "reputation", rep.detail, "T1566"))

        # Tier 1 lexical / structural signals -----------------------------
        self._brand_signal(a, eu)
        self._structural_signals(a, eu)
        self._lexical_signals(a, eu)
        return a

    # ---- tier 3 merge (deferred probe) ----------------------------------
    def merge_probe(self, assessment: Assessment, probe_result) -> Assessment:
        for sig in getattr(probe_result, "signals", []):
            assessment.add(sig)
        assessment.meta["probe"] = probe_result.to_dict() if probe_result else None
        return assessment

    # ---- individual signal groups ---------------------------------------
    def _brand_signal(self, a: Assessment, eu: ExtractedURL) -> None:
        from . import textkit as tk
        host = eu.ascii_host or eu.host
        if not host or eu.host_type in ("ipv4", "ipv6", "scheme"):
            return
        reg = eu.etld1 or etld1(host)
        host_skel = tk.skeleton(host)
        for brand in self._registry.brands:
            legit = set(brand.get("domains", []))
            if reg in legit:
                return  # exact legit brand domain -> stop, it's the real thing
            for skel in brand.get("skeletons", []):
                if not skel:
                    continue
                # (a) brand skeleton appears inside a non-legit host skeleton
                if skel in host_skel and reg not in legit:
                    a.add(Signal(
                        "brand_impersonation", 45, "impersonation",
                        f"โฮสต์ {eu.host} เลียนแบบแบรนด์ {brand['name']} "
                        f"แต่ไม่ใช่โดเมนจริง", "T1566.002",
                    ))
                    return
                # (b) a host label is a near-miss of the brand (typosquat)
                for label in host_skel.replace("/", ".").split("."):
                    if not label:
                        continue
                    dist = tk.damerau_levenshtein(label, skel, max_distance=2)
                    if 0 < dist <= 2 and len(skel) >= 4:
                        a.add(Signal(
                            "brand_typosquat", 40, "impersonation",
                            f"โฮสต์ {eu.host} ใกล้เคียงแบรนด์ {brand['name']} "
                            f"(ระยะแก้ไข {dist})", "T1566.002",
                        ))
                        return

    def _structural_signals(self, a: Assessment, eu: ExtractedURL) -> None:
        # text_link display/href mismatch — highest-value phishing tell
        if eu.href_mismatch:
            a.add(Signal(
                "text_link_mismatch", 45, "deception",
                f"ข้อความแสดง {eu.meta.get('shown_domain','?')} แต่ลิงก์ไป "
                f"{eu.meta.get('href_domain','?')}", "T1566.002"))
        # dangerous scheme
        if eu.is_dangerous_scheme:
            a.add(Signal("dangerous_scheme", 45, "scheme",
                         f"ใช้ scheme อันตราย {eu.scheme}:", "T1204"))
            return
        # obfuscation tells
        obf = set(eu.obfuscations)
        if "ip_obfuscated" in obf:
            a.add(Signal("ip_obfuscated", 30, "obfuscation",
                         "ซ่อน IP ปลายทางเป็นเลขฐานสิบ/ฐานสิบหก"))
        if eu.host_type in ("ipv4", "ipv6"):
            a.add(Signal("raw_ip_host", 18, "structural",
                         "ลิงก์ชี้ไปที่ IP โดยตรงแทนชื่อโดเมน"))
        if "userinfo_at_host" in obf:
            a.add(Signal("userinfo_trick", 20, "obfuscation",
                         "ใช้ user@host เพื่อพรางโดเมนจริง"))
        if "zero_width" in obf or any(o.startswith("obfuscation:") for o in obf) \
                or "spaced_dots" in obf:
            a.add(Signal("url_obfuscation", 15, "obfuscation",
                         "พราง URL (hxxp/[.]/zero-width/เว้นวรรค)"))
        # punycode / mixed script host
        if eu.host_type == "punycode":
            a.add(Signal("punycode_host", 15, "structural",
                         "โฮสต์เป็น punycode (อาจเลียนแบบด้วยอักษรต่างภาษา)"))
        scripts = host_scripts(eu.host)
        if len(scripts) > 1 and "LATIN" in scripts:
            a.add(Signal("mixed_script_host", 30, "impersonation",
                         f"โฮสต์ผสมหลายชุดอักษร {sorted(scripts)} (homograph)",
                         "T1036"))

    def _lexical_signals(self, a: Assessment, eu: ExtractedURL) -> None:
        host = eu.ascii_host or eu.host
        reg = eu.etld1 or etld1(host)
        path = (eu.path or "") + " " + (eu.raw or "")

        # risky TLD
        if reg and "." in reg:
            tld = "." + reg.rsplit(".", 1)[1]
            weight, band = self._registry.tld_weight(tld)
            if weight > 0 and band in ("high", "medium"):
                a.add(Signal("risky_tld", weight, "lexical",
                             f"TLD {tld} มีความเสี่ยง ({band})"))
        # URL shortener
        if reg in self._registry.shorteners:
            a.add(Signal("url_shortener", 15, "lexical",
                         f"ใช้ตัวย่อลิงก์ {reg} (ปลายทางถูกซ่อน)", "T1204"))
        # abused free hosting
        for suffix in self._registry.free_hosting:
            if host == suffix or host.endswith("." + suffix):
                a.add(Signal("free_hosting", 15, "lexical",
                             f"โฮสต์บนบริการฟรี {suffix} ที่มักถูกใช้ฟิชชิง"))
                break
        # phishy keywords
        kw = set(m.group(0).lower() for m in _KEYWORD_RE.finditer(path))
        if kw:
            # 1 keyword stays low (benign paths like /account/login), but multiple
            # phishy keywords together are a strong tell and should cross bands.
            weight = min(24, 6 + 5 * len(kw))
            a.add(Signal("phishy_keywords", weight, "lexical",
                         f"พบคำล่อลวงในลิงก์: {', '.join(sorted(kw))}", "T1566.002"))
        # subdomain depth
        depth = host.count(".")
        if depth >= 4:
            a.add(Signal("deep_subdomain", 12, "lexical",
                         f"ซับโดเมนซ้อนลึกผิดปกติ ({depth} ระดับ)"))
        # host entropy / digit ratio (DGA-ish)
        label = host.split(".")[0] if host else ""
        if len(label) >= 12:
            ent = _shannon_entropy(label)
            digits = sum(c.isdigit() for c in label)
            if ent >= 3.6:
                a.add(Signal("high_entropy_host", 12, "lexical",
                             f"ชื่อโฮสต์สุ่มผิดปกติ (entropy {ent:.1f})"))
            if digits / max(len(label), 1) >= 0.4:
                a.add(Signal("digit_heavy_host", 10, "lexical",
                             "ชื่อโฮสต์มีตัวเลขหนาแน่นผิดปกติ"))
