"""
entity_fusion.engines.crypto_engine — detect and format-validate public crypto
addresses embedded in profiles, bios and contact pages.

SCOPE. This engine recognises and *format-validates* addresses only (charset,
length, prefix, and a base58/bech32 structural check). It performs NO chain
queries, balance lookups, or wallet clustering — a shared address is treated as
a correlation signal (two profiles publishing the same donation address), which
is exactly the public-footprint use the fusion engine is for. "Only public
address metadata; never query private wallets" (per the module spec).

Supported: Bitcoin (P2PKH/P2SH/bech32), Ethereum & EVM chains (Polygon,
Avalanche C-chain — same 20-byte hex address), Solana, Litecoin, Tron, Monero
(format only). Pure stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from ..entity import Entity, EntityType, Evidence, SourceRef
from .base import CorrelationEngine, EngineResult

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_SET = set(_B58_ALPHABET)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _is_base58(s: str) -> bool:
    return bool(s) and all(c in _B58_SET for c in s)


def _b58_decode_len(s: str) -> int:
    """Decode base58 to a byte length (for structural validation of BTC/LTC
    P2PKH/P2SH: version+20-byte hash+4-byte checksum = 25 bytes)."""
    num = 0
    for c in s:
        num = num * 58 + _B58_ALPHABET.index(c)
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return pad + len(full)


def _valid_p2pkh_p2sh(s: str) -> bool:
    return _is_base58(s) and 25 <= _b58_decode_len(s) <= 26


def _valid_bech32(s: str, hrp: str) -> bool:
    s = s.lower()
    if not s.startswith(hrp + "1"):
        return False
    data = s[len(hrp) + 1:]
    return bool(data) and all(c in _BECH32_CHARSET for c in data) and 6 <= len(data) <= 71


@dataclass
class CryptoMatch:
    chain: str
    address: str

    def to_dict(self):
        return {"chain": self.chain, "address": self.address}


# Detectors ordered most-specific first. Each returns a chain name or None.
def _detect(addr: str) -> Optional[str]:
    a = addr.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        return "ethereum"          # also Polygon / Avalanche C-chain / BSC (same format)
    if re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", a) and _is_base58(a[1:]):
        return "tron"
    if re.fullmatch(r"(bc1)[0-9ac-hj-np-z]{6,71}", a.lower()) and _valid_bech32(a, "bc"):
        return "bitcoin"
    if re.fullmatch(r"(ltc1)[0-9ac-hj-np-z]{6,71}", a.lower()) and _valid_bech32(a, "ltc"):
        return "litecoin"
    if a[:1] in ("1", "3") and _valid_p2pkh_p2sh(a):
        return "bitcoin"
    if a[:1] in ("L", "M") and _valid_p2pkh_p2sh(a):
        return "litecoin"
    if a[:1] in ("4", "8") and re.fullmatch(r"[48][0-9A-Za-z]{94}", a):
        return "monero"            # format-only (length + prefix); no checksum here
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", a) and _is_base58(a):
        return "solana"
    return None


def detect_addresses(text: str) -> List[CryptoMatch]:
    """Extract candidate crypto addresses from free text, format-validated and
    de-duplicated. Tokenises on whitespace and common punctuation."""
    if not text:
        return []
    seen = set()
    out: List[CryptoMatch] = []
    for token in re.split(r"[\s,;<>()\[\]\"']+", text):
        token = token.strip().rstrip(".")
        if len(token) < 26 or len(token) > 128:
            continue
        chain = _detect(token)
        if chain and token not in seen:
            seen.add(token)
            out.append(CryptoMatch(chain, token))
    return out


def classify_address(addr: str) -> Optional[str]:
    """Public helper: the chain of a single address, or None if not recognised."""
    return _detect(addr.strip())


class CryptoEngine(CorrelationEngine):
    name = "crypto_engine"
    handles = (EntityType.WALLET,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        chain = classify_address(entity.value)
        if not chain:
            result.evidence.append(Evidence(
                kind="wallet_unrecognized", value=entity.value, weight=-0.1,
                note="address did not match any supported chain format"))
            return result
        result.derived["chain"] = chain
        result.derived["wallet"] = entity.value.strip()
        entity.normalized = (entity.value.strip().lower()
                             if chain in ("ethereum",) else entity.value.strip())
        result.evidence.append(Evidence(
            kind="wallet", value=entity.value.strip(), weight=0.0,
            note=f"format-valid {chain} address"))
        return result


class BioWalletExtractor(CorrelationEngine):
    """Extract crypto addresses embedded in a profile's text as discovered
    wallet entities linked back to the source."""

    name = "bio_wallet_extractor"
    handles = ()

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        text = " ".join(str(entity.metadata.get(k, "")) for k in
                        ("bio", "description", "about", "donate", "wallet"))
        for match in detect_addresses(text):
            child = Entity(type=EntityType.WALLET, value=match.address)
            child.metadata["chain"] = match.chain
            child.add_source(SourceRef(provider=f"bio:{entity.type.value}",
                                       detail="extracted from profile text"))
            result.entities.append(child)
        return result
