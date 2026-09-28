"""
blueteam/challenge.py — HMAC-signed verification challenges for Join Guard.

A new member is asked to prove they are human by tapping the correct button. The
button's ``callback_data`` must be safe against three attacks (กติกา):

  * **tampering** — the payload is signed with HMAC-SHA256 over
    ``(chat_id, user_id, nonce, choice)``; a forged or edited payload fails the
    constant-time signature check.
  * **replay** — a random per-challenge ``nonce`` plus server-side state
    (``bt_challenge``: status/expiry/attempts) means a captured payload cannot be
    reused once the challenge is PASSED/FAILED/EXPIRED.
  * **someone else tapping** — ``user_id`` is bound into the signature, and the
    verifier compares it to the *authenticated* presser (``callback_query.from_user``),
    so B tapping A's button fails both the signature and the state lookup.

``callback_data`` stays well under Telegram's 64-byte limit (~30 bytes): the large
chat/user ids live only inside the HMAC, not in the payload.

Pure/stdlib (``hmac``, ``hashlib``, ``secrets``) — no Telegram import; the caller
wires it to buttons and the store.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

_PREFIX = "bt1"
_SIG_BYTES = 12                      # 96-bit truncated HMAC -> 16 base64url chars
_NONCE_HEX = 8                       # 32-bit nonce reference


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sign(secret: str, chat_id: int, user_id: int, nonce: str, choice: str) -> str:
    msg = f"{chat_id}:{user_id}:{nonce}:{choice}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return _b64(digest[:_SIG_BYTES])


def make_callback(secret: str, chat_id: int, user_id: int, nonce: str,
                  choice: str) -> str:
    """Build a signed callback_data string (<=64 bytes)."""
    data = f"{_PREFIX}:{choice}:{nonce}:{_sign(secret, chat_id, user_id, nonce, choice)}"
    # Hard guarantee we never exceed Telegram's limit.
    return data[:64]


def verify_callback(secret: str, chat_id: int, user_id: int,
                    callback_data: str) -> Tuple[bool, str, str]:
    """Verify a callback payload's signature. Returns (valid, choice, nonce).

    This checks INTEGRITY only (tamper + binding to this chat/user). Freshness
    (expiry / attempts / one-time use) is enforced by the caller against the
    ``bt_challenge`` store row.
    """
    if not callback_data or not callback_data.startswith(_PREFIX + ":"):
        return False, "", ""
    parts = callback_data.split(":")
    if len(parts) != 4:
        return False, "", ""
    _, choice, nonce, sig = parts
    expected = _sign(secret, chat_id, user_id, nonce, choice)
    if not hmac.compare_digest(sig, expected):
        return False, "", ""
    return True, choice, nonce


# ---------------- challenge content ----------------

_EMOJI_POOL = ["🍎", "🚗", "⚽", "🌵", "🎸", "🐬", "🍔", "🚀", "🌙", "🔑",
               "🐱", "🌈", "⛄", "🎈", "🍩", "🧩"]


@dataclass(slots=True)
class Challenge:
    nonce: str
    answer: str                      # the correct choice token
    prompt_emoji: str                # emoji the user is asked to tap
    choices: List[Tuple[str, str]] = field(default_factory=list)  # (label, choice_token)
    ttl_seconds: int = 120

    def buttons(self, secret: str, chat_id: int, user_id: int) -> List[Tuple[str, str]]:
        """Return [(label, callback_data), ...] ready for an inline keyboard."""
        return [(label, make_callback(secret, chat_id, user_id, self.nonce, tok))
                for (label, tok) in self.choices]


def build_challenge(*, ttl_seconds: int = 120, num_choices: int = 4,
                    rng: Optional[secrets.SystemRandom] = None) -> Challenge:
    """Build an emoji-pick challenge. The user is shown a target emoji and must tap
    the matching button among ``num_choices``. Simple for a human, and — combined
    with the HMAC binding and time limit — effective against drive-by bot joins."""
    rand = rng or secrets.SystemRandom()
    pool = rand.sample(_EMOJI_POOL, k=min(num_choices, len(_EMOJI_POOL)))
    answer_emoji = rand.choice(pool)
    nonce = secrets.token_hex(_NONCE_HEX // 2)
    choices = [(emoji, str(i)) for i, emoji in enumerate(pool)]
    answer_tok = next(tok for (emoji, tok) in choices if emoji == answer_emoji)
    return Challenge(nonce=nonce, answer=answer_tok, prompt_emoji=answer_emoji,
                     choices=choices, ttl_seconds=ttl_seconds)
