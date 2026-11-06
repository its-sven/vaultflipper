# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""TOTP secrets: bring Bitwarden's formats into the one the Flipper reads.

Bitwarden stores a bare base32 secret, an ``otpauth://totp/...`` URI or
``steam://SECRET``. The Flipper gets ``ALGO:DIGITS:PERIOD:BASE32`` (see
flipper/vaultflipper/vf_totp.h).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from urllib.parse import parse_qs, unquote, urlparse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"
MAX_KEY = 64  # bytes, VF_TOTP_MAX_KEY


def _secret(raw: str) -> str | None:
    s = unquote(raw).replace(" ", "").replace("-", "").rstrip("=").upper()
    if not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in s):
        return None
    try:
        key = base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:
        return None
    return s if 0 < len(key) <= MAX_KEY else None


def normalize(raw: str) -> str | None:
    """Canonical form for the Flipper, or None if the secret cannot be used."""
    raw = (raw or "").strip()
    if not raw:
        return None
    low = raw.lower()
    if low.startswith("steam://"):
        secret = _secret(raw[8:])
        return f"STEAM:5:30:{secret}" if secret else None
    if low.startswith("otpauth://"):
        # split by hand: a "#" in the label would turn the query into a fragment
        head, _sep, query = raw.partition("?")
        kind = urlparse(head).netloc.lower()
        if kind not in ("totp", "steam"):
            return None  # HOTP (counter based) cannot work offline
        q = {k.lower(): v[0] for k, v in parse_qs(query.split("#")[0]).items()}
        secret = _secret(q.get("secret", ""))
        algo = q.get("algorithm", "SHA1").upper().replace("-", "")
        issuer = q.get("issuer", "").lower()
        try:
            digits = int(q.get("digits", "6"))
            period = int(q.get("period", "30"))
        except ValueError:
            return None
        if kind == "steam" or q.get("encoder", "").lower() == "steam" or (issuer == "steam" and digits == 5):
            algo, digits = "STEAM", 5
        if not secret or (algo not in ALGORITHMS and algo != "STEAM") or not 1 <= digits <= 10 or not 1 <= period <= 3600:
            return None
        return f"{algo}:{digits}:{period}:{secret}"
    secret = _secret(raw)
    return f"SHA1:6:30:{secret}" if secret else None


def code(canonical: str, unix_time: int) -> str:
    """The code the Flipper shows - used by the tests."""
    algo, digits, period, secret = canonical.split(":")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", unix_time // int(period)), ALGORITHMS.get(algo, hashlib.sha1)).digest()
    off = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    if algo == "STEAM":
        out = ""
        for _i in range(int(digits)):
            out += STEAM_ALPHABET[value % 26]
            value //= 26
        return out
    return str(value % 10 ** int(digits)).zfill(int(digits))
