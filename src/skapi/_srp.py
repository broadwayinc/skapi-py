"""
Cognito's SRP-6a password sign-in, ported from skapi-js (src/cognito/srp.ts), which is itself a
byte-for-byte port of amazon-cognito-identity-js. Every step, padHex in particular, must give the
same bytes: a wrong padding only fails a sign-in when a value starts with a high bit, about 1 in
256 attempts, so it is easy to miss.

The password never leaves the device: only A (g^a mod N) and a signature made with the derived key
are sent.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone

N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)

N = int(N_HEX, 16)
G = 2

_HEX_MSB = re.compile(r"^[89a-f]", re.IGNORECASE)
_INFO_BITS = b"Caldera Derived Key" + b"\x01"


def hex_to_int(hex_str: str) -> int:
    """Hex string to int, as `new BigInteger(hex, 16)` read it (an empty string is 0)."""
    return int(hex_str, 16) if hex_str else 0


def hex_to_bytes(hex_str: str) -> bytes:
    """Two characters at a time, stopping at the first pair that is not hex, like Buffer.from(hex, 'hex')."""
    out = bytearray()
    for i in range(0, len(hex_str) - 1, 2):
        try:
            out.append(int(hex_str[i:i + 2], 16))
        except ValueError:
            break
    return bytes(out)


def pad_hex(value: int) -> str:
    """
    Signed big-endian hex exactly as the library writes it: even length, a leading "00" when the top
    bit is set (so the value stays positive), and two's complement for a negative value.
    """
    is_negative = value < 0
    hex_str = format(-value if is_negative else value, "x")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    if _HEX_MSB.match(hex_str):
        hex_str = "00" + hex_str
    if is_negative:
        inverted = "".join("0123456789ABCDEF"[~int(c, 16) & 0xF] for c in hex_str)
        hex_str = format(int(inverted, 16) + 1, "x")
        if hex_str.upper().startswith("FF8"):
            hex_str = hex_str[2:]
    return hex_str


def _hash_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex_hash(hex_str: str) -> str:
    return _hash_hex(hex_to_bytes(hex_str))


K = hex_to_int(_hex_hash(pad_hex(N) + pad_hex(G)))


def compute_hkdf(ikm: bytes, salt: bytes) -> bytes:
    """HKDF-SHA256 with Cognito's info string, first 16 bytes."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, _INFO_BITS, hashlib.sha256).digest()[:16]


class SrpHelper:
    def __init__(self, pool_name: str, small_a: int | None = None):
        """
        pool_name: the part of the user pool id after the underscore.
        small_a: for the equivalence checks only, a fixed secret instead of 128 random bytes.
        """
        self.pool_name = pool_name
        # 128 random bytes read as a positive integer; no reduction needed, N is 3072 bits.
        self.small_a = small_a if small_a is not None else int.from_bytes(secrets.token_bytes(128), "big")
        self.large_a = pow(G, self.small_a, N)
        if self.large_a % N == 0:
            raise ValueError("Illegal paramater. A mod N cannot be 0.")

    def get_password_authentication_key(self, username: str, password: str, server_b: int, salt: int) -> bytes:
        """The 16 byte key both sides derive; Cognito checks a signature made with it."""
        if server_b % N == 0:
            raise ValueError("B cannot be zero.")
        u = hex_to_int(_hex_hash(pad_hex(self.large_a) + pad_hex(server_b)))
        if u == 0:
            raise ValueError("U cannot be zero.")
        username_password_hash = _hash_hex(f"{self.pool_name}{username}:{password}".encode("utf-8"))
        x = hex_to_int(_hex_hash(pad_hex(salt) + username_password_hash))
        # S = (B - k * g^x) ^ (a + u * x) mod N. The base can be negative; Python's % gives the
        # residue in [0, N), the same value the library's BigInteger used.
        base = (server_b - K * pow(G, x, N)) % N
        s = pow(base, self.small_a + u * x, N)
        return compute_hkdf(hex_to_bytes(pad_hex(s)), hex_to_bytes(pad_hex(u)))


_WEEK = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_MONTH = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def cognito_timestamp(now: datetime | None = None) -> str:
    """"Sun Nov 15 16:52:00 UTC 2026": the day is not zero padded, the time is."""
    now = now or datetime.now(timezone.utc)
    return (f"{_WEEK[now.weekday()]} {_MONTH[now.month - 1]} {now.day} "
            f"{now.hour:02d}:{now.minute:02d}:{now.second:02d} UTC {now.year}")
