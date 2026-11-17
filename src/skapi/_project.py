"""Project IDs: the compact form shown on skapi.com, and the service id and owner id inside it."""

from __future__ import annotations

import re
from typing import Tuple

from .errors import SkapiError

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
REGION_ALPHABET = "0123456789abcdefghijkl"  # 22 characters, not base62 order past the digits
REGION_KEYS = ["us31", "us72", "ap51", "ap22", "ap41", "eu71", "ap21", "us32", "us71",
               "af51", "ap31", "ap43", "ap23", "ap42", "ca01", "eu01", "eu72", "eu51",
               "eu73", "eu11", "me51", "sa31"]

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _b62_to_int(text: str) -> int:
    n = 0
    for ch in text:
        n = n * 62 + BASE62.index(ch)
    return n


def _int_to_b62(n: int) -> str:
    if n == 0:
        return "0"
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = BASE62[r] + out
    return out


def _decompress(token: str) -> str:
    parts = token.split("-")
    if len(parts) != 2:
        return token
    part1, part2 = parts
    length = BASE62.index(part1[0])
    c = part1[1:]
    moved_middle = c[len(c) - (length + 2):]
    moved_first = c[:len(c) - (length + 2)]
    second = moved_middle[:length]
    first = moved_middle[length:] + moved_first
    h = format(_b62_to_int(part2), "032x")
    uuid = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    return f"{first}-{second}-{uuid}"


def decode_project_id(project_id: str) -> Tuple[str, str]:
    """(service, owner) from a Project ID, compact ("5g8N...-7Zd6...") or long (7 parts)."""
    try:
        long_id = _decompress(project_id.strip())
        p = long_id.split("-")
        if len(p) != 7:
            raise ValueError
        region = REGION_KEYS[REGION_ALPHABET.index(p[1][0])]
        service = region + p[0] + p[1][1:]
        owner = "-".join(p[2:])
        if not _UUID.match(owner):
            raise ValueError
        return service, owner
    except (ValueError, IndexError):
        raise SkapiError("Project ID is invalid.", "INVALID_PARAMETER") from None


def format_project_id(service: str, owner: str) -> str:
    """The compact Project ID of a service id and owner id: the inverse of decode_project_id."""
    first = service[4:-4]
    second = REGION_ALPHABET[REGION_KEYS.index(service[:4])] + service[-4:]
    part1 = BASE62[len(second)] + first[2:] + second + first[:2]
    part2 = _int_to_b62(int(owner.replace("-", ""), 16))
    return f"{part1}-{part2}"


def is_project_id(text: str) -> bool:
    return isinstance(text, str) and len(text.split("-")) in (2, 7)


def is_user_id(text: str) -> bool:
    return isinstance(text, str) and bool(_UUID.match(text))
