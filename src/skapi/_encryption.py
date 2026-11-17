"""
Client-side record encryption, ported byte for byte from skapi-js (src/utils/crypto.ts,
src/methods/encryption.ts), so records and files sealed by either SDK open in the other.

Only `record.data` of PRIVATE records is sealed, with a per-record key (DEK). The DEK is wrapped
for the owner under a master key (MK) that only the user's password (or encryption recovery code) opens, and
for each user the record is shared with through ECDH P-256. The MK lives in a keyring record in the
reserved table "__skapi__keyring". Needs the `cryptography` package: pip install "skapi[encryption]".
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import time
import unicodedata
import warnings
from typing import Any, Dict, List, Optional, Tuple

from .errors import SkapiError

ENC_V = "skapi.enc.v1"
PBKDF2_ITERATIONS = 600000
ENV_MARKER = "__skapi_enc__"
WITHHELD = "__skapi_no_access__"
SPILL_LIMIT = 256 * 1024
CT_KEY = "__skenc_ct__"
CT_FILE = "payload.bin"
CT_FILE_SUFFIX = f"/{CT_KEY}/{CT_FILE}"
FILE_MARKER = "__skenc__"
FILE_CHUNK = 4 * 1024 * 1024
ENVELOPE_CAP = 2 * 1024 * 1024
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _err(message: str, code: str) -> SkapiError:
    return SkapiError(message, code)


# ---- crypto-free helpers (used with encryption off too) ------------------------------------------

def is_envelope(v: Any) -> bool:
    return (isinstance(v, dict) and isinstance(v.get(ENV_MARKER), (int, float)) and not isinstance(v.get(ENV_MARKER), bool)
            and all(isinstance(v.get(k), str) for k in ("ct", "iv", "own", "anch")) and isinstance(v.get("k"), dict))


def b62(n: int) -> str:
    if n == 0:
        return "0"
    out = ""
    while n > 0:
        n, r = divmod(n, 62)
        out = B62[r] + out
    return out


def from_b62_strict(s: str) -> Optional[int]:
    if not s:
        return None
    n = 0
    for ch in s:
        i = B62.find(ch)
        if i < 0:
            return None
        n = n * 62 + i
    return n


def parse_file_marker(path_key: str) -> Optional[Tuple[str, int]]:
    """'<form key>__skenc__<b62 plain size>' -> (form key, plain size), else None."""
    i = path_key.rfind(FILE_MARKER)
    if i < 0:
        return None
    size = from_b62_strict(path_key[i + len(FILE_MARKER):])
    return None if size is None else (path_key[:i], size)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64u_dec(s: Any) -> bytes:
    if not isinstance(s, str):
        raise _err("Expected a base64url string.", "INVALID_PARAMETER")
    if len(s) % 4 == 1:
        raise _err("Malformed base64url string.", "INVALID_PARAMETER")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def utf8(s: str) -> bytes:
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:  # TextEncoder writes a lone surrogate as U+FFFD
        return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def utf8_dec(b: bytes) -> str:
    s = b.decode("utf-8", "replace")
    return s[1:] if s.startswith("﻿") else s


def _js_json(v: Any) -> str:
    from ._http import js_json
    return js_json(v)


def check_bits(raw: bytes) -> int:
    """skapi-js's recovery code check: FNV-1a as JavaScript computes it (signed XOR, double multiply)."""
    h = 0x811c9dc5
    for b in raw:
        x = h ^ b
        if x >= 2 ** 31:
            x -= 2 ** 32
        h = int(float(x) * 16777619.0) % 2 ** 32
    return h & 0x3ff


def encode_recovery_code(raw: bytes) -> str:
    out, acc, bits = "", 0, 0
    for b in raw:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out += B32[(acc >> bits) & 31]
    if bits:
        out += B32[(acc << (5 - bits)) & 31]
    chk = check_bits(raw)
    out += B32[(chk >> 5) & 31] + B32[chk & 31]
    return "-".join(out[i:i + 4] for i in range(0, len(out), 4))


def decode_recovery_code(code: str) -> bytes:
    s = "".join(ch for ch in str(code).upper() if ch not in " \t\r\n-_").replace("O", "0").replace("I", "1").replace("L", "1")
    if len(s) != 28:
        raise _err(f"That does not look like an encryption recovery code: expected 28 characters, got {len(s)}.", "ENCRYPTION_BAD_RECOVERY_CODE")
    for ch in s:
        if ch not in B32:
            raise _err(f'That does not look like an encryption recovery code: "{ch}" is not a valid character.', "ENCRYPTION_BAD_RECOVERY_CODE")
    acc, bits, out = 0, 0, bytearray()
    for ch in s[:26]:
        acc = (acc << 5) | B32.index(ch)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    raw = bytes(out[:16])
    chk = check_bits(raw)
    if s[26:] != B32[(chk >> 5) & 31] + B32[chk & 31]:
        raise _err("That encryption recovery code has a typo in it: the check characters do not match.", "ENCRYPTION_BAD_RECOVERY_CODE")
    return raw


# ---- primitives (cryptography) ------------------------------------------------------------------

def _lib():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        raise _err('Record encryption needs the "cryptography" package: pip install "skapi[encryption]"', "NOT_SUPPORTED") from None
    return hashes, serialization, ec, AESGCM, HKDF, PBKDF2HMAC


def hkdf(ikm: bytes, salt: bytes, info: str, length: int = 32) -> bytes:
    hashes, _, _, _, HKDF, _ = _lib()
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=utf8(info)).derive(ikm)


def seal(key: bytes, pt: bytes, aad: bytes) -> Dict[str, str]:
    AESGCM = _lib()[3]
    iv = os.urandom(12)
    return {"iv": b64u(iv), "ct": b64u(AESGCM(key).encrypt(iv, pt, aad))}


def seal_raw(key: bytes, pt: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    AESGCM = _lib()[3]
    iv = os.urandom(12)
    return iv, AESGCM(key).encrypt(iv, pt, aad)


def open_(key: bytes, iv: bytes, ct: bytes, aad: bytes) -> bytes:
    AESGCM = _lib()[3]
    return AESGCM(key).decrypt(iv, ct, aad)


def password_kek(password: str, salt: bytes, iterations: int, info: str) -> bytes:
    hashes, _, _, _, _, PBKDF2HMAC = _lib()
    prk = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(utf8(unicodedata.normalize("NFC", password)))
    return hkdf(prk, salt, info)


def new_identity():
    _, serialization, ec, _, _, _ = _lib()
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    pkcs8 = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return priv, pub, pkcs8


def load_pkcs8(der: bytes):
    serialization = _lib()[1]
    return serialization.load_der_private_key(der, password=None)


def load_pub(raw: bytes):
    ec = _lib()[2]
    if len(raw) != 65 or raw[0] != 0x04:
        raise _err("Malformed public key: expected a 65 byte uncompressed P-256 point.", "INVALID_PARAMETER")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def fingerprint(pub_raw: bytes) -> str:
    return b64u(hashlib.sha256(pub_raw).digest())


def ecdh_wrap(dek: bytes, peer_pub_raw: bytes, info: str, aad: bytes) -> Dict[str, str]:
    _, serialization, ec, _, _, _ = _lib()
    eph = ec.generate_private_key(ec.SECP256R1())
    z = eph.exchange(ec.ECDH(), load_pub(peer_pub_raw))
    kw = hkdf(z, b"\x00" * 32, info)
    sealed = seal(kw, dek, aad)
    epk = eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"epk": b64u(epk), **sealed}


def ecdh_unwrap(priv, wrap: Dict[str, str], info: str, aad: bytes) -> bytes:
    ec = _lib()[2]
    z = priv.exchange(ec.ECDH(), load_pub(b64u_dec(wrap["epk"])))
    return open_(hkdf(z, b"\x00" * 32, info), b64u_dec(wrap["iv"]), b64u_dec(wrap["ct"]), aad)


# ---- encrypted file container "SKENCF" v2 ---------------------------------------------------------

def dek_id(dek: bytes) -> bytes:
    return hashlib.sha256(utf8(f"{ENC_V}|dekid") + dek).digest()[:8]


def _file_key(dek: bytes, file_id: bytes, ctx: Dict[str, str]) -> bytes:
    return hkdf(dek, file_id, f"{ENC_V}|binfile|{ctx['service']}|{ctx['owner']}|{ctx['recordOwner']}|{ctx['recordId']}")


def encrypt_file(dek: bytes, ctx: Dict[str, str], content: bytes, name: str, content_type: Optional[str], last_modified: int = 0) -> bytes:
    meta = utf8(json.dumps({"n": name, "t": content_type or "", "lm": last_modified or 0}, separators=(",", ":"), ensure_ascii=False))
    if len(meta) > 4096:
        raise _err("Encrypted file metadata is too large.", "INVALID_PARAMETER")
    count = max(1, math.ceil(len(content) / FILE_CHUNK))
    file_id = os.urandom(16)
    header = (b"SKENCF" + bytes([2, 1 if meta else 0]) + FILE_CHUNK.to_bytes(4, "big") + count.to_bytes(4, "big") + file_id
              + len(content).to_bytes(8, "big") + dek_id(dek) + len(meta).to_bytes(4, "big") + b"\x00\x00\x00\x00" + meta)
    header_hash = b64u(hashlib.sha256(header).digest())
    key = _file_key(dek, file_id, ctx)
    out = [header]
    for i in range(count):
        chunk = content[i * FILE_CHUNK:(i + 1) * FILE_CHUNK]
        aad = utf8(json.dumps([f"{ENC_V}|binchunk", header_hash, i, count], separators=(",", ":")))
        iv, ct = seal_raw(key, chunk, aad)
        out.append((12 + len(ct)).to_bytes(4, "big") + iv + ct)
    return b"".join(out)


def is_encrypted_file(b: bytes) -> bool:
    return len(b) >= 56 and b[:6] == b"SKENCF"


def decrypt_file(dek: bytes, ctx: Dict[str, str], blob: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if len(blob) < 56:
        raise _err("Encrypted file header is truncated.", "INVALID_REQUEST")
    version = blob[6]
    chunk_size = int.from_bytes(blob[8:12], "big")
    count = int.from_bytes(blob[12:16], "big")
    file_id = blob[16:32]
    plain_len = int.from_bytes(blob[32:40], "big")
    did = blob[40:48]
    meta_len = int.from_bytes(blob[48:52], "big")
    if len(blob) < 56 + meta_len:
        raise _err("Encrypted file header is truncated.", "INVALID_REQUEST")
    header = blob[:56 + meta_len]
    meta = json.loads(utf8_dec(blob[56:56 + meta_len])) if meta_len else {}
    if version != 2:
        raise _err(f"This file was encrypted by a different version of the SDK (container v{version}).", "NOT_SUPPORTED")
    if not count or not chunk_size:
        raise _err("Encrypted file header is malformed.", "INVALID_PARAMETER")
    if did != dek_id(dek):
        raise _err("This file was encrypted under a previous data key for this record, so it can no longer be opened. "
                   "It was most likely left behind by an interrupted access change.", "ENCRYPTION_FILE_STALE_KEY")
    header_hash = b64u(hashlib.sha256(header).digest())
    key = _file_key(dek, file_id, ctx)
    pos, out = 56 + meta_len, []
    for i in range(count):
        if pos + 4 > len(blob):
            raise _err("Encrypted file is truncated.", "INVALID_REQUEST")
        n = int.from_bytes(blob[pos:pos + 4], "big")
        if pos + 4 + n > len(blob):
            raise _err("Encrypted file is truncated.", "INVALID_REQUEST")
        iv, ct = blob[pos + 4:pos + 16], blob[pos + 16:pos + 4 + n]
        aad = utf8(json.dumps([f"{ENC_V}|binchunk", header_hash, i, count], separators=(",", ":")))
        out.append(open_(key, iv, ct, aad))
        pos += 4 + n
    return b"".join(out)[:plain_len], meta


# ---- per-instance state -----------------------------------------------------------------------------

def parse_option(option: Any) -> Optional[Dict[str, Any]]:
    if not option:
        return None
    if option is True:
        option = {}
    if not isinstance(option, dict):
        raise _err('"options.encryption" should be a boolean or an object.', "INVALID_PARAMETER")
    it = option.get("iterations", PBKDF2_ITERATIONS)
    if isinstance(it, (int, float)) and not isinstance(it, bool) and it < 100000:
        raise _err('"encryption.iterations" must be at least 100000.', "INVALID_PARAMETER")
    table = option.get("table")
    return {
        "iterations": int(it) if isinstance(it, (int, float)) and not isinstance(it, bool) else PBKDF2_ITERATIONS,
        "trustPolicy": "strict" if option.get("trustPolicy") == "strict" else "tofu",
        "withheld": "sentinel" if option.get("withheld") == "sentinel" else "null",
        "recovery": "none" if option.get("recovery") == "none" else "code",
        "table": table if isinstance(table, str) and table else "__skapi__keyring",
    }


class EncState:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.clear()

    def clear(self, keep_recovery: bool = False) -> None:
        """Drops every key. keep_recovery is lock_encryption()'s: an encryption recovery code the app
        has not collected yet can never be shown again, so a lock keeps it; a logout drops it."""
        self.status = "locked"
        self.reason = "NO_SESSION_KEY"
        self.mk: Optional[bytes] = None
        self.ik_priv = None
        self.pub_raw: Optional[bytes] = None
        self.fpr = ""
        self.keyring_record_id = ""
        self.user_id = ""
        self.pins: Dict[str, str] = {}
        self.peer_pub: Dict[str, Tuple[bytes, str]] = {}
        self.deks: Dict[str, Dict[str, Any]] = {}
        self.passthrough: Dict[str, Any] = {}
        self.roll: set = set()
        self.roll_key: Dict[str, bytes] = {}  # the key a revoke minted ahead of its roll (see _enc_drop_and_roll)
        if not keep_recovery:
            self.pending_recovery_code: Optional[str] = None
            self.pending_recovery_user = ""


class EncryptionMixin:
    """Mixed into Skapi. self._enc is None when the instance has encryption off."""

    _enc: Optional[EncState] = None

    # ---- strings ---------------------------------------------------------------------------------

    def _e_s(self, kind: str, user: str) -> str:
        return f"{ENC_V}|{kind}|{self.service}|{self.owner}|{user}"

    def _payload_aad(self, own: str, anch: str, anchor: str) -> bytes:
        return utf8(json.dumps([ENC_V, self.service, self.owner, own, anch, anchor], separators=(",", ":"), ensure_ascii=False))

    @staticmethod
    def _recipient_aad(payload_aad: bytes, recipient: str, bind: str) -> bytes:
        return payload_aad + b"\x00" + utf8(recipient) + b"\x00" + utf8(bind)

    def _wrap_info(self, anchor: str, own: str, recipient: str, fpr: str) -> str:
        return f"{ENC_V}|dekwrap|{self.service}|{self.owner}|{anchor}|{own}|{recipient}|{fpr}"

    @staticmethod
    def _anchor_of(env: Dict[str, Any]) -> str:
        return env.get("uid", "") if env.get("anch") == "uid" else env.get("rid", "") if env.get("anch") == "rid" else ""

    def _me(self) -> str:
        return (self._user or {}).get("user_id", "")

    # ---- keyring -----------------------------------------------------------------------------------

    def _find_keyring(self, uid: str) -> Optional[Dict[str, Any]]:
        res = self.get_records({"table": {"name": self._enc.cfg["table"], "access_group": "private"},
                                "index": {"name": "$user_id", "value": uid, "condition": "="}}, {"limit": 2})
        rows = sorted((r for r in res.get("list", []) if r.get("user_id") == uid), key=lambda r: r.get("uploaded", 0))
        return rows[0] if rows else None

    def _password_wrap(self, mk: bytes, password: str, uid: str) -> Dict[str, Any]:
        it = self._enc.cfg["iterations"]
        salt = os.urandom(16)
        s = b64u(salt)
        kek = password_kek(password, salt, it, self._e_s("kek", uid))
        sealed = seal(kek, mk, utf8(f"{self._e_s('mk', uid)}|PBKDF2-SHA256|{it}|{s}"))
        return {"id": b64u(os.urandom(6)), "p": "password", "kdf": {"a": "PBKDF2-SHA256", "it": it, "s": s}, **sealed, "created": int(time.time() * 1000)}

    def _recovery_wrap(self, mk: bytes, uid: str) -> Tuple[Dict[str, Any], str]:
        raw = os.urandom(16)
        salt = os.urandom(16)
        s = b64u(salt)
        rk = hkdf(raw, salt, self._e_s("recovery", uid))
        sealed = seal(rk, mk, utf8(f"{self._e_s('rk', uid)}|HKDF-SHA256|{s}"))
        return {"id": b64u(os.urandom(6)), "p": "recovery", "kdf": {"a": "HKDF-SHA256", "s": s}, **sealed, "created": int(time.time() * 1000)}, encode_recovery_code(raw)

    def _open_with_password(self, data: Dict[str, Any], password: str, uid: str) -> Optional[bytes]:
        wraps = sorted((w for w in data.get("wraps", []) if isinstance(w, dict) and w.get("p") == "password"), key=lambda w: w.get("created", 0), reverse=True)
        if not wraps:
            raise _err("The keyring has no password wrap.", "ENCRYPTION_KEYRING_CORRUPT")
        for w in wraps:
            try:
                kdf = w["kdf"]
                kek = password_kek(password, b64u_dec(kdf["s"]), kdf["it"], self._e_s("kek", uid))
                return open_(kek, b64u_dec(w["iv"]), b64u_dec(w["ct"]), utf8(f"{self._e_s('mk', uid)}|PBKDF2-SHA256|{kdf['it']}|{kdf['s']}"))
            except SkapiError:
                raise
            except Exception:
                continue
        return None

    def _adopt_keyring(self, keyring: Dict[str, Any], mk: bytes, uid: str) -> None:
        s, data = self._enc, keyring["data"]
        pkcs8 = open_(mk, b64u_dec(data["ik"]["iv"]), b64u_dec(data["ik"]["ct"]), utf8(self._e_s("ik", uid)))
        pins: Dict[str, str] = {}
        if isinstance(data.get("pins"), dict) and data["pins"].get("ct"):
            try:
                pins = json.loads(utf8_dec(open_(mk, b64u_dec(data["pins"]["iv"]), b64u_dec(data["pins"]["ct"]),
                                                 utf8(f"{ENC_V}|pins|{self.service}/{self.owner}|{uid}"))))
            except Exception:
                pins = {}
        s.mk, s.ik_priv = mk, load_pkcs8(pkcs8)
        s.pub_raw, s.fpr = b64u_dec(data["pub"]), data.get("fpr", "")
        s.keyring_record_id, s.user_id = keyring["record_id"], uid
        s.pins = pins if isinstance(pins, dict) else {}
        s.status, s.reason = "unlocked", ""
        try:
            self._repair_public_key(uid)
        except Exception as err:  # best effort: it never fails the unlock
            warnings.warn(f"skapi encryption: the public key directory could not be checked: {err}", RuntimeWarning, stacklevel=3)

    def _repair_public_key(self, uid: str) -> None:
        """
        Puts this keyring's public key back on top of the public key directory when a stray row is
        there instead. Two devices logging in for the first time at once could leave the losing
        keyring's public row behind, and it is the NEWEST row, the one peers read, so they wrapped
        data keys to a key nobody holds. When the newest row does not carry this keyring's key, and
        this session proves it holds the private half, the key is published again and the rows that
        do not match it are removed. As skapi-js repairPublicKey.
        """
        s = self._enc
        pub_raw, ik_priv = s.pub_raw, s.ik_priv
        if not uid or not pub_raw or ik_priv is None:
            return
        res = self.get_records({"table": {"name": s.cfg["table"], "access_group": "authorized"},
                                "index": {"name": "$user_id", "value": uid, "condition": "="}}, {"limit": 10})
        rows = sorted((r for r in res.get("list", []) if r.get("user_id") == uid and isinstance(r.get("data"), dict) and r["data"].get("pub")),
                      key=lambda r: r.get("uploaded", 0), reverse=True)
        if not rows:
            return
        mine = fingerprint(pub_raw)

        def fpr_of(r):
            try:
                return fingerprint(b64u_dec(r["data"]["pub"]))
            except Exception:
                return ""
        if fpr_of(rows[0]) == mine:
            return
        # the key about to be published must open what is sealed to it with this session's private key
        probe = os.urandom(32)
        label = utf8(f"{ENC_V}|pubcheck|{uid}")
        try:
            holds = ecdh_unwrap(ik_priv, ecdh_wrap(probe, pub_raw, label.decode("utf-8"), label), label.decode("utf-8"), label) == probe
        except Exception:
            holds = False
        if not holds:
            return
        stray = [r["record_id"] for r in rows if fpr_of(r) != mine and r.get("record_id")]
        if s.user_id != uid or self._me() != uid:
            return  # a lock, logout or another user's login since the unlock: leave it
        self.post_record({"v": 1, "alg": "ECDH-P-256", "user_id": uid, "pub": b64u(pub_raw), "fpr": mine, "created": int(time.time() * 1000)},
                         {"table": {"name": s.cfg["table"], "access_group": "authorized"}, "index": {"name": "pubkey", "value": uid}})
        if stray and s.user_id == uid and self._me() == uid:
            self.delete_records({"record_id": stray})

    def _unlock_keyring(self, keyring: Dict[str, Any], password: str, uid: str) -> None:
        data = keyring.get("data") or {}
        if keyring.get("user_id") != uid or (data.get("user_id") and data.get("user_id") != uid):
            raise _err("The encryption keyring does not belong to this user.", "ENCRYPTION_KEYRING_CORRUPT")
        mk = self._open_with_password(data, password, uid)
        if mk is None:
            raise _err("Incorrect password: the encryption keyring could not be opened.", "ENCRYPTION_BAD_PASSWORD")
        self._adopt_keyring(keyring, mk, uid)

    def _provision_keyring(self, password: str, uid: str) -> None:
        s = self._enc
        mk = os.urandom(32)
        priv, pub, pkcs8 = new_identity()
        fpr = fingerprint(pub)
        wraps = [self._password_wrap(mk, password, uid)]
        code = None
        if s.cfg["recovery"] == "code":
            w, code = self._recovery_wrap(mk, uid)
            wraps.append(w)
        now = int(time.time() * 1000)
        data = {"v": 1, "alg": "ECDH-P-256", "user_id": uid, "wraps": wraps, "ik": seal(mk, pkcs8, utf8(self._e_s("ik", uid))),
                "self": seal(mk, mk, utf8(self._e_s("self", uid))), "pub": b64u(pub), "fpr": fpr, "pins": None, "created": now, "updated": now}
        table = s.cfg["table"]
        pub_rec = self.post_record({"v": 1, "alg": "ECDH-P-256", "user_id": uid, "pub": b64u(pub), "fpr": fpr, "created": now},
                                   {"table": {"name": table, "access_group": "authorized"}, "index": {"name": "pubkey", "value": uid}})
        rec = self.post_record(data, {"table": {"name": table, "access_group": "private"}})
        oldest = self._find_keyring(uid)
        if oldest and oldest.get("record_id") != rec.get("record_id"):
            # another device enrolled first: its keyring wins. This device's public key and keyring
            # go (best effort), or peers would read this newer public key and wrap for a key nobody holds.
            try:
                self.delete_records({"record_id": [r for r in (pub_rec.get("record_id"), rec.get("record_id")) if r]})
            except Exception as err:
                warnings.warn(f"skapi encryption: this device's unused public key and keyring could not be removed: {err}", RuntimeWarning, stacklevel=3)
            self._unlock_keyring(oldest, password, uid)  # adopt the keyring of the device that enrolled first
            return
        self._adopt_keyring(dict(rec, data=data), mk, uid)
        s.pending_recovery_code, s.pending_recovery_user = code, uid
        s.pins = {}

    def _ensure_keyring(self, password: str, create: bool = True) -> None:
        """Open the keyring with the password, or create it when there is none. Creating is for
        login only (the default), where the password was just proven. unlock_encryption() passes
        create=False: a session restored from tokens proved no password, so creating a keyring
        there would seal the data under whatever was typed. As in skapi-js."""
        s = self._enc
        if s is None or not self._user:
            return
        _lib()
        if self._user.get("is_openid"):
            s.status, s.reason = "locked", "OPENID_UNSUPPORTED"
            return
        uid = self._me()
        keyring = self._find_keyring(uid)
        if keyring:
            self._unlock_keyring(keyring, password, uid)
        elif not create:
            raise _err("Encryption has not been set up for this account yet. It is set up at the first login with the password: "
                       "log in with the password to start using it.", "NOT_EXISTS")
        else:
            self._provision_keyring(password, uid)

    def _enc_after_login(self, password: Optional[str]) -> None:
        """Called after every password sign-in. Never fails the login."""
        if self._enc is None or not password:
            return
        self._enc.clear()  # a previous user's keys never carry over
        try:
            self._ensure_keyring(password)
        except Exception as err:
            warnings.warn(f"skapi encryption could not be unlocked at login: {err}", RuntimeWarning, stacklevel=3)

    def _enc_clear(self) -> None:
        if self._enc is not None:
            self._enc.clear()

    def _enc_rewrap_password(self, current: str, new: str) -> Optional[Dict[str, Any]]:
        s = self._enc
        if s is None:
            return None
        if s.status != "unlocked" or not s.mk:
            raise _err("Encryption must be unlocked before changing the password, or the encryption keyring would be left "
                       "wrapped under a password that no longer exists. Call unlock_encryption(password) first.", "ENCRYPTION_LOCKED")
        res = self.get_records({"record_id": s.keyring_record_id}, {"limit": 1})
        if not res.get("list"):
            raise _err("The encryption keyring could not be read, so the password change was stopped before it could strand it.", "ENCRYPTION_KEYRING_CORRUPT")
        keyring = res["list"][0]
        uid = self._me()
        mk = self._open_with_password(keyring["data"], current, uid)
        if mk is None:
            raise _err("Incorrect current password: the encryption keyring was not re-wrapped.", "ENCRYPTION_BAD_PASSWORD")
        data = dict(keyring["data"])
        data["wraps"] = list(data.get("wraps", [])) + [self._password_wrap(mk, new, uid)]
        data["updated"] = int(time.time() * 1000)
        self.post_record(data, {"record_id": s.keyring_record_id})
        return data

    def _enc_prune_wraps(self) -> None:
        s = self._enc
        if s is None or s.status != "unlocked":
            return
        try:
            keyring = self.get_records({"record_id": s.keyring_record_id}, {"limit": 1})["list"][0]
            data = dict(keyring["data"])
            pw = sorted((w for w in data.get("wraps", []) if w.get("p") == "password"), key=lambda w: w.get("created", 0), reverse=True)
            if len(pw) > 1:
                data["wraps"] = [pw[0]] + [w for w in data["wraps"] if w.get("p") != "password"]
                data["updated"] = int(time.time() * 1000)
                self.post_record(data, {"record_id": s.keyring_record_id})
        except Exception as err:
            warnings.warn(f"skapi encryption: old password wrap not pruned: {err}", RuntimeWarning, stacklevel=2)

    # ---- peers ------------------------------------------------------------------------------------

    def _peer_keys(self, ids: List[str]) -> Dict[str, Optional[Tuple[bytes, str]]]:
        s = self._enc
        out: Dict[str, Optional[Tuple[bytes, str]]] = {}
        pinned_new = False
        for uid in ids:
            if uid in s.peer_pub:
                out[uid] = s.peer_pub[uid]
                continue
            res = self.get_records({"table": {"name": s.cfg["table"], "access_group": "authorized"},
                                    "index": {"name": "$user_id", "value": uid, "condition": "="}}, {"limit": 10})
            rows = sorted((r for r in res.get("list", []) if r.get("user_id") == uid and isinstance(r.get("data"), dict) and r["data"].get("pub")),
                          key=lambda r: r.get("uploaded", 0), reverse=True)
            if not rows:
                out[uid] = None
                continue
            pub = b64u_dec(rows[0]["data"]["pub"])
            fpr = fingerprint(pub)
            if uid in s.pins and s.pins[uid] != fpr:
                raise _err(f'The public key for user "{uid}" has changed since it was first seen. '
                           "This is expected if they reset their account, and is what a key substitution attack also looks like. "
                           "Verify the new fingerprint out of band, then call pin_peer_key(user_id, fingerprint).", "ENCRYPTION_PEER_KEY_CHANGED")
            if uid not in s.pins:
                if s.cfg["trustPolicy"] == "strict":
                    raise _err(f'No pinned key for user "{uid}" and trustPolicy is "strict". Pin it first with pin_peer_key().', "ENCRYPTION_PEER_NOT_PINNED")
                s.pins[uid] = fpr
                pinned_new = True
            s.peer_pub[uid] = (pub, fpr)
            out[uid] = (pub, fpr)
        if pinned_new:
            try:
                self._persist_pins()
            except Exception:
                pass
        return out

    def _persist_pins(self) -> None:
        s = self._enc
        if not s.mk or not s.keyring_record_id:
            return
        keyring = self.get_records({"record_id": s.keyring_record_id}, {"limit": 1})["list"][0]
        data = dict(keyring["data"])
        data["pins"] = seal(s.mk, utf8(_js_json(s.pins)), utf8(f"{ENC_V}|pins|{self.service}/{self.owner}|{s.user_id}"))
        data["updated"] = int(time.time() * 1000)
        self.post_record(data, {"record_id": s.keyring_record_id})

    # ---- write ---------------------------------------------------------------------------------------

    def _write_group(self, view: Dict[str, Any], has_data: bool) -> Tuple[Any, Any, Optional[Dict[str, Any]]]:
        """(access group the write lands on, table name, the record if it had to be read)."""
        table = view.get("table")
        name = table if isinstance(table, str) else (table or {}).get("name") if isinstance(table, dict) else None

        def norm(g):
            if g in ("private", "*", "**"):
                return "private"
            return {"public": 0, "authorized": 1, "admin": 99}.get(g, g if isinstance(g, (int, float)) else 0)
        if isinstance(table, str):
            return 0, name, None
        if isinstance(table, dict) and "access_group" in table:
            return norm(table["access_group"]), name, None
        rid = view.get("record_id")
        if not rid:
            return 0, name, None
        # The cached data key says only what the group was when this session last saw the record;
        # another device may have made it non-private since, and sealing a payload into a
        # non-private record strands it. So the cache is trusted only for a write with no data,
        # where both answers write nothing (as skapi-js resolveWriteGroup).
        if rid in self._enc.deks and not has_data:
            return self._enc.deks[rid].get("access_group", "private"), name, None
        current = self._read_own_record(rid)
        if current is None:
            raise _err(f'Record "{rid}" not found.', "NOT_EXISTS")
        return current["table"]["access_group"], current["table"]["name"], current

    def _read_own_record(self, rid: str) -> Optional[Dict[str, Any]]:
        import re
        q = {"record_id": rid} if re.match(r"^[a-zA-Z0-9]+$", rid) else {"unique_id": rid}
        res = self.get_records(q, {"limit": 1})
        return res["list"][0] if res.get("list") else None

    def _owner_check(self, current: Optional[Dict[str, Any]], rid: str, what: str) -> None:
        if current and current.get("encrypted") and current.get("user_id") != self._me():
            raise _err(f'Record "{rid}" belongs to another user ({current.get("user_id")}), so {what} would either seal it '
                       "under the wrong key or strand its contents. Encryption only operates on records you own, "
                       "no matter what access level you hold.", "ENCRYPTION_NOT_RECORD_OWNER")

    def _maybe_encrypt(self, value: Any, view: Dict[str, Any], has_data: bool) -> Dict[str, Any]:
        s = self._enc
        if s is None:
            return {"send": value, "omit": not has_data}
        raw_id = view.get("record_id") or ""
        if raw_id and raw_id in s.passthrough:
            return {"send": s.passthrough.pop(raw_id), "encrypted": True}
        group, table_name, record = self._write_group(view, has_data)
        if group != "private":
            files = None
            current = record
            if raw_id and current is None:
                try:
                    current = self._read_own_record(raw_id)
                except SkapiError:
                    current = None
            if current is not None and current.get("encrypted"):
                self._owner_check(current, raw_id, "making it non-private")
                if not has_data:
                    if current["encrypted"].get("status") == "failed":
                        raise _err(f'Cannot make record "{raw_id}" non-private: its current contents could not be decrypted '
                                   f'({current["encrypted"].get("reason")}), so they cannot be written back in the clear. '
                                   "Unlock encryption, or supply the record's data with the access group change.", "ENCRYPTION_LOCKED")
                    value, has_data = current.get("data"), True
            if current is not None and any(b.get("encrypted") for entries in (current.get("bin") or {}).values() for b in entries):
                files = "decrypt"
            elif current is not None:
                s.deks.pop(current.get("record_id"), None)
            return {"send": value, "omit": not has_data, "files": files}
        if table_name == s.cfg["table"]:
            return {"send": value, "omit": not has_data}  # the keyring itself is never sealed
        if not has_data:
            return {"omit": True}
        if isinstance(value, dict) and value.get(WITHHELD) is True:
            raise _err("This record's data could not be decrypted by this session, so it cannot be written back. "
                       "Writing it would replace the record with the placeholder.", "ENCRYPTION_CANNOT_REWRITE_WITHHELD")
        if s.status != "unlocked":
            raise _err("Encryption is enabled but locked, so this private record cannot be written. "
                       "Call unlock_encryption(password) first, or the user must log in with their password.", "ENCRYPTION_LOCKED")
        if isinstance(value, dict) and ENV_MARKER in value:
            raise _err('"__skapi_enc__" is a reserved key in record data.', "INVALID_PARAMETER")
        if (view.get("service") and view["service"] != self.service) or (view.get("owner") and view["owner"] != self.owner):
            raise _err("Encrypted records cannot be written to another project. The encryption key is derived per project, "
                       "so a record written under one service and read under another could never be decrypted. "
                       "Construct a separate Skapi instance for that project.", "INVALID_REQUEST")
        me = self._me()
        if not me:
            raise _err("User login is required to write an encrypted record.", "INVALID_REQUEST")
        rolling = False
        roll_key: Optional[bytes] = None
        prior_ct: List[str] = []
        if raw_id and raw_id in s.roll:
            s.roll.discard(raw_id)
            roll_key = s.roll_key.pop(raw_id, None)
            stale = s.deks.pop(raw_id, None) or {}
            prior_ct = [u for u in [stale.get("ct_url")] + list(stale.get("ct_stale") or []) if u]
            rolling = True
        files = None
        entry = self._dek_if_current(raw_id) if raw_id else None
        resolved_id = ""
        uid = view.get("unique_id") or ""
        current = None
        if raw_id and entry is None:
            try:
                current = self._read_own_record(raw_id)
            except SkapiError:
                current = None
            self._owner_check(current, raw_id, "updating it")
        if current is not None:
            if not current.get("encrypted") and any(not b.get("encrypted") for entries in (current.get("bin") or {}).values() for b in entries):
                files = "encrypt"
            resolved_id = current.get("record_id", "")
            uid = uid or current.get("unique_id") or ""
            if current.get("encrypted", {}).get("status") == "failed":
                raise _err(f'Cannot update encrypted record "{raw_id}": its current contents could not be decrypted ({current["encrypted"].get("reason")}), '
                           "so its existing key wraps cannot be preserved. Updating anyway would revoke everyone it is shared with.", "ENCRYPTION_LOCKED")
            if not rolling:
                entry = s.deks.get(resolved_id)
        if entry:
            if entry.get("rid"):
                resolved_id = entry["rid"]
            if entry.get("anch") == "uid":
                uid = entry.get("uid") or uid
            if entry.get("own") != me:
                raise _err(f'Record "{raw_id}" belongs to another user ({entry.get("own")}). Encryption only operates on records you own.', "ENCRYPTION_NOT_RECORD_OWNER")
        elif raw_id and not resolved_id and not rolling:
            resolved_id = raw_id
        dek = entry["bytes"] if entry else (roll_key or os.urandom(32))
        recipients = dict(entry["recipients"]) if entry else {}
        anch = "uid" if uid else ("rid" if resolved_id else "new")
        anchor = uid if anch == "uid" else resolved_id if anch == "rid" else ""
        aad = self._payload_aad(me, anch, anchor)
        recipients[me] = {"t": "mk", **seal(s.mk, dek, self._recipient_aad(aad, me, "mk"))}
        if entry and (entry.get("anch") != anch or self._anchor_of(entry) != anchor):
            recipients = self._rewrap_all(dek, recipients, me, anch, anchor, aad)
        iv, ct = seal_raw(dek, utf8(_js_json(value)), aad)
        env = {ENV_MARKER: 1, "enc": "A256GCM", "kw": "ECDH-ES+A256GCM", "anch": anch, "uid": uid, "rid": resolved_id, "own": me,
               "iv": b64u(iv), "ct": b64u(ct), "k": recipients}
        spill, retire = None, None
        if resolved_id and len(env["ct"]) > SPILL_LIMIT:
            spill, env["ct"], env["ct_ref"] = ct, "", CT_FILE_SUFFIX
        if resolved_id:
            # the stored payload files' real urls (never the bare ct_ref suffix, which the server refuses),
            # retired whether the new data spills again or now fits inline
            old = [(entry or {}).get("ct_url")] + list((entry or {}).get("ct_stale") or []) + prior_ct
            retire = list(dict.fromkeys(u for u in old if u)) or None
        env_size = len(json.dumps(env, separators=(",", ":")))
        if env_size > ENVELOPE_CAP:
            raise _err(f"Encrypted record data is too large: once encrypted and base64 encoded it becomes {env_size} bytes, "
                       f"over the {ENVELOPE_CAP} byte limit. Encryption costs about 33% plus roughly 230 bytes per additional recipient.", "ENCRYPTED_DATA_TOO_LARGE")
        if resolved_id:
            self._cache_dek(resolved_id, dek, recipients, anch, uid, me)
        dek_entry = {"bytes": dek, "recipients": dict(recipients), "anch": anch, "uid": uid, "own": me, "access_group": "private"}
        return {"send": env, "plain": value, "encrypted": True, "dek": dek_entry, "spill": spill, "retire": retire, "files": files,
                "recipients": list(recipients)}

    def _dek_if_current(self, key: str) -> Optional[Dict[str, Any]]:
        """A record's cached data key, only while the stored envelope still carries the key wraps it
        was cached with. Another session of the owner may have rolled the key or changed who it is
        wrapped for since; then the cached key is forgotten (None) and the caller reads the record again."""
        s = self._enc
        entry = s.deks.get(key)
        if not entry:
            return None
        rid = entry.get("rid") or key
        stored = self._read_stored_envelope(rid)
        if stored is not None and stored.get("k") == entry.get("recipients"):
            return entry
        s.deks.pop(key, None)
        s.deks.pop(rid, None)
        return None

    def _bind_record_dek(self, record_id: str, dek_entry: Optional[Dict[str, Any]]) -> None:
        """A just-created record's key, under the record_id the server minted."""
        s = self._enc
        if s is None or not dek_entry or not record_id or record_id in s.deks:
            return
        s.deks[record_id] = dict(dek_entry, rid=record_id)

    def _convert_record_files(self, record_id: str, direction: str) -> List[str]:
        """Re-uploads a record's attachments sealed ('encrypt') or in the clear ('decrypt'); returns the urls to retire."""
        s = self._enc
        if s is None:
            return []
        rec = self._read_own_record(record_id)
        if not rec:
            return []
        want_sealed = direction == "decrypt"
        targets = [(form_key, f) for form_key, entries in (rec.get("bin") or {}).items() for f in entries if bool(f.get("encrypted")) == want_sealed]
        if not targets:
            return []
        import mimetypes
        from urllib.parse import urlsplit
        uploads, retire = [], []
        for form_key, f in targets:
            content = self.get_file(f["url"], {"dataType": "bytes", "_raw": True})
            content_type = None
            if want_sealed:
                content, meta = self._decrypt_file_for(f["url"], content)
                content_type = meta.get("t") or "application/octet-stream"
            uploads.append({"name": form_key, "filename": f["filename"], "content": content,
                            "content_type": content_type or mimetypes.guess_type(f["filename"])[0] or "application/octet-stream"})
            u = urlsplit(f["url"])
            retire.append(f"{u.scheme}://{u.netloc}/{f['path']}")
        # The key leaves the cache for the upload (or the upload would seal the files again), but
        # comes back if anything fails: all or nothing, as in skapi-js. A failed conversion removes
        # the copies that did upload and refuses the write, so the record and its files stay as they were.
        held = s.deks.pop(record_id, None) if want_sealed else None
        try:
            result = self._upload_prepared(uploads, record_id)
        except Exception:
            if held is not None:
                s.deks[record_id] = held
            raise
        if result["failed"]:
            if held is not None:
                s.deks[record_id] = held
            landed = [u for u in result.get("landed") or [] if u]
            if landed:
                try:
                    self._remove_landed_copies(record_id, landed)
                except Exception as err:
                    warnings.warn(f"skapi: could not remove the partly converted copies: {err}", RuntimeWarning, stacklevel=2)
            first = result["errors"][0]["error"]
            raise _err(f"The record's attached files could not all be converted, so the record was not changed: {first}",
                       getattr(first, "code", None) or "ERROR")
        return retire

    def _remove_landed_copies(self, record_id: str, urls: List[str]) -> None:
        """A record file joins the record's file list a moment after its upload, and removing an address
        the list does not hold yet does nothing, so wait for them to appear, then remove them in one write."""
        import time as _time
        from urllib.parse import unquote
        bare = lambda u: unquote(u.split("?")[0])
        want = {bare(u) for u in urls}
        for attempt in range(8):
            rec = self._read_own_record(record_id) or {}
            have = {bare(f.get("url") or "") for entries in (rec.get("bin") or {}).values() for f in entries}
            if want <= have:
                break
            _time.sleep(0.5 * (attempt + 1))
        self.post_record(config={"record_id": record_id, "remove_bin": urls})

    def _rewrap_all(self, dek: bytes, recipients: Dict[str, Any], me: str, anch: str, anchor: str, aad: bytes) -> Dict[str, Any]:
        out = {me: recipients[me]}
        others = [u for u in recipients if u != me]
        keys = self._peer_keys(others) if others else {}
        for u in others:
            k = keys.get(u)
            if not k:
                continue  # as in skapi-js: a grantee whose key cannot be found is dropped
            out[u] = {"t": "ecdh", **ecdh_wrap(dek, k[0], self._wrap_info(anchor, me, u, k[1]), self._recipient_aad(aad, u, k[1])), "fpr": k[1]}
        return out

    def _cache_dek(self, rid: str, dek: bytes, recipients: Dict[str, Any], anch: str, uid: str, own: str, ct_url: str = "",
                   ct_stale: Optional[List[str]] = None) -> None:
        entry = self._enc.deks.get(rid)
        if entry is None:
            entry = {}
            self._enc.deks[rid] = entry
        entry.update({"bytes": dek, "recipients": dict(recipients), "anch": anch, "uid": uid, "rid": rid, "own": own, "access_group": "private"})
        if ct_url:
            entry["ct_url"] = ct_url
            entry["ct_stale"] = list(ct_stale or [])

    # ---- read ----------------------------------------------------------------------------------------

    def _maybe_decrypt(self, raw: Any, ctx: Dict[str, Any]) -> Tuple[Any, Optional[Dict[str, Any]]]:
        """(value, flag). Never raises."""
        if not is_envelope(raw) or ctx.get("access_group") != "private":
            return raw, None
        s = self._enc
        if s is None:
            return None, {"status": "failed", "reason": "ENCRYPTION_DISABLED"}
        if ctx.get("table_name") == s.cfg["table"]:
            return raw, None

        def fail(reason, recipients=None):
            flag = {"status": "failed", "reason": reason}
            if recipients is not None:
                flag["recipients"] = recipients
            if s.cfg["withheld"] == "sentinel":
                v = {WITHHELD: True, "reason": reason}
                if reason == "NOT_A_RECIPIENT":
                    v["recipients"] = recipients
                return v, flag
            return None, flag

        if raw.get(ENV_MARKER) != 1:
            return fail("UNSUPPORTED_VERSION")
        if raw["own"] != ctx.get("user_id") or (raw.get("uid") and ctx.get("unique_id") and raw["uid"] != ctx["unique_id"]) \
                or (raw.get("rid") and ctx.get("record_id") and raw["rid"] != ctx["record_id"]):
            return fail("BINDING_MISMATCH")
        me = self._me()
        wrap = raw["k"].get(me)
        if not wrap:
            return fail("NOT_A_RECIPIENT", list(raw["k"]))
        if s.status != "unlocked":
            return fail("NO_SESSION_KEY")
        anchor = self._anchor_of(raw)
        aad = self._payload_aad(raw["own"], raw["anch"], anchor)
        try:
            if wrap.get("t") == "mk":
                dek = open_(s.mk, b64u_dec(wrap["iv"]), b64u_dec(wrap["ct"]), self._recipient_aad(aad, me, "mk"))
            elif wrap.get("t") == "ecdh":
                if s.ik_priv is None:
                    return fail("NO_SESSION_KEY")
                dek = ecdh_unwrap(s.ik_priv, wrap, self._wrap_info(anchor, raw["own"], me, wrap.get("fpr", "")), self._recipient_aad(aad, me, wrap.get("fpr", "")))
            else:
                return fail("UNSUPPORTED_VERSION")
        except Exception:
            return fail("BAD_KEY")
        ct_used, ct_stale = "", []
        if raw.get("ct_ref"):
            # newest payload file first (see _database.py); older SDKs could leave several, so the first one
            # that passes the GCM tag check is the current one, and the rest are retired on the next update
            candidates = list(ctx.get("ct_urls") or ([ctx["ct_url"]] if ctx.get("ct_url") else []))
            fetched, value = False, None
            for url in candidates:
                try:
                    ct = self.get_file(url, {"dataType": "bytes"})
                    fetched = True
                except Exception:
                    continue
                try:
                    value = json.loads(utf8_dec(open_(dek, b64u_dec(raw["iv"]), ct, aad)))
                    ct_used = url
                    break
                except Exception:
                    continue
            if not ct_used:
                return fail("CORRUPT" if fetched else "DATA_UNAVAILABLE")
            ct_stale = [u for u in candidates if u != ct_used]
        else:
            try:
                ct = b64u_dec(raw["ct"])
            except Exception:
                return fail("DATA_UNAVAILABLE")
            try:
                value = json.loads(utf8_dec(open_(dek, b64u_dec(raw["iv"]), ct, aad)))
            except Exception:
                return fail("CORRUPT")
        if ctx.get("record_id"):
            self._cache_dek(ctx["record_id"], dek, raw["k"], raw["anch"], raw.get("uid", ""), raw["own"], ct_used, ct_stale)
        return value, {"status": "encrypted", "recipients": list(raw["k"])}

    # ---- files ---------------------------------------------------------------------------------------

    def _maybe_encrypt_file(self, record_id: str, entry: Dict[str, Any]) -> Dict[str, Any]:
        s = self._enc
        if s is None or entry["name"] == CT_KEY:
            return {k: v for k, v in entry.items() if k != "_presealed"}
        if entry.get("_presealed"):
            # already sealed by a revoke, under the key its roll is about to install
            return {k: v for k, v in entry.items() if k != "_presealed"}
        if FILE_MARKER in entry["name"]:
            raise _err('"__skenc__" is reserved in an upload form key.', "INVALID_PARAMETER")
        dek_entry = s.deks.get(record_id)
        if not dek_entry:
            return entry  # as in skapi-js: without the record's key cached, the file goes up as is
        container = encrypt_file(dek_entry["bytes"], {"service": self.service, "owner": self.owner, "recordOwner": dek_entry["own"], "recordId": record_id},
                                 entry["content"], entry["filename"], entry["content_type"], 0)
        return dict(entry, name=f'{entry["name"]}{FILE_MARKER}{b62(len(entry["content"]))}', content=container, content_type="application/octet-stream")

    def _confirm_file_dek(self, record_id: str) -> None:
        """
        Before upload_files seals files with a record's cached data key: the key must still be the
        record's. Another session of the owner may have rolled it (a revoke) since, and files sealed
        under the old key could never be opened. A stale key is replaced by reading the record again;
        when the record is encrypted and this session cannot read its new key, the upload is refused
        rather than sending the files up in the clear or under a dead key.
        """
        s = self._enc
        if s is None or not record_id or record_id not in s.deks:
            return
        if self._dek_if_current(record_id) is not None:
            return
        rec = self._read_own_record(record_id)
        if rec is None or not rec.get("encrypted"):
            return
        if rec.get("record_id") != record_id and rec.get("record_id") in s.deks:
            s.deks[record_id] = s.deks[rec["record_id"]]
        if record_id not in s.deks:
            raise _err(f'Cannot attach files to encrypted record "{record_id}": its data key changed on another device and could not '
                       f'be read here ({(rec.get("encrypted") or {}).get("reason")}).', "ENCRYPTION_LOCKED")

    @staticmethod
    def _sealed_file_segments(url: str) -> Optional[List[str]]:
        segs = url.split("?")[0].split("/")[3:]
        if len(segs) < 12 or segs[4] != "records" or segs[7] != "bin" or parse_file_marker(segs[10]) is None:
            return None
        return segs

    def _maybe_decrypt_file(self, requested_url: str, blob: bytes) -> bytes:
        if self._enc is None or self._sealed_file_segments(requested_url) is None:
            return blob
        return self._decrypt_file_for(requested_url, blob)[0]

    def _decrypt_file_for(self, requested_url: str, blob: bytes) -> Tuple[bytes, Dict[str, Any]]:
        segs = self._sealed_file_segments(requested_url)
        dek_entry = self._enc.deks.get(segs[5])
        if not dek_entry:
            raise _err(f'Cannot open this file: the data key for record "{segs[5]}" is not available. Read the record first, and make sure encryption is unlocked.', "ENCRYPTION_LOCKED")
        if not is_encrypted_file(blob):
            raise _err("This file is marked as encrypted but its contents are not an encrypted container.", "ENCRYPTION_FILE_CORRUPT")
        return decrypt_file(dek_entry["bytes"], {"service": self.service, "owner": self.owner, "recordOwner": segs[3], "recordId": segs[5]}, blob)

    # ---- sharing ---------------------------------------------------------------------------------------

    def _load_for_rewrap(self, record_id: str) -> Optional[Dict[str, Any]]:
        s = self._enc
        entry = self._dek_if_current(record_id)
        if entry:
            return entry
        rec = self._read_own_record(record_id)
        if rec is None:
            raise _err(f'Record "{record_id}" not found.', "NOT_EXISTS")
        enc = rec.get("encrypted")
        if enc and enc.get("status") == "failed" and enc.get("reason") == "DATA_UNAVAILABLE":
            raise _err(f'Cannot change sharing on record "{record_id}": its data could not be read, '
                       "so whether it is encrypted is unknown. Retry once the record reads normally.", "ENCRYPTION_DATA_UNAVAILABLE")
        if not enc:
            return None
        if rec.get("user_id") != self._me():
            raise _err("Only the record owner can share an encrypted record, because adding a key wrap means writing the record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
        entry = s.deks.get(rec["record_id"])
        if not entry:
            raise _err(f'Cannot change sharing on record "{record_id}": its data could not be decrypted ({enc.get("reason")}).', "ENCRYPTION_LOCKED")
        return entry

    def _read_stored_envelope(self, record_id: str) -> Optional[Dict[str, Any]]:
        """
        The record's stored envelope, as the server holds it (None when it is not one). Its own read,
        never decrypted: an instance-wide "read raw" switch handed raw envelopes to any read another
        thread made at the same moment. As skapi-js readStoredEnvelope.
        """
        import re
        q, _ = self._build_query({"record_id": record_id} if re.match(r"^[a-zA-Z0-9]+$", record_id) else {"unique_id": record_id}, False)
        signed_in = self._signed_in()
        res = self._call("get-records", q, auth=signed_in, method="POST" if signed_in else "GET", fetch_options={"limit": 1})
        raw = res["list"][0] if isinstance(res, dict) and res.get("list") else None
        if not isinstance(raw, dict):
            return None
        rec = self._normalize_record(raw, skip_bin_resolve=True, skip_decrypt=True)
        return rec.get("data") if is_envelope(rec.get("data")) else None

    def _write_recipients(self, record_id: str, recipients: Dict[str, Any]) -> None:
        stored = self._read_stored_envelope(record_id)
        if not is_envelope(stored):
            raise _err(f'Cannot change sharing on record "{record_id}": its stored envelope could not be read.', "ENCRYPTION_DATA_UNAVAILABLE")
        self._enc.deks[record_id]["recipients"] = dict(recipients)
        self._enc.passthrough[record_id] = dict(stored, k=recipients)
        self.post_record(config={"record_id": record_id})

    def _enc_add_recipients(self, record_id: str, ids: List[str]) -> None:
        s = self._enc
        if s is None or not ids:
            return
        entry = self._load_for_rewrap(record_id)
        if entry is None:
            return
        me = self._me()
        if entry["own"] != me:
            raise _err("Only the record owner can share an encrypted record, because adding a key wrap means writing the record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
        targets = [i for i in ids if i != me]
        keys = self._peer_keys(targets)
        missing = [i for i in targets if not keys.get(i)]
        if missing:
            raise _err(f"These users have no encryption key yet, so they cannot be given access: {', '.join(missing)}. "
                       "A user's key is created the first time they log in with encryption enabled.", "ENCRYPTION_RECIPIENT_HAS_NO_KEY")
        recipients = dict(entry["recipients"])
        anchor = self._anchor_of(entry)
        aad = self._payload_aad(entry["own"], entry["anch"], anchor)
        for u in targets:
            pub, fpr = keys[u]
            recipients[u] = {"t": "ecdh", **ecdh_wrap(entry["bytes"], pub, self._wrap_info(anchor, entry["own"], u, fpr), self._recipient_aad(aad, u, fpr)), "fpr": fpr}
        self._write_recipients(record_id, recipients)

    def _enc_drop_and_roll(self, record_id: str, ids: Optional[List[str]]) -> None:
        s = self._enc
        if s is None:
            return
        entry = self._load_for_rewrap(record_id)
        if entry is None:
            return
        me = self._me()
        if entry["own"] != me:
            raise _err("Only the record owner can revoke access to an encrypted record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
        # the plaintext FIRST, while the current key is still usable
        rec = self._read_own_record(record_id)
        if rec is None or (rec.get("encrypted") or {}).get("status") == "failed":
            raise _err(f'Cannot change sharing on record "{record_id}": its current data could not be read '
                       f'({((rec or {}).get("encrypted") or {}).get("reason")}), so re-writing the record would destroy it.', "ENCRYPTION_DATA_UNAVAILABLE")
        rid = rec.get("record_id") or record_id
        # who keeps access, from the record just read rather than an older cached map
        current = s.deks.get(rid) or entry
        keep = [] if ids is None else [u for u in current["recipients"] if u != me and u not in ids]
        keys = self._peer_keys(keep) if keep else {}
        missing = [u for u in keep if not keys.get(u)]
        if missing:
            raise _err(f'Cannot revoke on record "{record_id}": these users keep access but their encryption keys could not be read, '
                       f"so re-sharing after the key roll would fail and lock them out: {', '.join(missing)}.", "ENCRYPTION_RECIPIENT_HAS_NO_KEY")
        # The new data key, minted now so the record's sealed attachments are sealed again under it
        # BEFORE the roll: each one is opened with the current key, sealed with the new one and
        # uploaded, and the roll write retires the old copies. Interrupted before the roll, the
        # record still reads exactly as before. Until the roll lands the new copies are sealed under a
        # key the record does not hold, so a failure on the way removes the ones already stored.
        import mimetypes
        from urllib.parse import urlsplit
        next_key = os.urandom(32)
        ctx = {"service": self.service, "owner": self.owner, "recordOwner": me, "recordId": rid}
        reseal, retire = [], []
        for form_key, entries in (rec.get("bin") or {}).items():
            for f in entries:
                if not f.get("encrypted"):
                    continue
                try:
                    content, meta = self._decrypt_file_for(f["url"], self.get_file(f["url"], {"dataType": "bytes", "_raw": True}))
                except SkapiError as err:
                    if err.code == "ENCRYPTION_FILE_STALE_KEY":
                        continue  # sealed under a key an earlier roll retired: nobody can open it, and it must not block this revoke
                    raise _err(f'Cannot revoke on record "{record_id}": its encrypted file "{f.get("filename")}" could not be read, '
                               f"so rolling the key would lock it: {err}", "ENCRYPTION_DATA_UNAVAILABLE") from err
                except Exception as err:
                    raise _err(f'Cannot revoke on record "{record_id}": its encrypted file "{f.get("filename")}" could not be read, '
                               f"so rolling the key would lock it: {err}", "ENCRYPTION_DATA_UNAVAILABLE") from err
                content_type = meta.get("t") or mimetypes.guess_type(f["filename"])[0] or "application/octet-stream"
                reseal.append({"name": f"{form_key}{FILE_MARKER}{b62(len(content))}", "filename": f["filename"],
                               "content": encrypt_file(next_key, ctx, content, f["filename"], content_type, meta.get("lm") or 0),
                               "content_type": "application/octet-stream", "_presealed": True})
                u = urlsplit(f["url"])
                retire.append(f"{u.scheme}://{u.netloc}/{f['path']}")
        copies: List[str] = []
        if reseal:
            result = self._upload_prepared(reseal, rid)
            copies = [u for u in result.get("landed") or [] if u]
            if result["failed"]:
                if copies:
                    try:
                        self._remove_landed_copies(rid, copies)
                    except Exception as err:
                        warnings.warn(f"skapi encryption: the re-sealed copies could not be removed: {err}", RuntimeWarning, stacklevel=3)
                raise result["errors"][0]["error"]
        s.roll.add(rid)
        s.roll_key[rid] = next_key
        config: Dict[str, Any] = {"record_id": rid, "table": {"name": rec["table"]["name"], "access_group": "private"}}
        if retire:
            config["remove_bin"] = retire
        try:
            self.post_record(rec.get("data"), config)
        except Exception:
            if copies:
                try:
                    self._drop_unrolled_copies(rid, next_key, copies)
                except Exception as err:
                    warnings.warn(f"skapi encryption: the re-sealed copies could not be removed: {err}", RuntimeWarning, stacklevel=3)
            raise
        finally:
            # never left for a later write: a pending roll writes a key wrapped for the owner only
            s.roll.discard(rid)
            s.roll_key.pop(rid, None)
        if keep:
            self._enc_add_recipients(rid, keep)

    def _drop_unrolled_copies(self, record_id: str, next_key: bytes, copies: List[str]) -> None:
        """
        After a failed roll write: removes the re-sealed attachment copies, unless the write landed
        after all (only its answer was lost), in which case they are the record's files now. Which
        one it was is read off the stored envelope: the owner's wrap opens to the new key or the old
        one. When that cannot be told, the copies are left alone. As skapi-js dropUnrolledCopies.
        """
        s = self._enc
        raw = self._read_stored_envelope(record_id)
        me = self._me()
        w = (raw.get("k") or {}).get(me) if raw and me else None
        if not raw or not isinstance(w, dict) or w.get("t") != "mk" or not s.mk or raw.get("own") != me:
            return
        try:
            stored = open_(s.mk, b64u_dec(w["iv"]), b64u_dec(w["ct"]),
                           self._recipient_aad(self._payload_aad(raw["own"], raw["anch"], self._anchor_of(raw)), me, "mk"))
        except Exception:
            return
        if stored != next_key:
            self._remove_landed_copies(record_id, copies)

    # ---- public methods ------------------------------------------------------------------------------

    def get_encryption_status(self) -> Dict[str, Any]:
        s = self._enc
        if s is None:
            return {"status": "disabled"}
        out: Dict[str, Any] = {"status": s.status}
        if s.status != "unlocked":
            out["reason"] = s.reason
        if s.user_id:
            out["user_id"] = s.user_id
        if s.fpr:
            out["fingerprint"] = s.fpr
        return out

    @staticmethod
    def is_withheld(value: Any) -> bool:
        return isinstance(value, dict) and value.get(WITHHELD) is True

    def unlock_encryption(self, password: str) -> Dict[str, str]:
        if self._enc is None:
            raise _err("Encryption is not enabled for this instance.", "INVALID_REQUEST")
        if not self._signed_in():
            raise _err("User login is required.", "INVALID_REQUEST")
        if not password:
            raise _err('"password" is required.', "INVALID_PARAMETER")
        self._ensure_keyring(password, create=False)  # opens an existing keyring only
        if self._enc.status != "unlocked":
            raise _err(f"Encryption could not be unlocked: {self._enc.reason}", "ENCRYPTION_LOCKED")
        return {"status": "unlocked"}

    def lock_encryption(self) -> Dict[str, str]:
        if self._enc is None:
            return {"status": "disabled"}
        # keeps an encryption recovery code the app has not collected yet: it can never be shown
        # again, and losing it to a lock left the user without one they never knew existed
        self._enc.clear(keep_recovery=True)
        return {"status": "locked"}

    def _encryption_recovery_info(self) -> Optional[Dict[str, Any]]:
        """The "encryption_recovery" entry of get_connection_info(), or None when encryption is off
        or nobody is signed in. The code is created once, when encryption is first set up for a user,
        and never stored readable, so the FIRST call after that returns it and forgets it; every later
        call returns code None and a message. As in skapi-js."""
        s = self._enc
        if s is None or not self._signed_in():
            return None
        if s.cfg["recovery"] != "code":
            return {"code": None, "message": 'Encryption recovery codes are turned off ("encryption.recovery" is "none").'}
        if s.pending_recovery_code and s.pending_recovery_user == self._me():
            code, s.pending_recovery_code, s.pending_recovery_user = s.pending_recovery_code, "", ""
            return {"code": code, "message": "This is your encryption recovery code. Save it now: it is shown only this once. "
                                             "If you forget your password, it is the only way to read your encrypted private data again."}
        if s.status != "unlocked":
            return {"code": None, "message": "Encryption is locked. Unlock it with unlock_encryption() or unlock_encryption_with_recovery_code(), "
                                             "then call regenerate_encryption_recovery_code() to get a new encryption recovery code."}
        return {"code": None, "message": "Your encryption recovery code was shown once and cannot be shown again. "
                                         "Call regenerate_encryption_recovery_code() to get a new one."}

    def unlock_encryption_with_recovery_code(self, code: str, password: Optional[str] = None) -> Dict[str, Any]:
        s = self._enc
        if s is None:
            raise _err("Encryption is not enabled for this instance.", "INVALID_REQUEST")
        if not self._signed_in():
            raise _err("User login is required. Reset the password and log in first, then use the encryption recovery code.", "INVALID_REQUEST")
        if not code:
            raise _err('"code" is required.', "INVALID_PARAMETER")
        uid = self._me()
        keyring = self._find_keyring(uid)
        if not keyring:
            raise _err("This account has no encryption keyring, so there is nothing to recover.", "NOT_EXISTS")
        raw = decode_recovery_code(code)
        data = dict(keyring["data"])
        mk = None
        for w in sorted((w for w in data.get("wraps", []) if w.get("p") == "recovery"), key=lambda w: w.get("created", 0), reverse=True):
            try:
                rk = hkdf(raw, b64u_dec(w["kdf"]["s"]), self._e_s("recovery", uid))
                mk = open_(rk, b64u_dec(w["iv"]), b64u_dec(w["ct"]), utf8(f"{self._e_s('rk', uid)}|HKDF-SHA256|{w['kdf']['s']}"))
                break
            except Exception:
                continue
        if mk is None:
            raise _err("That encryption recovery code did not open the keyring. Check it against the copy you saved when encryption was set up.", "ENCRYPTION_BAD_RECOVERY_CODE")
        self._adopt_keyring(keyring, mk, uid)
        wraps = list(data.get("wraps", []))
        repaired, new_code = False, None
        if password:
            wraps = [w for w in wraps if w.get("p") != "password"] + [self._password_wrap(mk, password, uid)]
            repaired = True
        if s.cfg["recovery"] == "code":
            w, new_code = self._recovery_wrap(mk, uid)
            wraps = [x for x in wraps if x.get("p") != "recovery"] + [w]
        data["wraps"], data["updated"] = wraps, int(time.time() * 1000)
        self.post_record(data, {"record_id": keyring["record_id"]})
        return {"status": "unlocked", "repaired": repaired, "encryptionRecoveryCode": new_code}

    def regenerate_encryption_recovery_code(self) -> Dict[str, str]:
        s = self._enc
        if s is None:
            raise _err("Encryption is not enabled for this instance.", "INVALID_REQUEST")
        if s.status != "unlocked" or not s.mk:
            raise _err("Encryption must be unlocked to issue an encryption recovery code. Only someone who can already decrypt can create one.", "ENCRYPTION_LOCKED")
        if s.cfg["recovery"] == "none":
            raise _err('Encryption recovery codes are turned off for this instance ("encryption.recovery" is "none").', "INVALID_REQUEST")
        res = self.get_records({"record_id": s.keyring_record_id}, {"limit": 1})
        if not res.get("list"):
            raise _err("The encryption keyring could not be read.", "ENCRYPTION_KEYRING_CORRUPT")
        data = dict(res["list"][0]["data"])
        if not (data.get("self") or {}).get("ct"):
            raise _err("This keyring predates encryption recovery code rotation and cannot issue a new code. "
                       "Use unlock_encryption_with_recovery_code() with the existing code, which issues a replacement.", "ENCRYPTION_KEYRING_CORRUPT")
        mk = open_(s.mk, b64u_dec(data["self"]["iv"]), b64u_dec(data["self"]["ct"]), utf8(self._e_s("self", s.user_id)))
        w, code = self._recovery_wrap(mk, s.user_id)
        data["wraps"] = [x for x in data.get("wraps", []) if x.get("p") != "recovery"] + [w]
        data["updated"] = int(time.time() * 1000)
        self.post_record(data, {"record_id": s.keyring_record_id})
        return {"encryptionRecoveryCode": code}

    def pin_peer_key(self, user_id: str, fingerprint_: str) -> None:
        s = self._enc
        if s is None or s.status != "unlocked":
            raise _err("Encryption is locked.", "ENCRYPTION_LOCKED")
        s.pins[user_id] = fingerprint_
        s.peer_pub.pop(user_id, None)
        self._persist_pins()
