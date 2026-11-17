"""
Database methods, ported from skapi-js (src/methods/database.ts): same validation, same request
bodies, same decoding of the records the server returns.
"""

from __future__ import annotations

import json
import mimetypes
import os
import random
import re
import string
import time
import warnings
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, urlsplit

from .errors import SkapiError
from ._encryption import parse_file_marker

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
NUMBER_SHIFT = 4503599627370496  # 2^52: number index values are stored shifted by this
CONDITIONS = ["gt", "gte", "lt", "lte", ">", ">=", "<", "<=", "=", "eq"]
CONDITIONS_NE = CONDITIONS + ["!=", "ne"]
SPECIAL_INDEX = ("$updated", "$uploaded", "$referenced_count", "$user_id")
ORDER_BY = ["average_number", "total_number", "number_count", "average_bool", "total_bool",
            "bool_count", "string_count", "index_name", "number_of_records"]
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_CONTROL = re.compile(r"[\u0000-\u001F\u007F]|\U0010FFFF")
_table_string_warned = False
# Seconds before a private access key expires at which it is no longer sent.
_PRIVATE_KEY_REFRESH_MARGIN = 60
_EXPIRING_KEY = re.compile(r"([0-9]+)\.")


def _jd(v):
    """A value as it appears in an error message; never fails on odd types."""
    return json.dumps(v, default=repr, ensure_ascii=False)


def _err(message: str, code: str = "INVALID_PARAMETER") -> SkapiError:
    return SkapiError(message, code)


def js_length(text: str) -> int:
    """String length as JavaScript counts it (UTF-16 code units: an emoji counts 2)."""
    return len(text.encode("utf-16-le")) // 2


def from_base62(text: str) -> int:
    n = 0
    for i, ch in enumerate(reversed(text)):
        idx = BASE62.find(ch)
        n += idx * (62 ** i)
    return n


def to_base62(n: int) -> str:
    if n == 0:
        return "0"
    out = ""
    while n > 0:
        n, r = divmod(n, 62)
        out = BASE62[r] + out
    return out


def encode_delimiters(value: str) -> str:
    return value.replace("%", "%25").replace("/", "%2F").replace("!", "%21").replace("*", "%2A").replace("#", "%23")


def decode_delimiters(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    value = re.sub(r"%(2F|21|2A|23)", lambda m: {"2F": "/", "21": "!", "2A": "*", "23": "#"}[m.group(1).upper()], value, flags=re.IGNORECASE)
    return re.sub(r"%25", "%", value, flags=re.IGNORECASE)


def validate_string(value: Any, field: str, *, allow_empty: bool = False, max_length: int = 256,
                    escape: bool = False, no_dollar: bool = False, alphanumeric: bool = False) -> str:
    if not isinstance(value, str):
        raise _err(f'"{field}" should be type: <string>.')
    if alphanumeric and re.search(r"[^a-zA-Z0-9]", value):
        raise _err(f'"{field}" should only contain alphanumeric characters.')
    if not allow_empty and len(value) == 0:
        raise _err(f'"{field}" is required.')
    if max_length and js_length(value) > max_length:
        raise _err(f'"{field}" should be <= {max_length} characters.')
    if _CONTROL.search(value):
        raise _err(f'"{field}" cannot include control characters or unsupported sentinel characters.')
    if escape:
        value = encode_delimiters(value)
        if max_length and js_length(value) > max_length:
            raise _err(f'"{field}" should be <= {max_length} characters. "/", "!", "*", "#" and "%" count as 3 characters each.')
    if no_dollar and value.startswith("$"):
        raise _err(f'"{field}" cannot start with "$".')
    return value


def table_name(v, field="table.name", allow_empty=False):
    return validate_string(v, field, allow_empty=allow_empty, escape=True)


def tag_name(v, field="tag", allow_empty=False):
    return validate_string(v, field, allow_empty=allow_empty, escape=True)


def index_name(v, field="index.name", allow_empty=False):
    return validate_string(v, field, allow_empty=allow_empty, escape=True, no_dollar=True)


def user_id(v, field="User ID"):
    if not v:
        raise _err(f"{field} is empty.")
    if not isinstance(v, str):
        raise _err(f"{field} should be type: string.")
    if not _UUID.match(v):
        raise _err(f"{field} is invalid.")
    return v


def access_group_in(v, signed_in: bool):
    if isinstance(v, bool):
        raise _err('"table.access_group" should be type: <number | string>.')
    if isinstance(v, (int, float)):
        if v > 99 or v < 0:
            raise _err('"table.access_group" value should be within a range of 0 ~ 99.')
        result = v
    elif isinstance(v, str):
        mapping = {"*": "private", "private": "private", "public": 0, "authorized": 1, "admin": 99}
        if v not in mapping:
            raise _err('"table.access_group" is invalid.')
        result = mapping[v]
    else:
        raise _err('"table.access_group" should be type: <number | string>.')
    if not signed_in and result:
        raise _err("Unsigned users have no access to records with access group.")
    return result


def access_group_out(v) -> Union[str, int]:
    if v == "**":
        return "private"
    try:
        n = int(str(v))
    except ValueError:
        return v
    return {0: "public", 1: "authorized", 99: "admin"}.get(n, n)


def index_value(v, field="index.value"):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        if abs(v) > NUMBER_SHIFT:
            raise _err("Number value should be within range -4503599627370496 ~ +4503599627370496")
        return v
    if isinstance(v, str):
        return validate_string(v, field, allow_empty=True)
    raise _err(f'"{field}" should be type: <number | boolean | string>.')


def _typeof(v) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    return "object"


def _condition(v, allowed=CONDITIONS, field="condition"):
    if v not in allowed:
        raise _err(f'{_jd(v)} is invalid in "{field}". allowed types or values are: ' + ", ".join(_jd(c) for c in allowed) + ".")
    return v


def _record_or_unique_id(query: dict, is_delete: bool) -> Optional[dict]:
    """ID mode: only service, owner and record_id (or else unique_id) survive."""
    if is_delete:
        for key in ("record_id", "unique_id"):
            v = query.get(key)
            if v is not None and (v == "" or v == []):
                raise _err(f'"{key}" is empty.')
    if not query.get("record_id") and not query.get("unique_id"):
        return None
    out = {}
    for key in ("service", "owner"):
        if query.get(key):
            out[key] = query[key]
    key = "record_id" if query.get("record_id") else "unique_id"
    value = query[key]

    def one(v, field):
        if key == "record_id":
            return validate_string(v, field, alphanumeric=True, max_length=0)
        if not isinstance(v, str):
            raise _err(f'"{field}" should be type: <string>.')
        if not v:
            raise _err(f'"{field}" is required.')
        return v

    if isinstance(value, list):
        if not is_delete:
            raise _err(f'"{key}" should be type: <string>.')
        if not value:
            raise _err(f'"{key}" should not be an empty list.')
        if len(value) > 1000:
            raise _err(f'"{key}" can hold at most 1000 ids.')
        out[key] = [one(v, f"{key}[{i}]") for i, v in enumerate(value)]
    else:
        out[key] = one(value, key)
    return out


def _typed_string(v: str) -> Any:
    """Index values as the server stores them ("!S%text", "!N%<number + 2^52>", "!B%1")."""
    prefix, body = v[:3], v[3:]
    if prefix == "!S%":
        return body
    if prefix == "!B%":
        return body == "1"
    if prefix in ("!L%", "!D%"):
        try:
            return json.loads(body)
        except ValueError:
            raise SkapiError("Value parse error.", "PARSE_ERROR") from None
    if prefix == "!N%":
        whole, _, frac = body.partition(".")
        n = int(whole) - NUMBER_SHIFT
        if not frac:
            return n
        if n >= 0 or not re.search(r"[1-9]", frac):
            return float(f"{n}.{frac}")
        digits = frac.rstrip("0")
        complement = "".join(str(9 - int(d)) for d in digits[:-1]) + str(10 - int(digits[-1]))
        return float(f"-{-n - 1}.{complement}")
    return v


def parse_stored_data(r: Any) -> Any:
    """The stored record payload ('!J%<json>' and the legacy forms) as the value that was posted."""
    if isinstance(r, str):
        if r.startswith("!J%"):
            try:
                return json.loads(r[3:])
            except ValueError:
                return r
        if r == "!D%{}":
            return {}
        if r == "!L%[]":
            return []
        return r
    if isinstance(r, dict) and list(r.keys()) == ["__json__"] and isinstance(r["__json__"], str):
        try:
            return json.loads(r["__json__"])
        except ValueError:
            return r
    return r


def _is_offload_marker(r: Any) -> bool:
    return (isinstance(r, dict) and list(r.keys()) == ["__data__"] and isinstance(r["__data__"], str)
            and r["__data__"].endswith("/__data__/__json__.json"))


def _random_key(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


# The ASCII bytes a URL path encoder percent-encodes (as the WHATWG URL parser skapi-js uses):
# C0 controls except tab/LF/CR, space " < > ` { } DEL, and ^. get_file itself only encodes the
# space, which is in this set, so urls from either SDK are undone the same way.
_URL_PATH_ENCODED_ASCII = frozenset([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x22, 0x3C, 0x3E, 0x5E, 0x60, 0x7B, 0x7D, 0x7F])


def undo_url_path_encoding(url: str) -> str:
    """
    Undoes only what a url path encoder produces: uppercase %XX of the bytes above and of valid
    UTF-8 sequences. Any other "%" is part of the file's own name ("50%25 off.pdf", "a%2Fb.pdf")
    and is kept. Same as skapi-js database.ts undoUrlPathEncoding.
    """
    def run(m):
        tokens = re.findall(r"%[0-9A-F]{2}", m.group(0))
        out, i = "", 0
        while i < len(tokens):
            b = int(tokens[i][1:], 16)
            if b < 0x80:
                out += chr(b) if b in _URL_PATH_ENCODED_ASCII else tokens[i]
                i += 1
                continue
            n = 4 if b >= 0xF0 else 3 if b >= 0xE0 else 2 if b >= 0xC0 else 1
            seq = tokens[i:i + n]
            try:
                if len(seq) < n or n == 1:
                    raise ValueError
                out += bytes(int(t[1:], 16) for t in seq).decode("utf-8")
                i += n
            except ValueError:
                out += tokens[i]
                i += 1
        return out
    return re.sub(r"(?:%[0-9A-F]{2})+", run, url)


class DatabaseMixin:
    """Mixed into Skapi. Needs: _call(path, data, auth=, method=, fetch_options=, ...), _signed_in(),
    _fresh_id_token(), user, service, owner, _ensure_connection(), _requester."""

    # caches, created by Skapi.__init__
    _private_access_key: Dict[str, str]
    _my_unique_ids: Dict[str, Dict[str, str]]

    def _scope(self, service=None, owner=None) -> str:
        return f"{service or self.service}/{owner or self.owner}"

    def _forget_unique_ids_of(self, scope: str, record_ids) -> None:
        """Drops every remembered unique_id that points at one of these records (renamed or deleted)."""
        known = self._my_unique_ids.get(scope)
        if known:
            for uid in [u for u, rid in known.items() if rid in record_ids]:
                del known[uid]

    def _remember_unique_id(self, scope: str, record: dict) -> None:
        """After a write: the record's current unique_id, and none of its earlier ones."""
        rid = record.get("record_id")
        if not rid:
            return
        self._forget_unique_ids_of(scope, (rid,))
        if record.get("unique_id"):
            self._my_unique_ids.setdefault(scope, {})[record["unique_id"]] = rid

    def _remember_handed_out_url(self, handed_out: str, requested: str) -> None:
        """
        A record file url get_file gave out (as "endpoint" or "info") may come back to delete_files
        or remove_bin. The server removes the stored file url by exact string, so the url given out
        is mapped back to the exact url it was made from. Kept only when the two differ, or when the
        url looks encoded ("a%20b.pdf" is its own stored form), so the map stays small.
        """
        base = handed_out.split("?")[0]
        raw = requested.split("?")[0]
        if base.startswith("https://") and (base != raw or undo_url_path_encoding(base) != base):
            self._handed_out_file_urls[base] = raw

    def _stored_record_file_url(self, url: str) -> str:
        """
        The form the server stores a record file url in. A non-public file's url from get_file
        ends in "?t=<token>" and has its spaces percent-encoded; sent back like that it matched no
        stored file, and the server answers success when nothing matched, so the file stayed.
        1. A url get_file handed out on this client maps back to the exact url it was made from.
        2. Otherwise a url with a query had its path encoded, and only that encoding is undone.
        3. A url without a query is already the stored form and is sent as written.
        """
        base = url.split("?")[0]
        known = getattr(self, "_handed_out_file_urls", {}).get(base)
        if known is not None:
            return known
        return undo_url_path_encoding(base) if "?" in url else base

    def _is_admin(self) -> bool:
        u = self.user
        return bool(u and u.get("service") == self.service and u.get("owner") == "skapi")

    def _require_login_gate(self, method: str):
        conn = self._ensure_connection()
        if not self._signed_in() and (conn or {}).get("opt", {}).get("require_login") is True:
            raise SkapiError(f'This project requires users to sign in before reading its database, so "{method}" is not available to a signed-out visitor.', "REQUIRE_LOGIN")

    # ---- query builder ----------------------------------------------------------------------

    def _build_query(self, query: Optional[dict], is_delete: bool):
        global _table_string_warned
        query = dict(query or {})
        scope = self._scope(query.get("service"), query.get("owner"))
        is_reference_fetch: Any = None
        signed_in = self._signed_in()

        id_query = _record_or_unique_id(query, is_delete)
        if id_query is not None:
            query = id_query
            single = query.get("record_id") or query.get("unique_id")
            if isinstance(single, list):
                if "unique_id" in query:
                    for uid in single:
                        self._my_unique_ids.get(scope, {}).pop(uid, None)
                elif is_delete:
                    self._forget_unique_ids_of(scope, set(single))
                return query, ""
            is_reference_fetch = single
            cached_key = self._cached_private_key(single)
            if cached_key:
                query["private_key"] = cached_key
            cached = self._my_unique_ids.get(scope, {}).get(single)
            if is_delete:
                self._my_unique_ids.get(scope, {}).pop(single, None)
                if "record_id" in query:
                    self._forget_unique_ids_of(scope, (single,))
            elif cached:
                query["record_id"] = cached
            return query, is_reference_fetch

        is_admin = self._is_admin()
        ref_user_is_me = False
        ref = query.get("reference")
        if isinstance(ref, dict):
            rid = ref.get("record_id") or ref.get("unique_id")
            if rid:
                is_reference_fetch = rid
                cached_key = self._cached_private_key(rid)
                if cached_key:
                    query["private_key"] = cached_key
                query["reference"] = rid
            elif ref.get("user_id"):
                ref_user_is_me = bool(self.user) and ref["user_id"] == self.user.get("user_id")
                query["reference"] = ref["user_id"]

        table = query.get("table")
        if isinstance(table, str):
            if not _table_string_warned:
                _table_string_warned = True
                warnings.warn(f'skapi: table: "{table}" in get_records() and delete_records() is deprecated. Write the access group with the name: '
                              f'table: {{"name": "{table}", "access_group": "public"}}. See https://docs.skapi.com/deprecated/deprecated.html',
                              DeprecationWarning, stacklevel=3)
            query["table"] = table = {"name": table, "access_group": 0}
        if not is_admin and isinstance(table, dict) and table.get("access_group") is None:
            raise _err('"table.access_group" is required: a table is always { name, access_group }. '
                       'To read what references a record in every table, send "reference" without "table".')
        index = query.get("index")
        if isinstance(index, dict) and "range" in index and "condition" in index:
            index = dict(index)
            del index["range"]
            query["index"] = index

        reads_by_reference = not is_delete and signed_in and bool(is_reference_fetch or (isinstance(query.get("reference"), str) and query.get("reference")))
        required_table = not (ref_user_is_me or is_admin or reads_by_reference)

        out: Dict[str, Any] = {}
        if "table" in query:
            t = query["table"]
            if not isinstance(t, dict):
                raise _err(f'{_jd(t)} is invalid in "table". allowed type or value is: Type<object>.')
            nt = dict(t)
            if "name" in t:
                nt["name"] = table_name(t["name"])
            if "access_group" in t:
                nt["access_group"] = access_group_in(t["access_group"], signed_in)
            if "subscription" in t:
                nt["subscription"] = user_id(t["subscription"], 'User ID in "subscription"')
            out["table"] = nt
        elif required_table:
            raise _err('Key "table" is required.')
        if "reference" in query:
            if not isinstance(query["reference"], str):
                raise _err(f'{_jd(query["reference"])} is invalid in "reference". allowed type or value is: Type<string>.')
            out["reference"] = query["reference"]
        if "index" in query:
            i = query["index"]
            if not isinstance(i, dict):
                raise _err(f'{_jd(i)} is invalid in "index". allowed type or value is: Type<object>.')
            ni = dict(i)
            raw_name = i.get("name")
            if "name" in i:
                ni["name"] = raw_name if raw_name in SPECIAL_INDEX else index_name(raw_name)
            if "value" in i:
                v = i["value"]
                if raw_name in ("$updated", "$uploaded", "$referenced_count"):
                    if isinstance(v, bool) or not isinstance(v, (int, float)):
                        raise _err('"index.value" should be type: number.')
                elif raw_name == "$user_id":
                    v = user_id(v)
                elif v == "":
                    v = ""
                elif isinstance(v, str) and isinstance(raw_name, str) and raw_name.endswith("."):
                    v = validate_string(v, "index.value", allow_empty=True, escape=True)
                else:
                    v = index_value(v)
                ni["value"] = v
            if "condition" in i:
                ni["condition"] = _condition(i["condition"], CONDITIONS, "condition")
            if "range" in i:
                if "value" not in i:
                    raise _err('"index.value" is required.')
                if raw_name == "$record_id":
                    raise _err('Cannot do "index.range" on $record_id')
                r = i["range"]
                if _typeof(i["value"]) != _typeof(r):
                    raise _err('"index.range" type should match the type of "index.value".')
                if isinstance(r, str):
                    r = validate_string(r, "index.range", allow_empty=True, escape=isinstance(raw_name, str) and raw_name.endswith("."))
                ni["range"] = r
            out["index"] = ni
        if "tag" in query and query["tag"] is not None:
            if not isinstance(query["tag"], str):
                raise _err('"tag" should be type: string.')
            out["tag"] = tag_name(query["tag"])
        for key in ("private_key", "service", "owner"):
            if key in query:
                if not isinstance(query[key], str):
                    raise _err(f'{_jd(query[key])} is invalid in "{key}". allowed type or value is: Type<string>.')
                out[key] = query[key]
        return out, is_reference_fetch

    # ---- reads ------------------------------------------------------------------------------

    def get_records(self, query: Optional[dict] = None, fetch_options: Optional[dict] = None) -> dict:
        """Records by id, unique id, table, index, tag or reference. See the docs for the query keys."""
        self._require_login_gate("get_records")
        q, ref_id = self._build_query(query, False)
        signed_in = self._signed_in()
        result = self._call("get-records", q, auth=signed_in, method="POST" if signed_in else "GET", fetch_options=fetch_options)
        if ref_id and isinstance(result, dict) and isinstance(result.get("reference_private_key"), str):
            self._private_access_key[ref_id] = result["reference_private_key"]
        if isinstance(result, dict) and isinstance(result.get("list"), list):
            result["list"] = [self._normalize_record(r) for r in result["list"]]
        return result

    def delete_records(self, query: dict, fetch_options: Optional[dict] = None):
        """Deletes your records (or any, as an admin) by id, unique id, or query."""
        self._ensure_connection()
        q, ref_id = self._build_query(query, True)
        result = self._call("del-records", q, auth=True, fetch_options=fetch_options)
        if ref_id and isinstance(result, dict) and isinstance(result.get("reference_private_key"), str):
            self._private_access_key[ref_id] = result["reference_private_key"]
        if isinstance(result, dict) and isinstance(result.get("list"), list):
            out = []
            for r in result["list"]:
                try:
                    out.append(self._normalize_record(r, skip_data_fetch=True, skip_bin_resolve=True) if isinstance(r, dict) else r)
                except Exception:
                    out.append(r)
            result["list"] = out
            # A delete by query names no ids up front: the unique_ids remembered for the records it
            # deleted are dropped here, from the records it returns (as skapi-js deleteRecords).
            deleted = {r.get("record_id") or r.get("rec") for r in out if isinstance(r, dict)}
            deleted = {rid for rid in deleted if isinstance(rid, str) and rid}
            if deleted:
                self._forget_unique_ids_of(self._scope((query or {}).get("service"), (query or {}).get("owner")), deleted)
        if isinstance(result, dict) and result.get("message"):
            return result["message"]
        return result

    def get_tables(self, query: Optional[dict] = None, fetch_options: Optional[dict] = None) -> dict:
        query = query or {}
        p: Dict[str, Any] = {}
        if "table" in query:
            p["table"] = table_name(query["table"], "table", allow_empty=True)
        if "condition" in query:
            p["condition"] = _condition(query["condition"], CONDITIONS_NE)
        p.update({k: query[k] for k in ("service", "owner") if k in query})
        res = self._call("get-table", p, auth=self._signed_in(), fetch_options=fetch_options)
        names = {"pv": "private", "00": "public", "01": "authorized", "99": "admin"}
        for item in res.get("list", []) if isinstance(res, dict) else []:
            for k in list(item.keys()):
                if k.startswith("grp_"):
                    x = k[4:]
                    item[f"number_of_records_in_access_group_{names.get(x, x)}"] = item.pop(k)
            for old, new in (("cnt_rec", "number_of_records"), ("tbl", "table"), ("srvc", "service")):
                if old in item:
                    item[new] = item.pop(old)
            if "table" in item:
                item["table"] = decode_delimiters(item["table"])
        return res

    def get_tags(self, query: Optional[dict] = None, fetch_options: Optional[dict] = None) -> dict:
        query = query or {}
        p: Dict[str, Any] = {}
        if "table" in query:
            p["table"] = table_name(query["table"], "table", allow_empty=True)
        if "tag" in query:
            p["tag"] = tag_name(query["tag"], "tag", allow_empty=True)
        if "condition" in query:
            p["condition"] = _condition(query["condition"], CONDITIONS_NE)
        p.update({k: query[k] for k in ("service", "owner") if k in query})
        res = self._call("get-tag", p, auth=self._signed_in(), fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            out = []
            for item in res["list"]:
                parts = item.get("tag", "").split("/")
                out.append({"table": decode_delimiters(parts[1] if len(parts) > 1 else ""), "tag": decode_delimiters(parts[0]),
                            "number_of_records": item.get("cnt_rec")})
            res["list"] = out
        return res

    def get_indexes(self, query: dict, fetch_options: Optional[dict] = None) -> dict:
        if not (query or {}).get("table"):
            raise _err('"table" is required.')
        p: Dict[str, Any] = {"table": table_name(query["table"], "table", allow_empty=True)}
        if "index" in query:
            p["index"] = index_name(query["index"], "index.name")
        if "order" in query:
            o = query["order"]
            if not isinstance(o, dict):
                raise _err(f'{_jd(o)} is invalid in "order". allowed type or value is: Type<object>.')
            no = dict(o)
            if "by" in o:
                no["by"] = _condition(o["by"], ORDER_BY, "by")
            if "value" in o:
                v = o["value"]
                if o.get("by") == "index_name" and isinstance(v, str):
                    v = validate_string(v, "order.value", allow_empty=True, escape=True)
                elif not isinstance(v, (str, int, float, bool)):
                    raise _err('"order.value" should be type: <string | number | boolean>.')
                no["value"] = v
            if "condition" in o:
                no["condition"] = _condition(o["condition"], CONDITIONS_NE)
            if "by" not in no:
                raise _err('"order.by" is required.')
            if "condition" in no and "value" not in no:
                raise _err('"value" is required for "condition".')
            if "index" in p and not p["index"].endswith("."):
                raise _err('"index" should be a parent index name of the compound index when using "order.by"')
            p["order"] = no
        p.update({k: query[k] for k in ("service", "owner") if k in query})
        res = self._call("get-index", p, auth=self._signed_in(), fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            out = []
            rename = {"cnt_bool": "boolean_count", "cnt_numb": "number_count", "totl_numb": "total_number", "totl_bool": "total_bool",
                      "avrg_numb": "average_number", "avrg_bool": "average_bool", "cnt_str": "string_count"}
            for i in res["list"]:
                parts = i.get("idx", "").split("/")
                item = {"table": decode_delimiters(parts[1] if len(parts) > 1 else ""), "index": decode_delimiters(parts[2] if len(parts) > 2 else ""),
                        "number_of_records": i.get("cnt_rec")}
                for k, v in rename.items():
                    if k in i:
                        item[v] = i[k]
                out.append(item)
            res["list"] = out
        return res

    def get_unique_id(self, query: Optional[dict] = None, fetch_options: Optional[dict] = None) -> dict:
        query = query or {}
        p: Dict[str, Any] = {}
        if "unique_id" in query:
            if not isinstance(query["unique_id"], str):
                raise _err(f'{_jd(query["unique_id"])} is invalid in "unique_id". allowed type or value is: Type<string>.')
            p["unique_id"] = query["unique_id"]
        if "condition" in query:
            p["condition"] = _condition(query["condition"], CONDITIONS_NE)
        p.update({k: query[k] for k in ("service", "owner") if k in query})
        res = self._call("get-uniqueid", p, auth=self._signed_in(), fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [{"unique_id": i.get("unq"), "record_id": i.get("rec")} for i in res["list"]]
        return res

    # ---- writes -----------------------------------------------------------------------------

    def _setup_post_config(self, config: dict) -> tuple:
        """Validated config (what goes on the wire) and the reference id to remember a private key under."""
        if not isinstance(config, dict):
            raise _err('"config" argument is required.')
        signed_in = self._signed_in()
        c = dict(config)
        if not c.get("record_id") and not c.get("table"):
            raise _err('"table.name" is required.')
        if isinstance(c.get("table"), str):
            c["table"] = {"name": c["table"]} if c.get("record_id") else {"name": c["table"], "access_group": 0}
        scope = self._scope(c.get("service"), c.get("owner"))
        out: Dict[str, Any] = {}
        is_reference_post = None

        if "record_id" in c and c["record_id"] is not None:
            rid = c["record_id"]
            cached = self._my_unique_ids.get(scope, {}).get(rid) if isinstance(rid, str) else None
            out["record_id"] = cached or validate_string(rid, "record_id", max_length=0)
        if "unique_id" in c:
            if c["unique_id"] is not None and not isinstance(c["unique_id"], str):
                raise _err(f'{_jd(c["unique_id"])} is invalid in "unique_id". allowed types or values are: Type<string>, null.')
            out["unique_id"] = c["unique_id"]
        if "readonly" in c:
            if not isinstance(c["readonly"], bool):
                raise _err(f'{_jd(c["readonly"])} is invalid in "readonly". allowed type or value is: Type<boolean>.')
            out["readonly"] = c["readonly"]
        if "table" in c and c["table"] is not None:
            t = c["table"]
            if not isinstance(t, dict):
                raise _err(f'{_jd(t)} is invalid in "table". allowed types or values are: Type<string>, Type<object>.')
            nt = dict(t)
            if "name" in t:
                nt["name"] = table_name(t["name"])
            if "access_group" in t:
                nt["access_group"] = access_group_in(t["access_group"], signed_in)
            if "subscription" in t and t["subscription"] is not None:
                if not isinstance(t["subscription"], dict):
                    raise _err('"table.subscription" should be type: <object | null>.')
                for k, v in t["subscription"].items():
                    if k in ("is_subscription_record", "upload_to_feed", "notify_subscribers", "feed_referencing_records", "notify_referencing_records") and not isinstance(v, bool):
                        raise _err(f'"table.subscription.{k}" should be type: <boolean>.')
            out["table"] = nt
        if "notification" in c and c["notification"] is not None:
            n = c["notification"]
            if not isinstance(n, dict):
                raise _err('"notification" should be an object with "title" and "body".')
            for k in ("title", "body"):
                if not isinstance(n.get(k), str) or not n[k].strip():
                    raise _err(f'"notification.{k}" is required.')
            out["notification"] = {"title": n["title"], "body": n["body"]}
        if "source" in c and c["source"] is not None:
            s = dict(c["source"])
            if "referencing_limit" in s and s["referencing_limit"] is not None:
                v = s["referencing_limit"]
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise _err('"reference_limit" should be type: <number | null>')
                if v < 0:
                    raise _err('"reference_limit" should be >= 0')
                if v > 4503599627370546:
                    raise _err('"reference_limit" should be <= 4503599627370546')
            for k in ("prevent_multiple_referencing", "can_remove_referencing_records", "only_granted_can_reference", "allow_granted_to_grant_others"):
                if k in s and not isinstance(s[k], bool):
                    raise _err(f'"source.{k}" should be type: <boolean>.')
            if "referencing_index_restrictions" in s:
                r = s["referencing_index_restrictions"]
                if not r:
                    s["referencing_index_restrictions"] = None
                else:
                    items = r if isinstance(r, list) else [r]
                    fixed = []
                    for item in items:
                        if "name" not in item:
                            raise _err('Key "name" is required.')
                        if "range" in item:
                            raise _err('Index restriction "range" type should match the type of "value".')
                        ni = dict(item)
                        ni["name"] = index_name(item["name"], '"name" in "index_restrictions"')
                        if "value" in item:
                            ni["value"] = index_value(item["value"])
                        ni["condition"] = item.get("condition") if item.get("condition") in CONDITIONS_NE else None
                        fixed.append(ni)
                    s["referencing_index_restrictions"] = fixed
            out["source"] = s
        if "reference" in c:
            ref = c["reference"]
            if ref is None:
                out["reference"] = {"record_id": None}
            elif not ref:
                pass
            elif isinstance(ref, str):
                out["reference"] = self._my_unique_ids.get(scope, {}).get(ref) or ref
                is_reference_post = out["reference"]
            elif isinstance(ref, dict):
                nr = dict(ref)
                if ref.get("record_id") is not None:
                    nr["record_id"] = validate_string(ref["record_id"], "reference.record_id", alphanumeric=True, max_length=0)
                if "unique_id" in ref and not isinstance(ref["unique_id"], str):
                    raise _err('"reference.unique_id" should be type: <string>.')
                out["reference"] = nr
            else:
                raise _err('"reference" should be type: <string | object>.')
        if "index" in c:
            i = c["index"]
            if i is None:
                out["index"] = None
            else:
                if not isinstance(i, dict):
                    raise _err('"index" should be type: <object | null>.')
                ni = dict(i)
                if "name" in i:
                    ni["name"] = index_name(i["name"])
                if "value" in i:
                    ni["value"] = index_value(i["value"])
                out["index"] = ni
        if "tags" in c and c["tags"] is None:
            out["tags"] = None  # removes every tag, as in skapi-js
        elif "tags" in c:
            tags = c["tags"]
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            if not isinstance(tags, list):
                raise _err('"tag" should be type: <string | string[]>.')
            out["tags"] = [tag_name(t) for t in tags]
        if "remove_bin" in c:
            rb = c["remove_bin"]
            # JavaScript falsiness: None, False, 0 and "" mean null; an empty list removes nothing
            if rb is None or rb is False or rb == 0 or rb == "":
                out["remove_bin"] = None
            else:
                if not isinstance(rb, list):
                    raise _err('"remove_bin" should be type: <string[] | BinaryFile[] | null>')
                fixed = []
                for item in rb:
                    if isinstance(item, str):
                        # the stored file url, as delete_files sends it: no "?t=<token>", and
                        # get_file's encoding undone without touching a "%" of the name itself
                        fixed.append(self._stored_record_file_url(item))
                    elif isinstance(item, dict) and item.get("url") and item.get("size") and item.get("filename"):
                        u = urlsplit(item["url"])
                        fixed.append(f"{u.scheme}://{u.netloc}/{item['path']}")
                    else:
                        raise _err('"remove_bin" should be type: <string[] | BinaryFile[] | null>')
                out["remove_bin"] = fixed
        for key in ("service", "owner"):
            if key in c:
                out[key] = c[key]

        if not signed_in:
            t = out.get("table") or {}
            if out.get("record_id"):
                raise _err("Public users cannot update existing records.", "INVALID_REQUEST")
            if t.get("access_group") not in ("public", 0):
                raise _err("Public users can only post records to public tables.", "INVALID_REQUEST")
            if any((t.get("subscription") or {}).values()):
                raise _err("Public users cannot post subscription records.", "INVALID_REQUEST")
            if out.get("remove_bin"):
                raise _err("Public users cannot remove files from records.", "INVALID_REQUEST")
            if out.get("unique_id"):
                raise _err("Public users cannot set unique_id for records.", "INVALID_REQUEST")
        return out, is_reference_post

    _NO_DATA = object()

    def post_record(self, data: Any = _NO_DATA, config: Optional[dict] = None, files: Optional[list] = None) -> dict:
        """
        Creates a record, or updates one when config has record_id.
        data: any JSON value. Leave it out on an update to keep the stored data; None stores null.
        files: [{"name": "<field>", "file": <path, bytes or file object>, "filename"?: str, "content_type"?: str}]
        """
        self._ensure_connection()
        if config is None:
            raise _err('"config" argument is required.')
        conf, is_reference_post = self._setup_post_config(config)
        upload_files = _prepare_files(files)  # read and checked before the record is created
        if "data" in config:
            data = config["data"]
        sent_data = data is not self._NO_DATA
        view = dict(config)
        if "table" in conf:
            view["table"] = conf["table"]
        enc = self._maybe_encrypt(data if sent_data else None, view, sent_data)
        conf.pop("data", None)
        if not enc.get("omit"):
            if not enc.get("encrypted") and len(_json_bytes(enc["send"])) > 2 * 1024 * 1024:
                raise _err("Data should not exceed 2MB", "INVALID_REQUEST")
            conf["data"] = enc["send"]
        rid_in = conf.get("record_id")
        if enc.get("files") == "decrypt" and rid_in:
            # private -> not private: attachments back to plaintext while the key is still here
            conf["remove_bin"] = (conf.get("remove_bin") or []) + self._convert_record_files(rid_in, "decrypt")
        if enc.get("spill") is not None and rid_in:
            # ciphertext over 256 KB travels as a file, uploaded before the record points at it
            up = self._upload_prepared([{"name": "__skenc_ct__", "filename": "payload.bin", "content": enc["spill"],
                                         "content_type": "application/octet-stream"}], rid_in)
            if up["failed"]:
                raise up["errors"][0]["error"]
            if rid_in in self._enc.deks and up["bin_endpoints"][0]:
                self._enc.deks[rid_in]["ct_url"] = up["bin_endpoints"][0]
                self._enc.deks[rid_in]["ct_stale"] = []
        if enc.get("retire") and rid_in:
            # old payload files: retired whether this write spilled again or now fits inline
            conf["remove_bin"] = (conf.get("remove_bin") or []) + list(enc["retire"])
        rec = self._call("post-record", conf, auth=self._signed_in(), method="POST")
        if enc.get("encrypted") and rec.get("rec"):
            self._bind_record_dek(rec["rec"], enc.get("dek"))
        if enc.get("files") == "encrypt" and rec.get("rec"):
            # now private with its key cached: seal the existing attachments, then retire the plain ones
            try:
                retire = self._convert_record_files(rec["rec"], "encrypt")
                if retire:
                    self.post_record(config={"record_id": rec["rec"], "remove_bin": retire})
            except Exception as err:
                warnings.warn(f"Failed to encrypt existing attachments after making the record private: {err}", RuntimeWarning, stacklevel=2)

        if upload_files:
            if not enc.get("encrypted"):
                # this write did not seal the record, so its cached key was not confirmed by it
                self._confirm_file_dek(rec.get("rec"))
            result = self._upload_prepared(upload_files, rec.get("rec"), service=conf.get("service"))
            rec["bin"] = (rec.get("bin") or []) + result["bin_endpoints"]
        if is_reference_post and isinstance(rec.get("reference_private_key"), str):
            self._private_access_key[is_reference_post] = rec["reference_private_key"]
        record = self._normalize_record(rec, skip_data_fetch=sent_data, skip_decrypt=bool(enc.get("encrypted")))
        if sent_data and _is_offload_marker(rec.get("data")):
            record["data"] = data
        if enc.get("encrypted") and "plain" in enc:
            record["data"] = enc["plain"]
            record["encrypted"] = {"status": "encrypted", "recipients": enc["recipients"]}
        self._remember_unique_id(self._scope(conf.get("service"), conf.get("owner")), record)
        return record

    def post_records(self, items: List[dict]) -> dict:
        """Many records in few requests: items = [{"data": ..., "config": {...}}]. Returns {list, failed}."""
        self._ensure_connection()
        if not isinstance(items, list) or not items:
            raise _err('"items" should be a non-empty array.')
        queue, failed, out = [], [], []
        for i, item in enumerate(items):
            try:
                if not isinstance(item, dict):
                    raise _err(f'"items[{i}]" should be an object with "config".')
                if not isinstance(item.get("config"), dict):
                    raise _err(f'"items[{i}].config" is required.')
                conf, _ = self._setup_post_config(item["config"])
                payload = item["config"]["data"] if "data" in item["config"] else item.get("data", self._NO_DATA)
                has = payload is not self._NO_DATA
                view = dict(item["config"])
                if "table" in conf:
                    view["table"] = conf["table"]
                enc = self._maybe_encrypt(payload if has else None, view, has)
                conf.pop("data", None)
                if enc.get("encrypted"):
                    if enc.get("spill") is not None:
                        # skapi-js stores an empty ciphertext here (no payload file is uploaded in bulk); refuse instead
                        raise _err("This encrypted update is over 256 KB once sealed; save it with post_record().", "INVALID_REQUEST")
                    conf["data"] = enc["send"]
                    conf["_skapi_plain"] = enc
                elif has:
                    if len(_json_bytes(payload)) > 2 * 1024 * 1024:
                        raise _err("Data should not exceed 2MB", "INVALID_REQUEST")
                    conf["data"] = payload
                queue.append((i, conf))
            except SkapiError as err:
                failed.append({"index": i, "code": str(err.code or "INVALID_PARAMETER"), "message": err.message})
        position = 0
        while position < len(queue):
            chunk = queue[position:position + 100]
            answered = self._bulk_post([c for _, c in chunk])
            if not answered:
                for idx, _ in chunk:
                    failed.append({"index": idx, "code": "ERROR", "message": "The server answered nothing for this record."})
                position += len(chunk)
                continue
            taken = min(len(answered), len(chunk))
            for k in range(taken):
                rec = answered[k]
                if rec.get("record_id"):
                    out.append(rec)
                else:
                    e = rec.get("error") or {}
                    failed.append({"index": chunk[k][0], "code": e.get("code") or "ERROR", "message": e.get("message") or "The record was not saved."})
            position += taken
        failed.sort(key=lambda f: f["index"])
        return {"list": out, "failed": failed}

    def _bulk_post(self, configs: List[dict]) -> List[dict]:
        services = {c["service"] for c in configs if "service" in c}
        owners = {c["owner"] for c in configs if "owner" in c}
        if len(services) > 1:
            raise _err('All bulk params should share the same "service" value.')
        if len(owners) > 1:
            raise _err('All bulk params should share the same "owner" value.')
        common_service = services.pop() if services else ""
        common_owner = owners.pop() if owners else ""
        sent = [{k: v for k, v in c.items() if k not in ("service", "owner", "_skapi_plain")} for c in configs]
        res = self._call("post-record", {"_is_bulk_": sent, "service": common_service, "owner": common_owner}, auth=self._signed_in(), method="POST")
        if not isinstance(res, list):
            return []
        records = []
        for conf, raw in zip(configs, res):
            sealed = conf.get("_skapi_plain")
            rec = self._normalize_record(raw, skip_data_fetch="data" in conf, skip_decrypt=bool(sealed)) if isinstance(raw, dict) else {}
            if "data" in conf and isinstance(raw, dict) and _is_offload_marker(raw.get("data")) and not raw.get("error"):
                rec["data"] = conf["data"]
            if sealed and rec.get("record_id"):
                self._bind_record_dek(rec["record_id"], sealed.get("dek"))
                rec["data"] = sealed["plain"]
                rec["encrypted"] = {"status": "encrypted"}
            if isinstance(raw, dict) and raw.get("error") and not rec.get("record_id"):
                rec["error"] = raw["error"]
            self._remember_unique_id(self._scope(common_service or None, common_owner or None), rec)
            records.append(rec)
        return records

    # ---- files ------------------------------------------------------------------------------

    def upload_files(self, files: list, record_id: str, service: Optional[str] = None) -> dict:
        """Attaches files to a record you can write: [{"name", "file", "filename"?, "content_type"?}]."""
        if not record_id:
            raise _err('"record_id" is required.')
        entries = _prepare_files(files)
        self._confirm_file_dek(record_id)  # an encrypted record's files are sealed only with its current key
        return self._upload_prepared(entries, record_id, service)

    def _upload_prepared(self, entries: List[dict], record_id: str, service: Optional[str] = None) -> dict:
        entries = [self._maybe_encrypt_file(record_id, e) for e in entries]  # sealed when the record's key is cached
        reserved_key = _random_key(6)
        base = {"reserved_key": reserved_key, "service": service or self.service, "request": "post", "id": record_id}
        params = [{"key": f'{e["name"]}/{e["filename"]}', "sizeKey": to_base62(len(e["content"])), "contentType": e["content_type"]} for e in entries]
        permits: List[Any] = [None] * len(entries)
        if len(entries) >= 5 and not getattr(self, "_bulk_permits_unavailable", False):
            try:
                for start in range(0, len(entries), 100):
                    chunk = params[start:start + 100]
                    res = self._call("get-signed-urls", {"files": chunk, "reserved_key": reserved_key, "service": base["service"], "request": "post", "id": record_id},
                                     auth=self._signed_in())
                    answered = res.get("list") or []
                    errors = {f.get("index"): f for f in res.get("failed") or []}
                    for k in range(len(chunk)):
                        if k in errors:
                            permits[start + k] = SkapiError(errors[k].get("message") or "Upload permit refused.", errors[k].get("code") or "ERROR")
                        elif k < len(answered) and answered[k]:
                            permits[start + k] = answered[k]
                        else:
                            permits[start + k] = SkapiError("No upload permit was answered for this file.", "ERROR")
            except SkapiError as err:
                if str(err.code) in ("404", "501") or re.search(r"missing authentication token|not implemented", err.message, re.I) \
                        or (str(err.code) == "403" and re.search(r"not found", err.message, re.I)):
                    self._bulk_permits_unavailable = True
                    permits = [None] * len(entries)
                else:
                    raise
        completed, failed, errors, endpoints, landed = [], [], [], [], []
        for i, e in enumerate(entries):
            permit = permits[i]
            if permit is None:
                try:
                    permit = self._call("get-signed-url", dict(params[i], **base), auth=self._signed_in())
                except SkapiError as err:
                    permit = err
            if isinstance(permit, SkapiError):
                endpoints.append("")
                failed.append(e["filename"])
                errors.append({"file": e["filename"], "name": e["name"], "error": permit})
                continue
            endpoints.append(permit.get("cdn"))
            try:
                self._requester.upload(permit["url"], permit.get("fields") or {}, e["filename"], e["content"], e["content_type"])
                completed.append(e["filename"])
                landed.append(permit.get("cdn"))
            except SkapiError as err:
                failed.append(e["filename"])
                errors.append({"file": e["filename"], "name": e["name"], "error": err})
        return {"completed": completed, "failed": failed, "errors": errors, "bin_endpoints": endpoints, "landed": landed}

    def delete_files(self, endpoints: Union[str, List[str]]) -> list:
        if isinstance(endpoints, str):
            endpoints = [endpoints]
        if not isinstance(endpoints, list):
            raise _err('"endpoints" should be type: array | string.')
        # A non-public file's url ends in "?t=<token>" and is percent-encoded (get_file "endpoint").
        # The server removes the stored, decoded url by exact string and answers success when
        # nothing matched, so the stored form is sent.
        endpoints = [self._stored_record_file_url(e) if isinstance(e, str) else e for e in endpoints]
        res = self._call("del-files", {"endpoints": endpoints, "storage": "records"}, auth=True, method="POST")
        return [self._normalize_record(r) for r in res] if isinstance(res, list) else res

    def get_file(self, url: str, config: Optional[dict] = None):
        """
        A file of a record. config["dataType"]: "bytes" (default), "text", "endpoint" (a URL you can
        open), "info" (what the URL says, no download). config["expires"]: seconds, for a signed URL
        that works without signing in. config["save_to"]: a path to write the file to (returns the path).
        """
        config = dict(config or {})
        if not isinstance(url, str):
            raise _err('"url" should be type: string.')
        requested_url = url
        base, sep, query = url.partition("?")
        try:
            parts = urlsplit(base)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise ValueError
            base = parts.geturl().replace(" ", "%20")
        except ValueError:
            raise _err(f'"{url}" is an invalid url.') from None
        url = base + (sep + query if sep else "")
        data_type = config.get("dataType", config.get("data_type", "bytes"))
        if data_type == "blob":
            data_type = "bytes"
        if data_type not in ("bytes", "text", "endpoint", "info"):
            data_type = "bytes"
        expires = config.get("expires") or 0
        if isinstance(expires, bool) or not isinstance(expires, (int, float)):
            expires = 0

        host = urlsplit(base).netloc.split(".")
        subdomain = host[0] if len(host) == 3 and host[1] == "skapi" else None
        target_key = base.split("/")[3:]
        need_auth = False
        is_skapi_file = bool(subdomain)
        presigned = bool(re.search(r"(^|&)(Signature|X-Amz-Signature)=", query))
        if presigned:
            # a link from get_file(..., {"expires": ...}): already signed, opened as it is
            if data_type == "endpoint":
                return url
            target_key = []
        if not subdomain and target_key and target_key[0] in ("auth", "publ"):
            if len(target_key) < 4 or not _UUID.match(target_key[2]) or not _UUID.match(target_key[3]):
                raise _err("Invalid file url.")
            need_auth = target_key[0] == "auth"
            is_skapi_file = True
        service = None if subdomain else (target_key[1] if len(target_key) > 1 else None)

        if data_type == "info":
            self._remember_handed_out_url(url, requested_url)
            g = target_key[6] if len(target_key) > 6 else None
            return {
                "url": url, "filename": target_key[-1] if target_key else "", "fileKey": target_key[-2] if len(target_key) > 1 else "",
                "access_group": "private" if g == "**" else "authorized" if g == "01" else "public" if g == "00" else (int(g) if g and g.isdigit() else g),
                "uploader": target_key[3] if len(target_key) > 3 else None,
                "record_id": target_key[5] if len(target_key) > 5 and target_key[4] == "records" else "N/A",
                "filesize": from_base62(target_key[9]) if len(target_key) > 9 else None,
                "uploaded": from_base62(target_key[8]) if len(target_key) > 8 else None,
            }

        if expires:
            if not is_skapi_file:
                raise _err("Expires option can only be used on skapi cdn endpoints.")
            if expires < 0:
                raise _err('"config.expires" should be > 0. (seconds)')
            params = {"request": "get-host" if subdomain else "get", "id": subdomain or target_key[5], "key": requested_url.split("?")[0], "expires": expires}
            if service:
                params["service"] = service
            url = self._call("get-signed-url", params, auth=True)["url"]
        elif need_auth:
            token = self._fresh_id_token()
            url += ("&" if "?" in url else "?") + "t=" + quote(token, safe="-_.!~*'()")
            group = target_key[6]
            u = self.user or {}
            if u.get("user_id") != target_key[3] and (group == "**" or (group.isdigit() and int(u.get("access_group") or 0) < int(group))):
                rid = target_key[5]
                key = self._cached_private_key(rid)
                if not key and self.owner != "skapi":
                    try:
                        key = self.request_private_record_access_key({"record_id": rid, "reference_id": config.get("_ref")})
                    except SkapiError:
                        key = None
                if key:
                    url += "&p=" + quote(key, safe="-_.!~*'()")

        if data_type == "endpoint":
            # a url handed out here may be fed back to delete_files or remove_bin
            self._remember_handed_out_url(url, requested_url)
            return url
        if presigned or expires:
            content = self._requester.fetch_plain(url)
        else:
            content = self._requester.request(url, None, method="GET", content_type="application/x-www-form-urlencoded", ignore_service=True, raw=True)
        if not config.get("_raw"):
            content = self._maybe_decrypt_file(requested_url, content)
        if config.get("save_to"):
            path = os.path.abspath(os.path.expanduser(config["save_to"]))
            with open(path, "wb") as f:
                f.write(content)
            return path
        if data_type == "text":
            return content.decode("utf-8", errors="replace")
        return content

    # ---- private record access --------------------------------------------------------------

    def _record_access(self, record_id, uid, execute):
        ids = self._record_access_ids(record_id, uid)
        return self._call("grant-private-access", {"record_id": record_id, "user_id": ids, "execute": execute}, auth=True, ignore_service=True)

    @staticmethod
    def _record_access_ids(record_id, uid) -> List[str]:
        if not isinstance(record_id, str):
            raise _err(f'{_jd(record_id)} is invalid in "record_id". allowed type or value is: Type<string>.')
        if not uid:
            raise _err("User ID is required.")
        ids = [uid] if isinstance(uid, str) else uid
        if len(ids) > 100:
            raise _err("Cannot process more than 100 users at once.")
        return [user_id(i, 'User ID in "user_id"') for i in ids]

    def grant_private_record_access(self, params: dict):
        uid = params.get("user_id")
        if self._enc is not None and uid and isinstance(params.get("record_id"), str):
            # an encrypted record gets a key wrap for each new user first
            self._enc_add_recipients(params["record_id"], [uid] if isinstance(uid, str) else list(uid))
        return self._record_access(params.get("record_id"), uid, "add")

    def remove_private_record_access(self, params: dict):
        uid = params.get("user_id") or None
        if self._enc is not None:
            # The data key is rolled BEFORE the access change: a fresh key, wrapped only for the users
            # who keep access. The roll is the step that can fail (attachments are sealed again and
            # uploaded), and failing first leaves access exactly as it was. As skapi-js.
            ids = self._record_access_ids(params.get("record_id"), uid)
            self._enc_drop_and_roll(params["record_id"], ids)
        return self._record_access(params.get("record_id"), uid, "remove")

    def list_private_record_access(self, params: dict, fetch_options: Optional[dict] = None) -> dict:
        rid, uid = params.get("record_id") or None, params.get("user_id") or None
        if not rid and not uid:
            raise _err("Either record_id or user_id must be provided.")
        p: Dict[str, Any] = {}
        if rid:
            p["record_id"] = rid
        if uid:
            if isinstance(uid, str):
                p["user_id"] = [user_id(uid)]
            elif isinstance(uid, list):
                p["user_id"] = [user_id(u) for u in uid]
            else:
                raise _err("user_id should be type: <string | string[]>")
        p["execute"] = "list"
        res = self._call("grant-private-access", p, auth=True, fetch_options=fetch_options, ignore_service=True)
        for item in res.get("list", []) if isinstance(res, dict) else []:
            if item.get("rec_usr"):
                item["record_id"], item["user_id"] = item["rec_usr"].split("/")[0], item["rec_usr"].split("/")[1]
            elif item.get("usr_rec"):
                item["user_id"], item["record_id"] = item["usr_rec"].split("/")[0], item["usr_rec"].split("/")[1]
        return res

    def _cached_private_key(self, record_id) -> Optional[str]:
        """The cached private access key for `record_id`, or None when there is none worth sending.

        The server mints "<exp>.<hash>", exp the unix second the key stops working (an hour after
        it was minted). A key that has expired or expires within _PRIVATE_KEY_REFRESH_MARGIN
        seconds is dropped, so the caller fetches a fresh one the usual way. A legacy key (64 hex
        characters, no expiry) is dropped too: the server accepts it only until a follow-up
        deploy turns that off, and a fresh key costs one request."""
        key = self._private_access_key.get(record_id) if isinstance(record_id, str) else None
        if not isinstance(key, str) or not key:
            return None
        m = _EXPIRING_KEY.match(key)
        if m and int(m.group(1)) - _PRIVATE_KEY_REFRESH_MARGIN > time.time():
            return key
        self._private_access_key.pop(record_id, None)
        return None

    def request_private_record_access_key(self, params: dict) -> str:
        rid, ref = params.get("record_id"), params.get("reference_id")
        if not rid:
            raise _err("Record ID is required.")
        if not isinstance(rid, str):
            raise _err("Record ID should be type: <string | string[]>")
        if ref and not isinstance(ref, str):
            raise _err("Reference ID should be type: <string>")
        cached_key = self._cached_private_key(rid)
        if cached_key:
            return cached_key
        body = {"record_id": rid}
        if ref:
            body["reference_id"] = ref
        res = self._call("request-private-access-key", body, auth=True)
        key = res if isinstance(res, str) else (res.get("private_key") if isinstance(res, dict) else None)
        if not isinstance(key, str):
            raise SkapiError("Invalid private access key response.", "ERROR")
        self._private_access_key[rid] = key
        return key

    # ---- decoding -----------------------------------------------------------------------------

    def _normalize_record(self, record: Any, skip_data_fetch: bool = False, skip_bin_resolve: bool = False, skip_decrypt: bool = False) -> dict:
        if not isinstance(record, dict):
            return record
        if record.get("record_id"):
            return record
        out: Dict[str, Any] = {
            "user_id": "", "record_id": "", "updated": 0, "uploaded": 0, "readonly": False,
            "table": {"name": "", "access_group": 0, "subscription": {"is_subscription_record": False, "upload_to_feed": False,
                      "notify_subscribers": False, "feed_referencing_records": False, "notify_referencing_records": False}},
            "referenced_count": 0,
            "source": {"referencing_limit": None, "prevent_multiple_referencing": False, "can_remove_referencing_records": False,
                       "only_granted_can_reference": False},
            "ip": "", "bin": {},
        }
        anonymous = False
        bins = record.get("bin") if isinstance(record.get("bin"), list) else []
        data_url = None
        ct_urls = []
        for u in bins:
            if isinstance(u, str):
                sp = u.split("/")[3:]
                if len(sp) >= 12 and sp[10] == "__data__" and sp[-1] == "__json__.json":
                    data_url = u
                if len(sp) >= 12 and sp[10] == "__skenc_ct__" and sp[-1] == "payload.bin":
                    ct_urls.append(u)  # an encrypted record's large ciphertext

        # Newest upload first: every record file url carries its upload time right after "bin"
        # (".../bin/<base62 ms>/<size>/<field>/<name>"), and the record's file list is a set with
        # no order. Older SDKs could leave several payload files; the newest is the current one.
        def _uploaded(u):
            sp = u.split("/")[3:]
            try:
                return from_base62(sp[8]) if sp[7] == "bin" else 0
            except Exception:
                return 0
        ct_urls.sort(key=_uploaded, reverse=True)
        ct_url = ct_urls[0] if ct_urls else None

        if "ip" in record:
            parts = str(record["ip"]).split("#")
            ip = parts[0]
            if len(parts) > 1:
                out["unique_id"] = "#".join(parts[1:])
            if ip.endswith("R"):
                out["readonly"] = True
                ip = ip[:-1]
            if re.match(r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$", ip):
                ip = ip.replace("-", ".")
                anonymous = True
            out["ip"] = ip
        if record.get("rec"):
            out["record_id"] = record["rec"]
            out["uploaded"] = from_base62(record["rec"][:-9])
        if "usr" in record:
            out["user_id"] = record["usr"]
        if "tbl" in record and not out["table"]["name"]:
            p = str(record["tbl"]).split("/")
            out["table"]["name"] = decode_delimiters(p[0])
            out["table"]["access_group"] = access_group_out(p[2]) if len(p) > 2 else 0
            out["table"]["subscription"]["is_subscription_record"] = len(p) > 3 and bool(p[3])
        if "usr_tbl" in record:
            p = str(record["usr_tbl"]).split("/")
            if not out["user_id"]:
                out["user_id"] = p[0]
            if not out["table"]["name"]:
                out["table"]["name"] = decode_delimiters(p[1] if len(p) > 1 else "")
                out["table"]["access_group"] = access_group_out(p[3]) if len(p) > 3 else 0
                out["table"]["subscription"]["is_subscription_record"] = len(p) > 4 and bool(p[4])
        if "idx" in record and isinstance(record["idx"], str):
            parts = record["idx"].split("!")
            out["index"] = {"name": decode_delimiters(parts[0]), "value": _typed_string("!" + "!".join(parts[1:]))}
        if record.get("ref"):
            out["reference"] = str(record["ref"]).split("/")[0]
        if "tags" in record:
            out["tags"] = [decode_delimiters(t) for t in record["tags"]] if isinstance(record["tags"], list) else record["tags"]
        if "upd" in record:
            out["updated"] = record["upd"]
        if "acpt_mrf" in record:
            out["source"]["prevent_multiple_referencing"] = not record["acpt_mrf"]
        if "ref_limt" in record:
            out["source"]["referencing_limit"] = record["ref_limt"]
        if "rfd" in record:
            out["referenced_count"] = record["rfd"]
        if bins:
            for u in bins:
                if not isinstance(u, str) or not u:
                    continue
                path = "/".join(u.split("/")[3:])
                sp = path.split("/")
                if len(sp) < 12 or sp[10] in ("__data__", "__skenc_ct__"):
                    continue
                path_key = sp[10]
                group = access_group_out(sp[6])
                endpoint = u
                if group != "public" and not skip_bin_resolve:
                    try:
                        endpoint = self.get_file(u, {"dataType": "endpoint", "_ref": out.get("reference")})
                    except SkapiError:
                        endpoint = u
                entry = {"access_group": group, "filename": sp[-1], "url": endpoint, "path": path,
                         "size": from_base62(sp[9]), "uploaded": from_base62(sp[8])}
                sealed = parse_file_marker(path_key)
                if sealed:
                    # an encrypted attachment: listed under its own field name, with the plaintext size
                    path_key, entry["size"] = sealed
                    entry["encrypted"], entry["stored_size"] = True, from_base62(sp[9])
                out["bin"].setdefault(path_key, []).append(entry)
        if isinstance(record.get("prv_acs"), dict):
            for k, v in record["prv_acs"].items():
                if k in ("notify_subscribers", "upload_to_feed", "feed_referencing_records", "notify_referencing_records"):
                    out["table"]["subscription"][k] = v
                elif k == "referencing_index_restrictions" and isinstance(v, list):
                    out["source"][k] = [dict(i, name=decode_delimiters(i["name"])) if isinstance(i, dict) and isinstance(i.get("name"), str) else i for i in v]
                else:
                    out["source"][k] = v
        if "data" in record:
            r = record["data"]
            decoded = parse_stored_data(r)
            if decoded is not r or isinstance(r, str):
                out["data"] = decoded
            elif _is_offload_marker(r):
                if data_url and skip_data_fetch:
                    out["data"] = r
                elif data_url or not skip_data_fetch:
                    url = data_url or self._derived_data_url(record, r["__data__"], bins)
                    out["data"] = r
                    if url:
                        try:
                            out["data"] = json.loads(self.get_file(url, {"dataType": "text", "_ref": out.get("reference")}))
                        except Exception:
                            out["data"] = None if data_url else r
                            if self._enc is not None:
                                out["encrypted"] = {"status": "failed", "reason": "DATA_UNAVAILABLE"}
                else:
                    out["data"] = r
            else:
                out["data"] = r
            if not skip_decrypt and "data" in out:
                value, flag = self._maybe_decrypt(out["data"], {
                    "access_group": out["table"]["access_group"], "table_name": out["table"]["name"], "user_id": out["user_id"],
                    "record_id": out["record_id"], "unique_id": out.get("unique_id"), "ct_url": ct_url, "ct_urls": ct_urls})
                if flag:
                    out["data"], out["encrypted"] = value, flag
        if anonymous:
            out["user_id"] = "anonymous:" + out["user_id"]
        return out

    def _derived_data_url(self, record: dict, marker_path: str, bins: list) -> Optional[str]:
        """The offloaded data file's URL when the record's file list does not carry it."""
        if not re.match(r"^[0-9A-Za-z]+/[0-9A-Za-z]+/__data__/__json__\.json$", marker_path):
            return None
        service = owner = uploader = group = None
        if isinstance(record.get("srvc"), str):
            service, _, owner = record["srvc"].split("!")[0].partition("/")
        if isinstance(record.get("usr_tbl"), str):
            p = record["usr_tbl"].split("/")
            uploader = p[0]
            service = service or (p[2] if len(p) > 2 else None)
            group = p[3] if len(p) > 3 else None
        elif isinstance(record.get("tbl"), str):
            p = record["tbl"].split("/")
            service = service or (p[1] if len(p) > 1 else None)
            group = p[2] if len(p) > 2 else None
        uploader = record.get("usr") or uploader
        if not owner and service == self.service:
            owner = self.owner
        origin = None
        for u in bins:
            if isinstance(u, str) and service and f"/{service}/" in u:
                s = urlsplit(u)
                origin = f"{s.scheme}://{s.netloc}"
                break
        origin = origin or getattr(self, "_cdn_origins", {}).get(service)
        rec = record.get("rec")
        ids_ok = all(isinstance(x, str) and re.match(r"^[0-9A-Za-z_-]+$", x) for x in (service, owner, uploader, rec))
        if not (origin and ids_ok and isinstance(group, str) and re.match(r"^(\d{2}|\*\*)$", group)):
            return None
        return f"{origin}/{'publ' if group == '00' else 'auth'}/{service}/{owner}/{uploader}/records/{rec}/{group}/bin/{marker_path}"


def _json_bytes(v: Any) -> bytes:
    try:
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        raise _err("Invalid data type.", "INVALID_REQUEST") from None


def _prepare_files(files: Optional[list]) -> List[dict]:
    """[{"name", "file": path | bytes | file object, "filename"?, "content_type"?}] -> name, filename, content, content_type."""
    out = []
    for i, f in enumerate(files or []):
        if not isinstance(f, dict) or not f.get("name") or "file" not in f:
            raise _err(f'"files[{i}]" should be {{"name": <field name>, "file": <path, bytes or file object>}}.')
        src = f["file"]
        filename = f.get("filename")
        if isinstance(src, (str, os.PathLike)):
            path = os.fspath(src)
            try:
                with open(path, "rb") as fh:
                    content = fh.read()
            except OSError as err:
                raise SkapiError(f'"files[{i}].file" cannot be read: {err.strerror or err}.', "INVALID_PARAMETER", err) from None
            filename = filename or os.path.basename(path)
        elif isinstance(src, (bytes, bytearray)):
            content = bytes(src)
        elif hasattr(src, "read"):
            content = src.read()
            if isinstance(content, str):
                content = content.encode("utf-8")
            filename = filename or os.path.basename(getattr(src, "name", "") or "")
        else:
            raise _err(f'"files[{i}].file" should be a path, bytes or a file object.')
        if not filename:
            raise _err(f'"files[{i}].filename" is required for bytes.')
        content_type = f.get("content_type") or mimetypes.guess_type(filename)[0]
        out.append({"name": f["name"], "filename": filename, "content": content, "content_type": content_type})
    return out
