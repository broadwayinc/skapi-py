"""
The request layer: endpoint discovery, headers, body encoding, errors, rate-limit retries and
paging, matching skapi-js (src/utils/network.ts) so the server sees the same requests.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import random
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote, urlsplit

from .errors import SkapiError, network_error_message

DEFAULT_TARGET_CDN = "d3e9syvbtso631"
ENDPOINT_VERSION = "v2"
KNOWN_ERROR_CODES = ["INVALID_CORS", "INVALID_REQUEST", "SERVICE_DISABLED", "INVALID_PARAMETER", "ERROR", "EXISTS", "NOT_EXISTS"]
RATE_LIMIT_MAX_RETRIES = 6
# Uploads (2.4.4): the body goes out in blocks of this size, each with its own `timeout`, so the
# limit is "no progress for `timeout` seconds", never the file's total time. urllib sends a bytes
# body with ONE sendall(), and since Python 3.5 the socket timeout covers that whole call: an
# upload taking longer than `timeout` was cut off while still moving.
UPLOAD_BLOCK_BYTES = 64 * 1024
# Once the whole body is handed off, MB can still drain from the OS buffers with nothing to show;
# the answer may take this many times `timeout` before the upload counts as stalled.
UPLOAD_SENT_WAIT_FACTOR = 5


def _timed_out(err: BaseException) -> bool:
    """True when `err` is the socket limit running out (nothing moved for `timeout` seconds), also
    when urllib wraps it in URLError. socket.timeout is TimeoutError from Python 3.10, an OSError
    of its own on 3.9."""
    if isinstance(err, urllib.error.URLError) and not isinstance(err, urllib.error.HTTPError):
        err = err.reason if isinstance(err.reason, BaseException) else err
    return isinstance(err, (socket.timeout, TimeoutError))

ADMIN_ROUND_ROBIN = {
    "get-newsletters", "get-public-newsletters", "subscribe-newsletter", "subscribe-public-newsletter",
    "signupkey", "admin-newsletter-request", "admin-signup", "confirm-signup", "openid-logger",
    "block-account", "admin-edit-profile", "remove-account", "recover-account", "mock",
    "grant-access", "last-verified-email", "ticket", "register-ticket", "get-newsletter-subscription",
    "send-inquiry", "register-newsletter-group", "delete-newsletter-group", "newsletter-group-endpoint",
    "invitation-list", "csr", "csr-poll", "csr-cancel", "csr-finalize",
}
RECORD_ROUND_ROBIN = {
    "store-subscription", "get-vapid-public-key", "push-notification", "delete-subscription",
    "subscription", "get-subscription", "get-table", "get-tag", "get-uniqueid", "get-index",
    "get-signed-url", "get-signed-urls", "extract-file-text", "grid-query", "anonymous-login",
    "anonymous-session", "grant-private-access", "request-private-access-key", "get-ws-group",
    "check-schema", "get-feed", "castspell", "dopamine", "getspell",
}

_counter_lock = threading.Lock()
_request_counter = 0  # one counter for admin and record picks, as in skapi-js


def _next_counter() -> int:
    global _request_counter
    with _counter_lock:
        _request_counter += 1
        return _request_counter


def _js_value(v: Any) -> Any:
    """What JSON.stringify writes: an integral float as an integer, NaN and Infinity as null."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        return int(v) if v.is_integer() and abs(v) < 2 ** 53 else v
    if isinstance(v, dict):
        return {str(k): _js_value(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_js_value(x) for x in v]
    return v


def js_json(v: Any) -> str:
    """JSON.stringify: compact, insertion order kept, non-ASCII left as is."""
    return json.dumps(_js_value(v), separators=(",", ":"), ensure_ascii=False)


def encode_uri_component(text: str) -> str:
    return quote(text, safe="-_.!~*'()")


def _sorted_keys(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _sorted_keys(v[k]) for k in sorted(v)}
    if isinstance(v, list):
        return [_sorted_keys(x) for x in v]
    return v


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _retry_delay_ms(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return max(0.0, float(value) * 1000)
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() * 1000 - time.time() * 1000)
    except (TypeError, ValueError):
        return None


def _rate_limit_wait_ms(delay: float, attempt: int) -> float:
    base = delay if delay > 0 else min(60000, 500 * 2 ** attempt)
    base = min(60000, base)
    return base + math.floor(random.random() * min(1000, max(50, base * 0.25)))


def parse_error(status: int, text: str, server_fault: bool = False) -> SkapiError:
    """
    A non-2xx answer as a SkapiError, read the way skapi-js reads it.

    server_fault: on the regular request path (not uploads, not signed links), a 5xx other than
    501 is SERVER_ERROR whatever the body says, so a caller can tell "try again" from "no"
    (skapi-js 2.7.0). The body is kept on `cause`. 501 says the route does not exist here,
    which is an answer.
    """
    try:
        body = json.loads(text)
    except ValueError:
        body = text
    fault = server_fault and status >= 500 and status != 501
    if isinstance(body, str):
        parts = body.split(":")
        code = parts[0].strip()
        message = ":".join(parts[1:]).strip()
        if fault:
            return SkapiError(message or body or f"Server error {status}.", "SERVER_ERROR", body)
        return SkapiError(message or body, code if code in KNOWN_ERROR_CODES else "ERROR")
    if isinstance(body, dict) and any(k in body for k in ("message", "stage", "code")):
        code = body.get("code") or str(status) or "ERROR"
        message = (body.get("message") or "").strip() or str(code)
        cause = body.get("cause", body if "stage" in body else None)
        if fault:
            return SkapiError(message, "SERVER_ERROR", body if cause is None else cause)
        return SkapiError(message, str(code), cause)
    if fault:
        return SkapiError(f"Server error {status}.", "SERVER_ERROR", body)
    return SkapiError(str(body), "ERROR")


class Requester:
    def __init__(self, service: str, owner: str, version: str, target_cdn: Optional[str] = None, timeout: float = 120):
        self.service = service
        self.owner = owner
        self.version = version
        self.target_cdn = target_cdn or DEFAULT_TARGET_CDN
        self.timeout = timeout
        self.public_identifier = ""
        self._admin: Optional[Dict[str, Any]] = None
        self._record: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        # paging: the startKeys a query has seen, newest last ("end" when the list is done)
        self._start_key_history: Dict[str, Dict[str, list]] = {}

    # ---- endpoints ------------------------------------------------------------------------------

    def _fetch_endpoint_file(self, name: str) -> Dict[str, Any]:
        url = f"https://{self.target_cdn}.cloudfront.net/{self.service[:4]}/{name}-{ENDPOINT_VERSION}.json"
        # Only the CDN's "no such file" (403 or 404) means the project does not exist. Anything else is
        # a failure on the way, reported with a code a caller (and a poll) retries: before, a passing
        # CDN error or a cut-off answer said "The project ID does not exist", and the next call, which
        # fetches the list again, worked.
        try:
            with urllib.request.urlopen(urllib.request.Request(url), timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as err:
            if err.code in (403, 404):
                raise SkapiError("The project ID does not exist. Create your project from skapi.com", "NOT_EXISTS") from None
            if err.code == 429:
                raise SkapiError("Too many requests", "RATE_LIMITED") from None
            raise SkapiError(f"Server error {err.code}.", "SERVER_ERROR") from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as err:
            if _timed_out(err):
                raise SkapiError(f"No response for {self.timeout:g} seconds.", "TIMEOUT", err) from None
            raise SkapiError(network_error_message(err), "NETWORK_ERROR", err) from None
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if not isinstance(parsed, dict):
            raise SkapiError(f'Network error: the project\'s endpoint list "{name}" arrived incomplete.', "NETWORK_ERROR")
        return parsed

    def endpoints(self):
        with self._lock:
            if self._admin is None:
                self._admin = self._fetch_endpoint_file("admin")
            if self._record is None:
                self._record = self._fetch_endpoint_file("record")
            return self._admin, self._record

    def _select_gateway(self, kind: str, auth: bool, stable: bool = False) -> str:
        admin, record = self.endpoints()
        n = _next_counter()
        if kind == "admin":
            suffix = "_private" if auth else "_public"
            items = [v for k, v in admin.items() if suffix in k and k not in ("get_users_private", "service_public") and isinstance(v, str)]
            if not items:
                raise SkapiError("No available admin gateways.", "INVALID_REQUEST")
        else:
            prefix = "record_private" if auth else "record_public"
            items = [v for k, v in record.items() if prefix in k and isinstance(v, str)]
            if not items:
                raise SkapiError("No available record gateways.", "INVALID_REQUEST")
            if stable:
                return items[0]
        return items[n % len(items)]

    def endpoint_url(self, dest: str, auth: bool, stable: bool = False) -> str:
        admin, record = self.endpoints()
        path, _, query = dest.partition("?")
        query = "?" + query if query else ""
        if path == "get-users":
            base = admin["get_users_private"]
        elif path == "service":
            base = admin["service_public"]
        elif path in ADMIN_ROUND_ROBIN:
            base = self._select_gateway("admin", auth)
        elif path == "post-record":
            base = record["post_private"] if auth else record["post_public"]
        elif path == "get-records":
            base = record["get_private"] if auth else record["get_public"]
        elif path in ("del-files", "del-records"):
            base = record["del_private"]
        elif path in RECORD_ROUND_ROBIN:
            base = self._select_gateway("record", auth, stable)
        else:
            if not path.startswith(("https://", "http://")):
                raise SkapiError(f'"{dest}" is not a valid url.', "INVALID_PARAMETER")
            return dest
        return base + path + query

    # ---- request ----------------------------------------------------------------------------------

    def request(self, dest: str, data: Any = None, *, auth: bool = False, method: str = "POST",
                token: Optional[str] = None, fetch_options: Optional[Dict[str, Any]] = None,
                ignore_service: bool = False, stable_gateway: bool = False, content_type: Optional[str] = "application/json",
                raw: bool = False, extra_headers: Optional[Dict[str, str]] = None,
                keep_paging: Optional[Callable[[], bool]] = None) -> Any:
        """
        token: the idToken, already fresh, when auth is on (sent raw as Authorization).
        fetch_options: limit, startKey, ascending (sent) and fetchMore (paging, not sent).
        raw: return the response bytes as they are.
        keep_paging: asked before the answer's startKey is saved for fetchMore; False when the caller
        already gave up on this answer (deadline or signal), so the next fetchMore asks for the same page.
        """
        method = method.upper()
        url = self.endpoint_url(dest, auth, stable_gateway)
        service = (data or {}).get("service") if isinstance(data, dict) else None
        owner = (data or {}).get("owner") if isinstance(data, dict) else None
        service = service or self.service
        owner = owner or self.owner

        fetch_options = dict(fetch_options or {})
        fetch_more = bool(fetch_options.pop("fetchMore", fetch_options.pop("fetch_more", False)))
        if "start_key" in fetch_options and "startKey" not in fetch_options:
            fetch_options["startKey"] = fetch_options.pop("start_key")
        sent_options: Dict[str, Any] = {}
        if "limit" in fetch_options and fetch_options["limit"] is not None:
            limit = fetch_options["limit"]
            if isinstance(limit, bool) or not isinstance(limit, (int, float)):
                raise SkapiError("Fetch limit should be a number.", "INVALID_REQUEST")
            if limit > 1000:
                raise SkapiError("Fetch limit should be below 1000.", "INVALID_REQUEST")
            sent_options["limit"] = limit
        if fetch_options.get("startKey") is not None:
            sent_options["startKey"] = fetch_options["startKey"]
        if "ascending" in fetch_options and fetch_options["ascending"] is not None:
            if not isinstance(fetch_options["ascending"], bool):
                raise SkapiError('"ascending" should be a boolean.', "INVALID_PARAMETER")
            sent_options["ascending"] = fetch_options["ascending"]

        body: Any = {} if ignore_service else {"service": service, "owner": owner}
        body.update(sent_options)
        if isinstance(data, dict):
            for k, v in data.items():
                body[k] = v
        elif data:
            body = data

        # paging: a query asked again with fetchMore continues from the last startKey it got
        history_key = None
        if isinstance(body, dict):
            start_key = body.get("startKey")
            if start_key:
                if start_key == "start":
                    del body["startKey"]
                    fetch_more = False
                elif not (start_key == "end" or (isinstance(start_key, dict) and start_key)):
                    raise SkapiError(f'"{start_key}" is invalid startKey key.', "INVALID_PARAMETER")
            fingerprint = f"{method}:{'auth' if auth else 'public'}:{dest}"
            # the private key of a shared record is attached once this client has it (after page 1),
            # so it stays out of the paging key: the next page of the same query continues the same list
            params_for_key = {k: v for k, v in body.items() if k not in ("startKey", "private_key")}
            history_key = _md5(fingerprint + "/" + js_json(_sorted_keys(params_for_key)))
            history = self._start_key_history.setdefault(dest, {})
            if not fetch_more:
                history.pop(history_key, None)
            elif history.get(history_key):
                last = history[history_key][-1]
                if last == "end":
                    return {"list": [], "startKey": "end", "endOfList": True, "startKeyHistory": list(history[history_key])}
                body["startKey"] = json.loads(last)

        headers = {"Accept": "*/*"}
        if content_type:
            headers["Content-Type"] = content_type
        if token:
            headers["Authorization"] = token
        if extra_headers:
            headers.update(extra_headers)
        headers["Content-Meta"] = js_json({
            "public_identifier": self.public_identifier,
            "service": service,
            "owner": owner,
            "resolves_offloaded_data": True,
            "skapi_version": self.version,
            "expiring_private_keys": True,  # renews private access keys before they expire, so 1-hour keys are safe
        })

        payload = None
        if method == "GET":
            if isinstance(body, dict) and body:
                pairs = "&".join(
                    encode_uri_component(str(k)) + "=" + encode_uri_component(v if isinstance(v, str) else js_json(v))
                    for k, v in body.items())
                url += ("?" if "?" not in url else ("" if url.endswith(("?", "&")) else "&")) + pairs
        elif isinstance(body, (bytes, bytearray)):
            payload = bytes(body)
        elif isinstance(body, str):
            payload = body.encode("utf-8")
        elif body:
            payload = js_json(body).encode("utf-8")

        result = self._send(url, method, headers, payload, raw)

        if history_key is not None and isinstance(result, dict) and result.get("startKey") \
                and (keep_paging is None or keep_paging()):
            seen = self._start_key_history.setdefault(dest, {}).setdefault(history_key, [])
            entry = "end" if result["startKey"] == "end" else js_json(result["startKey"])
            if entry not in seen:
                seen.append(entry)
            result = dict({"startKeyHistory": list(seen)}, **result)
        return result

    def _send(self, url: str, method: str, headers: Dict[str, str], payload: Optional[bytes], raw: bool = False) -> Any:
        attempt = 0
        while True:
            req = urllib.request.Request(url, data=payload, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    content = resp.read()
                if raw:
                    return content
                text = content.decode("utf-8", errors="replace")
                try:
                    return json.loads(text)
                except ValueError:
                    return text
            except urllib.error.HTTPError as err:
                try:
                    text = err.read().decode("utf-8", errors="replace")
                except (OSError, http.client.HTTPException) as cut:
                    # the connection dropped inside the error body: a transport failure, as above
                    raise SkapiError(network_error_message(cut), "NETWORK_ERROR", cut) from None
                if err.code == 429:
                    delay = _retry_delay_ms(err.headers.get("Retry-After") if err.headers else None)
                    if delay is None:
                        # a 429 that carries its own error (a ticket whose slots are all taken) keeps it
                        carried = parse_error(err.code, text) if text.strip() else None
                        if carried is not None and carried.code not in ("ERROR", "429"):
                            raise carried from None
                        # 2.7.0: a coded transport failure, as skapi-js "Too many requests" (RATE_LIMITED)
                        raise SkapiError("Too many requests", "RATE_LIMITED") from None
                    if attempt >= RATE_LIMIT_MAX_RETRIES:
                        raise SkapiError(f'Too many requests: "{url.split("?")[0]}" still answered 429 after {RATE_LIMIT_MAX_RETRIES} retries.',
                                         "TOO_MANY_REQUESTS") from None
                    time.sleep(_rate_limit_wait_ms(delay, attempt) / 1000)
                    attempt += 1
                    continue
                raise parse_error(err.code, text, server_fault=True) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.HTTPException) as err:
                # A connection with nothing moving for `timeout` seconds fails with TIMEOUT, as in
                # skapi-js 2.4.4 (its "No response for 60 seconds."); other failures stay NETWORK_ERROR.
                # http.client.HTTPException covers a connection dropped inside the answer (IncompleteRead,
                # BadStatusLine), which skapi-js sees as xhr.onerror: NETWORK_ERROR, so a poll keeps going.
                if _timed_out(err):
                    raise SkapiError(f"No response for {self.timeout:g} seconds.", "TIMEOUT", err) from None
                raise SkapiError(network_error_message(err), "NETWORK_ERROR", err) from None

    def fetch_plain(self, url: str) -> bytes:
        """A plain GET with no extra headers: for pre-signed links, whose signature covers the headers."""
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            text = err.read().decode("utf-8", errors="replace")
            code = re.search(r"<Code>(.*?)</Code>", text)
            message = re.search(r"<Message>(.*?)</Message>", text)
            if code or message:
                raise SkapiError(message.group(1) if message else text[:300], code.group(1) if code else "ERROR") from None
            raise parse_error(err.code, text) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.HTTPException) as err:
            if _timed_out(err):
                raise SkapiError(f"No response for {self.timeout:g} seconds.", "TIMEOUT", err) from None
            raise SkapiError(network_error_message(err), "NETWORK_ERROR", err) from None

    def upload(self, url: str, fields: Dict[str, str], filename: str, content: bytes, content_type: Optional[str]) -> Any:
        """multipart/form-data POST to a signed upload URL: every field in order, then the file."""
        boundary = "----skapi" + hashlib.md5(str(random.random()).encode()).hexdigest()
        parts = []
        for k, v in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode("utf-8"))
        safe_name = filename.replace('"', "%22").replace("\r", "").replace("\n", "")
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
                     f'Content-Type: {content_type or "application/octet-stream"}\r\n\r\n'.encode("utf-8"))
        parts.append(content)
        parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        return self._send_upload(url, {"Content-Type": f"multipart/form-data; boundary={boundary}"}, b"".join(parts), filename)

    def _send_upload(self, url: str, headers: Dict[str, str], payload: bytes, filename: str) -> Any:
        """POST an upload body with an idle limit: `timeout` per block sent, UPLOAD_SENT_WAIT_FACTOR x
        `timeout` for the answer once all of it is sent. Same answers and 429 retries as _send."""
        attempt = 0
        while True:
            parts = urlsplit(url)
            conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(parts.hostname, parts.port, timeout=self.timeout)
            path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
            sent = False
            try:
                conn.putrequest("POST", path)
                for k, v in headers.items():
                    conn.putheader(k, v)
                conn.putheader("Content-Length", str(len(payload)))
                conn.endheaders()
                view = memoryview(payload)
                for i in range(0, len(payload), UPLOAD_BLOCK_BYTES):
                    conn.send(view[i:i + UPLOAD_BLOCK_BYTES])
                sent = True
                if conn.sock is not None and self.timeout:
                    conn.sock.settimeout(self.timeout * UPLOAD_SENT_WAIT_FACTOR)
                resp = conn.getresponse()
                status, retry_after, content = resp.status, resp.getheader("Retry-After"), resp.read()
            except (socket.timeout, TimeoutError) as err:
                wait = self.timeout * (UPLOAD_SENT_WAIT_FACTOR if sent else 1)
                raise SkapiError(
                    f'Upload timeout: no answer for "{filename}" {wait:g} seconds after it was sent.' if sent
                    else f'Upload timeout: "{filename}" sent nothing for {wait:g} seconds.', "TIMEOUT", err) from None
            except (OSError, http.client.HTTPException) as err:
                raise SkapiError(network_error_message(err), "NETWORK_ERROR", err) from None
            finally:
                conn.close()
            text = content.decode("utf-8", errors="replace")
            if 200 <= status < 300:
                try:
                    return json.loads(text)
                except ValueError:
                    return text
            if status == 429:
                delay = _retry_delay_ms(retry_after)
                if delay is None:
                    # as skapi-js uploads (toFileUploadError): TOO_MANY_REQUESTS
                    raise SkapiError("Too many requests", "TOO_MANY_REQUESTS") from None
                if attempt >= RATE_LIMIT_MAX_RETRIES:
                    raise SkapiError(f'Too many requests: the upload of "{filename}" still answered 429 after {RATE_LIMIT_MAX_RETRIES} retries.',
                                     "TOO_MANY_REQUESTS") from None
                time.sleep(_rate_limit_wait_ms(delay, attempt) / 1000)
                attempt += 1
                continue
            raise parse_error(status, text)
