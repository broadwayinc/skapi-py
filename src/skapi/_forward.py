"""
Request forwarding (call another API through Skapi, with your stored client secrets) and
inquiries, ported from skapi-js (src/methods/request.ts).

Answers arrive by polling, exactly as skapi-js does without its realtime connection: a queued or
streamed request is dispatched, then polled until it settles. Streamed text is handed to an
on_stream(text, seq) callback as it arrives.
"""

from __future__ import annotations

import base64
import json
import random
import string
import time
import uuid
import warnings
from typing import Any, Callable, Dict, Optional

from ._database import _prepare_files
from ._http import js_json
from ._user import _url, validate_email
from .errors import SkapiError

METHODS = ("get", "post", "delete", "put", "patch", "head")
UPPER_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
STREAM_DEGRADED_RETRIES = 3
MULTIPART_LIMIT = 2 * 1024 * 1024 - 64 * 1024
# The shortest polling interval accepted, in milliseconds (skapi-js 2.4.4 MIN_POLL_INTERVAL_MS). A
# shorter one is refused with INVALID_PARAMETER, never raised quietly: applies to forward_request's
# `poll` (0 still means "do not poll"), forward_request_poll's `poll` and forward_request_stream's `poll`.
MIN_POLL_INTERVAL_MS = 1000


def _jd(v):
    """A value as it appears in an error message; never fails on odd types."""
    return json.dumps(v, default=repr, ensure_ascii=False)


def _assert_poll_interval(value: Any, name: str = "poll") -> None:
    """Refuse an interval that is not a finite number of at least MIN_POLL_INTERVAL_MS."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value \
            or value in (float("inf"), float("-inf")) or value < MIN_POLL_INTERVAL_MS:
        raise _p(f'"{name}" should be a number of milliseconds, {MIN_POLL_INTERVAL_MS} or more.')


def _p(message: str, code: str = "INVALID_PARAMETER") -> SkapiError:
    return SkapiError(message, code)


def _absolute_url(v: Any, field: str = "url") -> str:
    if v == "*":
        return v
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(v)
        if not parts.scheme or not parts.netloc:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise _p(f'"{v}" is an invalid url.') from None
    return v


def request_key(method: str, url: str, service: str, request_id: str) -> str:
    """The full id skapi-js and the server know a forwarded request by."""
    return f"[{method.upper()}]{url.lower()}#{service}:{request_id}"


def _has_secret(v: Any) -> bool:
    if isinstance(v, str):
        return "$CLIENT_SECRET" in v
    if isinstance(v, dict):
        return any(_has_secret(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_secret(x) for x in v)
    return False


def _is_envelope(v: Any) -> bool:
    return isinstance(v, dict) and isinstance(v.get("status"), str) and isinstance(v.get("id"), str) and "in_queue" in v


def _deliver_chunks(result: Any, cursor: int, on_stream: Callable) -> tuple:
    moved = False
    chunks = result.get("chunks") if isinstance(result, dict) else None
    if isinstance(chunks, list):
        for c in sorted((c for c in chunks if isinstance(c, dict) and isinstance(c.get("seq"), int)), key=lambda c: c["seq"]):
            if c["seq"] > cursor:
                cursor = c["seq"]
                moved = True
                if isinstance(c.get("txt"), str) and c["txt"]:
                    try:
                        on_stream(c["txt"], c["seq"])
                    except Exception as err:
                        # the request goes on; the callback's error is reported, not raised
                        warnings.warn(f"on_stream raised {err!r} for chunk {c['seq']}", RuntimeWarning, stacklevel=2)
    last = result.get("last_seq") if isinstance(result, dict) else None
    if isinstance(last, int) and not isinstance(last, bool) and last > cursor:
        cursor = last
        moved = True
    return cursor, moved


def _multipart(form: Dict[str, Any]) -> tuple:
    """A multipart/form-data body from a dict: files as file parts, the rest as text."""
    boundary = "----skapi" + uuid.uuid4().hex
    out = []

    def text_part(name, value):
        out.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8") + value.encode("utf-8") + b"\r\n")

    def file_part(name, entry):
        safe = entry["filename"].replace('"', "%22").replace("\r", "").replace("\n", "")
        out.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{safe}"\r\n'
                   f'Content-Type: {entry["content_type"] or "application/octet-stream"}\r\n\r\n'.encode("utf-8") + entry["content"] + b"\r\n")

    for name, value in form.items():
        for v in value if isinstance(value, list) else [value]:
            if isinstance(v, dict) and "file" in v:
                file_part(name, _prepare_files([dict(v, name=name)])[0])
            elif isinstance(v, (bytes, bytearray)):
                file_part(name, {"filename": name, "content": bytes(v), "content_type": None})
            elif v is None:
                text_part(name, "")
            elif isinstance(v, bool):
                text_part(name, "true" if v else "false")
            elif isinstance(v, (dict, list)):
                text_part(name, js_json(v))
            else:
                text_part(name, js_json(v) if isinstance(v, float) else str(v))
    out.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


class ForwardMixin:
    """Mixed into Skapi."""

    # ---- forwardRequest -----------------------------------------------------------------------------

    def forward_request(self, options: Dict[str, Any], form: Optional[Dict[str, Any]] = None, *,
                        on_stream: Optional[Callable[[str, int], None]] = None) -> Any:
        """
        Calls another API through Skapi. options: url (required), method, headers, data, params,
        secretName (a client secret stored on skapi.com; put "$CLIENT_SECRET" where it goes),
        skapiHeaders, queue, expires, stream, poll (milliseconds between checks, 1000 or more; 0 does not poll), multipart.

        Without queue/poll/stream: returns the API's answer. With poll or stream: waits for the
        answer and returns it, handing streamed text to on_stream(text, seq) as it arrives. With a
        queue and no poll: returns {id, status, queue_name, in_queue, request_id} at once; check it
        later with forward_request_poll(request_id).
        """
        if not isinstance(options, dict):
            raise _p('"options" is required in the second argument.')
        if options.get("apiKeyHeader") is not None or options.get("apiKeyScheme") is not None:
            raise _p('"apiKeyHeader" and "apiKeyScheme" are no longer supported. Store the key as a client secret, name it with "secretName", and put "$CLIENT_SECRET" where the key goes.')
        multipart = options.get("multipart")
        if multipart is not None and not isinstance(multipart, bool):
            raise _p('"multipart" should be type: <boolean>.')
        response_type = options.get("responseType")
        if response_type is not None:
            if response_type == "response":
                raise _p('"responseType": "response" is not available here. The request is relayed from the server and what comes back is the stored answer, not a live Response; the destination\'s status code is the "status_code" of the row forward_request_history lists.')
            if response_type not in ("json", "text"):
                raise _p('"responseType" should be either "json" or "text".')
        method = options.get("method") or "POST"
        merge_into = "params" if isinstance(method, str) and method.lower() in ("get", "delete", "head") else "data"

        params: Dict[str, Any] = {"url": options.get("url"), "method": method}
        for k in ("secretName", "headers", "data", "params", "skapiHeaders", "service", "owner", "queue", "expires", "stream", "realtime", "poll"):
            if k in options and options[k] is not None:
                params[k] = options[k]

        if multipart:
            if options.get("data") is not None:
                raise _p('"data" cannot be sent with "multipart": true. The form itself is the body.')
            if form is None:
                raise _p('"multipart": true needs a form body in the first argument.')
            if not isinstance(form, dict):
                raise _p('"form" should be a submit event, a form element, FormData, or an object.')
            body, content_type = _multipart(form)
            b64 = base64.b64encode(body).decode("ascii")
            if len(b64) > MULTIPART_LIMIT:
                raise _p(f"Multipart body is too large: {len(b64)} bytes once base64 encoded, and the limit is {MULTIPART_LIMIT}. Upload the file first and send its url instead.")
            params["body_b64"] = b64
            params["body_content_type"] = content_type
        elif isinstance(form, dict) and form:
            if params.get(merge_into) is not None and not isinstance(params[merge_into], dict):
                raise _p(f'"{merge_into}" should be type: <object>.')
            if len(json.dumps(form, default=str).encode("utf-8")) > 2 * 1024 * 1024:
                raise SkapiError("Data should not exceed 2MB", "INVALID_REQUEST")
            params[merge_into] = dict(form, **(params.get(merge_into) or {}))

        return self._dispatch_forward(params, on_stream, response_type)

    def _dispatch_forward(self, params: Dict[str, Any], on_stream: Optional[Callable], response_type: Optional[str]) -> Any:
        secret_named = bool(params.get("secretName"))
        poll = params.pop("poll", None)
        # 0 (or False, or absent) means "do not poll"; any other number is the interval.
        if isinstance(poll, (int, float)) and not isinstance(poll, bool) and poll != 0:
            _assert_poll_interval(poll)
        latency = poll if isinstance(poll, (int, float)) and not isinstance(poll, bool) else (1000 if poll else 0)
        self._ensure_connection()
        signed_in = self._signed_in()
        if (latency or params.get("stream")) and not params.get("queue"):
            params["queue"] = f"{(self._user or {}).get('user_id') or 'anonymous'}-" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(6))

        body: Dict[str, Any] = {}
        url = params.get("url")
        if not url or not isinstance(url, str):
            raise _p('"url" should be type: <string>.')
        _absolute_url(url)
        body["url"] = url
        has_secret = "$CLIENT_SECRET" in url
        if "secretName" in params:
            if not isinstance(params["secretName"], str):
                raise _p(f'{_jd(params["secretName"])} is invalid in "secretName". allowed type or value is: Type<string>.')
            body["secretName"] = params["secretName"]
        m = params.get("method")
        if m and (not isinstance(m, str) or m.lower() not in METHODS):
            raise _p('"method" should be one of "GET", "POST", "PUT", "PATCH", "DELETE" or "HEAD".')
        body["method"] = m.lower()
        for k in ("stream", "realtime"):
            if k in params:
                if not isinstance(params[k], bool):
                    raise _p(f'"{k}" should be type: <boolean>.')
                body[k] = params[k]
        if "headers" in params:
            h = params["headers"]
            if h and not isinstance(h, dict):
                raise _p('"headers" should be type: <object>.')
            for k in (h or {}):
                if str(k).lower().startswith("x-skapi-"):
                    raise _p(f'"headers" cannot set "{k}": the "x-skapi-" prefix is reserved. Use "skapiHeaders" to tell the destination who the caller is.')
            has_secret = has_secret or _has_secret(h)
            body["headers"] = h
        if "skapiHeaders" in params:
            sh = params["skapiHeaders"]
            if isinstance(sh, bool):
                body["skapiHeaders"] = sh
            elif isinstance(sh, dict):
                body["skapiHeaders"] = {"user": bool(sh.get("user")), "service": bool(sh.get("service"))}
            else:
                raise _p('"skapiHeaders" should be type: <boolean> or { user?: boolean; service?: boolean }.')
        for k in ("data", "params"):
            if k in params:
                v = params[k]
                if v and not isinstance(v, dict):
                    raise _p(f'"{k}" should be type: <object>.')
                has_secret = has_secret or _has_secret(v)
                body[k] = v
        for k in ("body_b64", "body_content_type"):
            if k in params:
                body[k] = params[k]
        if "expires" in params:
            if isinstance(params["expires"], bool) or not isinstance(params["expires"], (int, float)):
                raise _p(f'{_jd(params["expires"])} is invalid in "expires". allowed type or value is: Type<number>.')
            body["expires"] = params["expires"]
        if "queue" in params:
            if not isinstance(params["queue"], str):
                raise _p(f'{_jd(params["queue"])} is invalid in "queue". allowed type or value is: Type<string>.')
            body["queue"] = params["queue"]
        for k in ("service", "owner"):
            if k in params:
                body[k] = params[k]
        if body.get("realtime") and not body.get("stream"):
            raise _p('"realtime" requires "stream": true.')
        if body.get("body_b64") and body.get("data"):
            raise _p('"data" cannot be sent with "multipart": true.')
        if secret_named and not has_secret:
            body.pop("secretName", None)

        token = self._fresh_id_token() if signed_in else None
        extra = {"X-Access-Token": self._session.access_token.jwt_token} if signed_in else None
        res = self._requester.request("csr", body, auth=signed_in, token=token, extra_headers=extra)

        service = params.get("service") or self.service
        if _is_envelope(res) and res.get("status") in ("running", "pending"):
            full_id = request_key(body["method"], url, service, res["id"])
            res["request_id"] = full_id
            if latency > 0 or body.get("stream"):
                res = self.forward_request_poll(full_id, poll=latency or 1000, on_stream=on_stream,
                                                service=params.get("service"), owner=params.get("owner"))
        return self._response_type(res, response_type)

    @staticmethod
    def _response_type(res: Any, response_type: Optional[str]) -> Any:
        if not response_type or _is_envelope(res) or (isinstance(res, dict) and res.get("status") == "stopped"):
            return res
        if response_type == "text":
            return res if isinstance(res, str) else js_json(res)
        if isinstance(res, str):
            try:
                return json.loads(res)
            except ValueError:
                return res
        return res

    def _request_id(self, request_id: Any, url: Optional[str], method: Optional[str], service: Optional[str]) -> str:
        if not isinstance(request_id, str) or not request_id:
            raise _p('"requestId" should be type: <string>.')
        if "#" in request_id:
            return request_id
        if not isinstance(url, str) or not isinstance(method, str) or not url or not method:
            raise _p('"url" and "method" are required to address a request by its short id.')
        _absolute_url(url)
        return request_key(method, url, service or self.service, request_id)

    def forward_request_poll(self, request_id: str, *, poll: float = 1000, url: Optional[str] = None, method: Optional[str] = None,
                             on_stream: Optional[Callable[[str, int], None]] = None,
                             service: Optional[str] = None, owner: Optional[str] = None) -> Any:
        """Waits for a queued request (its request_id, or its short id with url and method) and returns the answer."""
        if isinstance(poll, bool) or not isinstance(poll, (int, float)):
            raise _p('"poll" should be a number.')
        poll = poll or 1000
        _assert_poll_interval(poll)
        full_id = self._request_id(request_id, url, method, service)
        self._ensure_connection()
        cursor, stalled = 0, 0
        while True:
            time.sleep(poll / 1000)
            while True:
                body = {"id": full_id, "service": service or self.service, "owner": owner or self.owner}
                if on_stream:
                    body["since"] = cursor
                result = self._call("csr-poll", body, auth=self._signed_in())
                # Chunks, "more" and a running status belong to skapi's status envelope. A resolved
                # read is the destination's own body, returned as it is: a "chunks", "more" or
                # "status": "pending" key in THAT is the destination's data, not text to stream or
                # a cue to read again.
                envelope = _is_envelope(result)
                moved = False
                if on_stream and envelope:
                    cursor, moved = _deliver_chunks(result, cursor, on_stream)
                running = envelope and result.get("status") in ("running", "pending")
                more = envelope and bool(result.get("more"))
                if more and moved:
                    stalled = 0
                    continue
                if running:
                    stalled = 0
                    break
                stalled = stalled + 1 if more else 0
                if more and stalled < STREAM_DEGRADED_RETRIES:
                    break
                return result

    def forward_request_stream(self, request_id: str, options: Optional[Dict[str, Any]] = None, *,
                               on_stream: Optional[Callable[[str, int], None]] = None) -> Any:
        """Reads a streamed request's text from `since` (or the start) until it settles; returns the final answer."""
        options = dict(options or {})
        poll = options.get("poll")
        latency = poll if isinstance(poll, (int, float)) and not isinstance(poll, bool) else 1000
        _assert_poll_interval(latency)
        if "since" in options and (isinstance(options["since"], bool) or not isinstance(options["since"], (int, float))):
            raise _p('"since" should be a number.')
        full_id = self._request_id(request_id, options.get("url"), options.get("method"), options.get("service"))
        self._ensure_connection()
        cursor = int(options.get("since") or 0) if (options.get("since") or 0) > 0 else 0
        stalled = 0
        while True:
            result = self._call("csr-poll", {"id": full_id, "service": options.get("service") or self.service,
                                             "owner": options.get("owner") or self.owner, "since": cursor}, auth=self._signed_in())
            if not _is_envelope(result):
                return result
            moved = False
            if on_stream:
                cursor, moved = _deliver_chunks(result, cursor, on_stream)
            elif isinstance(result.get("last_seq"), int) and result["last_seq"] > cursor:
                cursor, moved = result["last_seq"], True
            running = result.get("status") in ("running", "pending")
            more = bool(result.get("more"))
            if more and moved:
                continue
            stalled = stalled + 1 if more else 0
            if not running and (not more or stalled >= STREAM_DEGRADED_RETRIES):
                return result
            time.sleep(latency / 1000)

    def forward_request_finalize(self, request_id: str, data: Any = None, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stores `data` as a streamed request's final answer, so later polls return it."""
        options = dict(options or {})
        full_id = self._request_id(request_id, options.get("url"), options.get("method"), options.get("service"))
        self._ensure_connection()
        body: Dict[str, Any] = {"id": full_id}
        if data is not None:
            body["data"] = data
        body.update({"service": options.get("service") or self.service, "owner": options.get("owner") or self.owner})
        return self._call("csr-finalize", body, auth=self._signed_in())

    def forward_request_history(self, params: Dict[str, Any], fetch_options: Optional[dict] = None) -> dict:
        """The forwarded requests you made to one url and method, newest last, with their answers."""
        self._ensure_connection()
        params = dict(params or {})
        service = params.get("service") or self.service
        owner = params.get("owner") or self.owner
        for key in ("url", "method"):
            if key not in params:
                raise _p(f'Key "{key}" is required.')
        if not isinstance(params["url"], str):
            raise _p(f'{_jd(params["url"])} is invalid in "url". allowed type or value is: Type<string>.')
        if params["method"] not in UPPER_METHODS:
            raise _p(f'{_jd(params["method"])} is invalid in "method". allowed types or values are: ' + ", ".join(_jd(m) for m in UPPER_METHODS) + ".")
        if "status" in params and params["status"] not in ("pending", "running", "resolved", "failed"):
            raise _p(f'{_jd(params["status"])} is invalid in "status". allowed types or values are: "pending", "running", "resolved", "failed".')
        for k in ("queue", "queue_exclude"):
            if k in params and params[k] is not None and not isinstance(params[k], str):
                raise _p(f'{_jd(params[k])} is invalid in "{k}". allowed type or value is: Type<string>.')
        for k in ("compact", "queue_exact"):
            if k in params and not isinstance(params[k], bool):
                raise _p(f'{_jd(params[k])} is invalid in "{k}". allowed type or value is: Type<boolean>.')
        prefix = request_key(params["method"], params["url"], service, "")
        req: Dict[str, Any] = {"id": prefix, "queue": params.get("queue"), "status": params.get("status"), "service": service, "owner": owner}
        if params.get("compact"):
            req["compact"] = True
        if params.get("queue_exact"):
            req["queue_exact"] = True
        if params.get("queue_exclude"):
            req["queue_exclude"] = params["queue_exclude"]
        req = {k: v for k, v in req.items() if v}
        if req.get("queue"):
            req["id_prefix"] = req.pop("id")
        res = self._call("csr-poll", req, auth=self._signed_in(), fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            out = []
            for r in res["list"]:
                rslv = r.get("rslv") or {}
                item = {
                    "id": r.get("id"),
                    "status_code": rslv.get("status_code") if isinstance(rslv, dict) else None,
                    "response_body": (rslv.get("body") or rslv.get("truncated")) if isinstance(rslv, dict) else None,
                }
                for key, src in (("error", "err"), ("created", "stmp"), ("updated", "utmp")):
                    if src in r:
                        item[key] = r[src]
                if isinstance(r.get("att"), (int, float)):
                    item["executed"] = r["att"] * 1000
                if isinstance(r.get("rtmp"), (int, float)):
                    item["responded"] = r["rtmp"]
                for key, src in (("request_body", "reqbdy"), ("expires", "expt"), ("status", "stts"), ("queue_name", "qid"),
                                 ("request_text", "reqtxt"), ("response_text", "rslvtxt")):
                    if src in r:
                        item[key] = r[src]
                if r.get("rslvmk") is not None:
                    item["response_complete_marker"] = bool(r["rslvmk"])
                if r.get("cmpct"):
                    item["compact"] = True
                item["request_id"] = prefix + str(r.get("id"))
                out.append(item)
            res["list"] = out
        return res

    def cancel_forward_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Cancels a queued request that has not run yet: {url, method, id}."""
        params = dict(params or {})
        for key in ("url", "method", "id"):
            if key not in params:
                raise _p(f'Key "{key}" is required.')
        if params["method"] not in UPPER_METHODS:
            raise _p(f'{_jd(params["method"])} is invalid in "method". allowed types or values are: ' + ", ".join(_jd(m) for m in UPPER_METHODS) + ".")
        for key in ("url", "id", "queue"):
            if key in params and not isinstance(params[key], str):
                raise _p(f'{_jd(params[key])} is invalid in "{key}". allowed type or value is: Type<string>.')
        self._ensure_connection()
        service = params.get("service") or self.service
        full_id = request_key(params["method"], params["url"], service, params["id"])
        return self._call("csr-cancel", {"id": full_id, "service": service, "owner": params.get("owner") or self.owner}, auth=self._signed_in())

    def forward_request_queue_count(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """How many requests are waiting in one of your queues. Signed-in users only."""
        params = dict(params or {})
        if not params.get("queue"):
            raise _p('"queue" is required.')
        res = self._call("csr-poll", {"service": params.get("service") or self.service, "owner": params.get("owner") or self.owner,
                                      "queue": params["queue"] + ":"}, auth=True)
        if isinstance(res, dict) and isinstance(res.get("queue_name"), str):
            res["queue_name"] = res["queue_name"].rstrip(":")
        return res

    # ---- inquiry ----------------------------------------------------------------------------------

    def send_inquiry(self, data: Dict[str, Any]) -> str:
        """Sends a message to the project's owner: {name, email, subject, message}."""
        self._ensure_connection()
        data = dict(data or {})
        for key in ("name", "email", "subject", "message"):
            if key not in data:
                raise _p(f'Key "{key}" is required.')
        for key in ("name", "subject", "message"):
            if not isinstance(data[key], str):
                raise _p(f'{_jd(data[key])} is invalid in "{key}". allowed type or value is: Type<string>.')
        validate_email(data["email"])
        self._call("send-inquiry", {k: data[k] for k in ("name", "email", "subject", "message")})
        return "SUCCESS: Inquiry has been sent."
