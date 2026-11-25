"""
Request forwarding (call another API through Skapi, with your stored client secrets) and
inquiries, ported from skapi-js (src/methods/request.ts).

Answers arrive by polling, exactly as skapi-js does without its realtime connection: a queued or
streamed request is dispatched, then polled until it settles. Streamed text is handed to an
on_stream(text, seq) callback as it arrives.

A poll ends only on the server's own answer (2.7.0): a read that fails on the way (no network, no
answer in time, rate limited, a server fault, no token) is tried again, waiting longer each time.
A request sent with notify=True is read at once when a status frame names it, and only as a
heartbeat while frames are arriving (_request_status.py).
"""

from __future__ import annotations

import base64
import json
import random
import re
import string
import threading
import time
import uuid
import warnings
from typing import Any, Callable, Dict, List, Optional

from ._database import _prepare_files
from ._http import js_json
from ._request_status import STATUS_PUSH_IDLE_POLL_MS
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
# Codes of a request that failed on the way, not because the server said no (skapi-js 2.7.0). A poll
# keeps going through these; only the server's own answer ends it.
TRANSPORT_FAILURE_CODES = ("NETWORK_ERROR", "TIMEOUT", "RATE_LIMITED", "TOO_MANY_REQUESTS", "SERVER_ERROR", "ABORTED")
# Longest wait between two tries of a poll whose reads keep failing on the way.
POLL_RETRY_MAX_MS = 30 * 1000
# How many requests forward_request_status asks about per call to the server.
STATUS_BATCH_MAX = 100
_CREF = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _poll_retry_delay(latency: float, failures: int) -> float:
    """How long a poll waits after `failures` reads in a row failed on the way: the next tick after
    the first, then twice the interval each time, up to POLL_RETRY_MAX_MS."""
    if failures <= 1:
        return 0
    return min(POLL_RETRY_MAX_MS, latency * 2 ** (failures - 1))


def _client_reference(v: Any) -> str:
    """A `cref`: 1 to 64 letters, digits, "_" or "-", the rule the server stores it under."""
    if not isinstance(v, str) or not _CREF.match(v):
        raise _p('"cref" should be 1 to 64 characters of letters, digits, "_" or "-".')
    return v


def _transport_options(opts: Any) -> Dict[str, Any]:
    """
    deadline (milliseconds in all, then TIMEOUT), fresh (accepted for skapi-js parity: a skapi-py
    read never joins another read, so every read is fresh) and signal (a threading.Event; once set
    the read fails with ABORTED).
    """
    opts = opts or {}
    out: Dict[str, Any] = {}
    deadline = opts.get("deadline")
    if deadline is not None:
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or deadline != deadline \
                or deadline in (float("inf"), float("-inf")) or deadline <= 0:
            raise _p('"deadline" should be a number of milliseconds above 0.')
        out["deadline"] = deadline
    fresh = opts.get("fresh")
    if fresh is not None and not isinstance(fresh, bool):
        raise _p('"fresh" should be type: <boolean>.')
    signal = opts.get("signal")
    if signal is not None:
        if not callable(getattr(signal, "is_set", None)):
            raise _p('"signal" should be a threading.Event.')
        out["signal"] = signal
    return out


class _PagingGate:
    """
    Decides once, under a lock, whether a bounded read's answer is used. Either the read saves its
    startKey for fetchMore first (keep) and the caller gets that answer, or the caller gives up first
    (drop) and the paging state stays where the caller last saw it, as in skapi-js, whose aborted
    request never saves the page it was reading.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.kept = False
        self.dropped = False

    def keep(self) -> bool:
        with self.lock:
            if not self.dropped:
                self.kept = True
            return self.kept

    def drop(self) -> bool:
        """True when the answer is dropped; False when the read already saved its page."""
        with self.lock:
            if not self.kept:
                self.dropped = True
            return self.dropped


def _ms_text(ms: float) -> str:
    """A number of milliseconds as skapi-js prints it: 1000000, not 1e+06."""
    if isinstance(ms, float) and ms.is_integer():
        return str(int(ms))
    return str(ms)


def _bounded(fn: Callable[[], Any], deadline: Optional[float] = None, signal: Any = None,
             paging: Optional[_PagingGate] = None) -> Any:
    """
    Runs fn() and waits for it at most `deadline` milliseconds (TIMEOUT past it), or until
    `signal` is set (ABORTED). The caller is answered at once; a request already on the network
    is left to finish in the background, and its answer is dropped. paging: the gate fn's request
    asks before saving a startKey, so a dropped answer does not move fetchMore on.
    """
    if deadline is None and signal is None:
        return fn()
    if signal is not None and signal.is_set():
        raise SkapiError("Aborted", "ABORTED")
    box: Dict[str, Any] = {}
    done = threading.Event()

    def give_up(err: SkapiError) -> None:
        if paging is not None and not paging.drop():
            done.wait()  # the read already saved its page: its answer is the caller's
            return
        raise err

    def run():
        try:
            box["value"] = fn()
        except BaseException as err:  # handed to the caller
            box["error"] = err
        finally:
            done.set()

    threading.Thread(target=run, daemon=True, name="skapi-read").start()
    end = time.monotonic() + deadline / 1000 if deadline is not None else None
    while True:
        step = 0.05 if signal is not None else None
        if end is not None:
            left = end - time.monotonic()
            if left <= 0:
                if done.is_set():
                    break
                give_up(SkapiError(f"No answer within {_ms_text(deadline)} ms.", "TIMEOUT"))
                break
            step = left if step is None else min(step, left)
        if done.wait(step):
            break
        if signal is not None and signal.is_set():
            give_up(SkapiError("Aborted", "ABORTED"))
            break
    if "error" in box:
        raise box["error"]
    return box.get("value")


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
        skapiHeaders, queue, expires, stream, poll (milliseconds between checks, 1000 or more; 0 does not poll), multipart,
        cref (your own reference for this request: 1 to 64 letters, digits, "_" or "-"; stored on it and
        handed back by the reply and every read), notify (status push for a queued request of a
        signed-in user: its poll reads it when a status frame names it, see on_request_status).

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
        for k in ("secretName", "headers", "data", "params", "skapiHeaders", "service", "owner", "queue", "expires", "stream", "realtime",
                  "notify", "cref", "poll"):
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
        for k in ("stream", "realtime", "notify"):
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
        if "cref" in params:
            body["cref"] = _client_reference(params["cref"])
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
            # The server accepted notify (an older one ignores it and says nothing).
            notified = res.get("notify") is True
            if notified:
                self._status_push().note_ack()
            # The server echoes cref; kept here too so the reply always carries it.
            if body.get("cref") and "cref" not in res:
                res["cref"] = body["cref"]
            if latency > 0 or body.get("stream"):
                res = self._poll_request(full_id, latency=latency or 1000, on_stream=on_stream, service=params.get("service"),
                                         owner=params.get("owner"), notify=notified, auth=signed_in)
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
                             service: Optional[str] = None, owner: Optional[str] = None, notify: bool = False) -> Any:
        """
        Waits for a queued request (its request_id, or its short id with url and method) and returns
        the answer. Reads that fail on the way are tried again (never raised); only the server's own
        answer ends the wait. notify=True for a request sent with notify: it is read when a status
        frame names it, and otherwise every minute while frames are arriving.
        """
        if isinstance(poll, bool) or not isinstance(poll, (int, float)):
            raise _p('"poll" should be a number.')
        if not isinstance(notify, bool):
            raise _p('"notify" should be type: <boolean>.')
        poll = poll or 1000
        _assert_poll_interval(poll)
        full_id = self._request_id(request_id, url, method, service)
        self._ensure_connection()
        return self._poll_request(full_id, latency=poll, on_stream=on_stream, service=service, owner=owner,
                                  notify=notify, auth=self._signed_in())

    def _poll_failure(self, err: SkapiError, auth: bool, state: Dict[str, Any]) -> bool:
        """
        A read of a poll failed. True when the poll carries on: the read failed on the way, the
        gateway refused the token (one forced refresh per run of refusals), or the user is signed out
        (the poll waits for a sign in). False for the server's own answer, which ends the poll.
        """
        if auth and not self._signed_in():
            return True  # not counted: the next read waits for a sign in
        if str(err.code) == "401":
            state["failures"] += 1
            if not state["refresh_tried"]:
                state["refresh_tried"] = True
                try:
                    self._refresh_session()
                except SkapiError:
                    pass  # a token that still fails just waits like any failure
            return True
        if err.code in TRANSPORT_FAILURE_CODES:
            state["failures"] += 1
            return True
        return False

    def _poll_request(self, full_id: str, *, latency: float, on_stream: Optional[Callable], service: Optional[str],
                      owner: Optional[str], notify: bool, auth: bool) -> Any:
        push = self._status_push() if notify else None
        wake = threading.Event()
        unhold = push.hold() if push else None
        unwake = push.add_waker(full_id, wake.set) if push else None
        state = {"failures": 0, "refresh_tried": False}
        last_poll: List[Optional[float]] = [None]

        def pause(ms: float) -> None:
            """Waits `ms`, longer while status frames are arriving, and not at all after a wake."""
            start = time.monotonic()
            while True:
                target = start + ms / 1000
                if push is not None and last_poll[0] is not None and push.warm():
                    target = max(target, last_poll[0] + STATUS_PUSH_IDLE_POLL_MS / 1000)
                left = target - time.monotonic()
                if left <= 0:
                    return
                if wake.wait(min(left, latency / 1000)):
                    wake.clear()
                    return

        try:
            cursor, stalled = 0, 0
            pause(latency)
            while True:
                if auth and not self._signed_in():
                    # Signed out: nothing to read with. Waits for a sign in, then reads.
                    pause(latency)
                    continue
                body = {"id": full_id, "service": service or self.service, "owner": owner or self.owner}
                if on_stream:
                    body["since"] = cursor
                try:
                    last_poll[0] = time.monotonic()
                    result = self._call("csr-poll", body, auth=auth)
                except SkapiError as err:
                    if not self._poll_failure(err, auth, state):
                        raise
                    pause(max(latency, _poll_retry_delay(latency, state["failures"])))
                    continue
                state["failures"], state["refresh_tried"] = 0, False
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
                    pause(latency)
                    continue
                stalled = stalled + 1 if more else 0
                if more and stalled < STREAM_DEGRADED_RETRIES:
                    pause(latency)
                    continue
                return result
        finally:
            if unwake:
                unwake()
            if unhold:
                unhold()

    def forward_request_stream(self, request_id: str, options: Optional[Dict[str, Any]] = None, *,
                               on_stream: Optional[Callable[[str, int], None]] = None) -> Any:
        """
        Reads a streamed request's text from `since` (or the start) until it settles; returns the
        final answer. Reads that fail on the way are tried again, as for forward_request_poll.
        """
        options = dict(options or {})
        poll = options.get("poll")
        latency = poll if isinstance(poll, (int, float)) and not isinstance(poll, bool) else 1000
        _assert_poll_interval(latency)
        if "since" in options and (isinstance(options["since"], bool) or not isinstance(options["since"], (int, float))):
            raise _p('"since" should be a number.')
        full_id = self._request_id(request_id, options.get("url"), options.get("method"), options.get("service"))
        self._ensure_connection()
        auth = self._signed_in()
        cursor = int(options.get("since") or 0) if (options.get("since") or 0) > 0 else 0
        stalled = 0
        state = {"failures": 0, "refresh_tried": False}
        while True:
            if auth and not self._signed_in():
                time.sleep(latency / 1000)  # signed out: waits for a sign in
                continue
            try:
                result = self._call("csr-poll", {"id": full_id, "service": options.get("service") or self.service,
                                                 "owner": options.get("owner") or self.owner, "since": cursor}, auth=auth)
            except SkapiError as err:
                if not self._poll_failure(err, auth, state):
                    raise
                time.sleep(max(latency, _poll_retry_delay(latency, state["failures"])) / 1000)
                continue
            state["failures"], state["refresh_tried"] = 0, False
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
        """
        Stores `data` as a streamed request's final answer, so later polls return it.
        options: url, method, service, owner, if_absent (store only when no result is stored yet;
        otherwise nothing changes and the answer is {"finalized": False, "reason": "exists"}).
        """
        options = dict(options or {})
        if_absent = options.get("if_absent", options.get("ifAbsent"))
        if if_absent is not None and not isinstance(if_absent, bool):
            raise _p('"if_absent" should be type: <boolean>.')
        full_id = self._request_id(request_id, options.get("url"), options.get("method"), options.get("service"))
        self._ensure_connection()
        body: Dict[str, Any] = {"id": full_id}
        if data is not None:
            body["data"] = data
        body.update({"service": options.get("service") or self.service, "owner": options.get("owner") or self.owner})
        if if_absent:
            body["if_absent"] = True  # sent only when asked, so a call without it is the same request as before
        return self._call("csr-finalize", body, auth=self._signed_in())

    def forward_request_history(self, params: Dict[str, Any], fetch_options: Optional[dict] = None) -> dict:
        """
        The forwarded requests you made to one url and method, newest last, with their answers.
        params also take fields ("ids": each row is only its id, status, times, queue and cref),
        after (only rows newer than this request id), deadline, fresh and signal.
        """
        self._ensure_connection()
        params = dict(params or {})
        transport = _transport_options(params)
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
        if params.get("fields") is not None and params["fields"] != "ids":
            raise _p('"fields" should be "ids".')
        if params.get("after") is not None and not isinstance(params["after"], str):
            raise _p(f'{_jd(params["after"])} is invalid in "after". allowed type or value is: Type<string>.')
        prefix = request_key(params["method"], params["url"], service, "")
        req: Dict[str, Any] = {"id": prefix, "queue": params.get("queue"), "status": params.get("status"), "service": service, "owner": owner}
        if params.get("compact"):
            req["compact"] = True
        if params.get("queue_exact"):
            req["queue_exact"] = True
        if params.get("queue_exclude"):
            req["queue_exclude"] = params["queue_exclude"]
        if params.get("fields"):
            req["fields"] = params["fields"]
        if params.get("after"):
            req["after"] = params["after"]
        req = {k: v for k, v in req.items() if v}
        if req.get("queue"):
            req["id_prefix"] = req.pop("id")
        auth = self._signed_in()
        gate = _PagingGate()
        res = _bounded(lambda: self._call("csr-poll", req, auth=auth, fetch_options=fetch_options, keep_paging=gate.keep),
                       paging=gate, **transport)
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
                    elif key in r:  # a fields="ids" row already names these in full
                        item[key] = r[key]
                if isinstance(r.get("att"), (int, float)):
                    item["executed"] = r["att"] * 1000
                if isinstance(r.get("rtmp"), (int, float)):
                    item["responded"] = r["rtmp"]
                for key, src in (("request_body", "reqbdy"), ("expires", "expt"), ("status", "stts"), ("queue_name", "qid"),
                                 ("request_text", "reqtxt"), ("response_text", "rslvtxt")):
                    if src in r:
                        item[key] = r[src]
                if "status" not in item and "status" in r:
                    item["status"] = r["status"]
                if r.get("cref") is not None:
                    item["cref"] = r["cref"]
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

    # ---- reading many requests at once (2.7.0) -----------------------------------------------------

    def forward_request_status(self, requests: list, *, service: Optional[str] = None, owner: Optional[str] = None,
                               deadline: Optional[float] = None, fresh: Optional[bool] = None, signal: Any = None) -> Dict[str, Any]:
        """
        Where many forwarded requests stand, in one call per 100: status ("pending", "running",
        "resolved", "failed", "cancelled", or "missing" for one this caller cannot see), stream
        position (last_seq, final_seq), whether a result is stored (has_body), timestamps and cref.
        No bodies. A strongly consistent read.

        requests: full request ids, or {"id", "url", "method"} with the short id.
        deadline: milliseconds each call may take (TIMEOUT past it). signal: a threading.Event
        (ABORTED once set). Returns {"list": [...]} in the order asked.
        """
        if not isinstance(requests, (list, tuple)):
            raise _p('"requests" should be an array of request ids or { id, url, method }.')
        transport = _transport_options({"deadline": deadline, "fresh": fresh, "signal": signal})
        self._ensure_connection()
        service = service or self.service
        owner = owner or self.owner
        auth = self._signed_in()
        ids = []
        for r in requests:
            if isinstance(r, str):
                ids.append(self._request_id(r, None, None, service))
            elif isinstance(r, dict):
                ids.append(self._request_id(r.get("id"), r.get("url"), r.get("method"), service))
            else:
                raise _p('"requests" should be an array of request ids or { id, url, method }.')
        out: Dict[str, Any] = {"list": []}
        for i in range(0, len(ids), STATUS_BATCH_MAX):
            batch = ids[i:i + STATUS_BATCH_MAX]
            res = _bounded(lambda: self._call("csr-poll", {"ids": batch, "service": service, "owner": owner}, auth=auth), **transport)
            if isinstance(res, dict):
                # anything else the server reports beside the list (queue counters) is kept
                for k, v in res.items():
                    if k != "list" and k not in out:
                        out[k] = v
                if isinstance(res.get("list"), list):
                    out["list"].extend(res["list"])
        return out

    def forward_request_queue_counters(self, queues: list, *, service: Optional[str] = None, owner: Optional[str] = None,
                                       deadline: Optional[float] = None, fresh: Optional[bool] = None, signal: Any = None) -> Dict[str, Any]:
        """
        The counters of up to 20 queues: {"queues": {name: {"cnt", "rct", "seq", "in_queue"}}}.
        rct grows when a request on the queue finishes and seq when one is added: read these on
        every check and the requests themselves (forward_request_status) only when one moved. A queue
        that never had a request is left out.
        """
        if not isinstance(queues, (list, tuple)) or not queues or len(queues) > 20 \
                or any(not isinstance(q, str) or not q or ":" in q for q in queues):
            raise _p('"queues" should be an array of 1 to 20 queue names.')
        transport = _transport_options({"deadline": deadline, "fresh": fresh, "signal": signal})
        self._ensure_connection()
        auth = self._signed_in()
        body = {"queues": list(queues), "service": service or self.service, "owner": owner or self.owner}
        res = _bounded(lambda: self._call("csr-poll", body, auth=auth), **transport)
        queues_out = res.get("queues") if isinstance(res, dict) else None
        return {"queues": queues_out if isinstance(queues_out, dict) else {}}

    def forward_request_read(self, request_id: str, *, url: Optional[str] = None, method: Optional[str] = None,
                             since: Optional[float] = None, service: Optional[str] = None, owner: Optional[str] = None,
                             deadline: Optional[float] = None, fresh: Optional[bool] = None, signal: Any = None) -> Dict[str, Any]:
        """
        Reads one forwarded request in full, always as {"id", "status", "body"?, "error"?, "chunks"?,
        "last_seq"?, "final_seq"?, "more"?, ...}: a resolved request does not come back as its bare
        body, so the status is always there to read. since (a chunk sequence, 0 for the beginning)
        also returns a streamed request's text after that point, including the text a failed stream
        got before it failed. A stored result that cannot be loaded right now comes back as
        body_unavailable: True.
        """
        if since is not None and (isinstance(since, bool) or not isinstance(since, (int, float)) or since != since
                                  or since in (float("inf"), float("-inf"))):
            raise _p('"since" should be a number.')
        transport = _transport_options({"deadline": deadline, "fresh": fresh, "signal": signal})
        self._ensure_connection()
        service = service or self.service
        full_id = self._request_id(request_id, url, method, service)
        body: Dict[str, Any] = {"id": full_id, "envelope": True, "service": service, "owner": owner or self.owner}
        if since is not None:
            body["since"] = max(0, since)
        auth = self._signed_in()
        return _bounded(lambda: self._call("csr-poll", body, auth=auth), **transport)

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
