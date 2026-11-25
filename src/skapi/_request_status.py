"""
Request status push, ported from skapi-js (src/methods/request_status.ts, 2.5.0 and 2.7.0).

A forwarded request sent with notify=True is stamped on the server with the caller's user. From
then on every status change of it (pending, running, resolved, failed, cancelled) arrives on that
user's realtime connections as one private frame:

    {"#private": {"v": 1, "ev": [{id, q, s, p, t, att}, ...]}, "#code": "CSR_STATUS"}

The frame is a HINT and never an outcome. A poll that a frame names reads the request at once,
and what the request says is what settles it, so a lost, late, duplicated or forged frame costs at
most one read or one slow interval, never a wrong answer. A frame a user sent carries "#user_id",
so a frame without one can only have come from the server. These frames never reach the app's
realtime callback.

Connection rules, as in skapi-js: the realtime connection is opened only when none exists and a
user is signed in, and only a connection this module opened is ever closed by it (10 minutes after
the last holder lets go, and only while no group is joined on it).
"""

from __future__ import annotations

import json
import threading
import warnings
from typing import Any, Callable, Dict, List, Optional

from .errors import SkapiError

# While frames are arriving, a poll of a request sent with notify reads the request on its own only
# this often (a heartbeat), and otherwise only when a frame names it.
STATUS_PUSH_IDLE_POLL_MS = 60 * 1000
# How long the connection this module opened stays open after the last holder let go.
STATUS_PUSH_LINGER_SECONDS = 10 * 60
# How soon to look again for a connection to listen on after the one in use went away.
STATUS_PUSH_REATTACH_SECONDS = 3.0


def short_request_id(request_id: str) -> str:
    """"stamp:entropy" from any form of a request id (a full id ends with it)."""
    if not isinstance(request_id, str):
        return ""
    parts = request_id.split(":")
    return parts[-2] + ":" + parts[-1] if len(parts) >= 2 else request_id


def is_status_push_frame(data: Any) -> bool:
    """True for a frame that is a server status push (and so not the app's business)."""
    return isinstance(data, dict) and data.get("#code") == "CSR_STATUS" and bool(data.get("#private")) and not data.get("#user_id")


class StatusPush:
    """The status push listener of one Skapi object."""

    def __init__(self, skapi):
        self.skapi = skapi
        self.lock = threading.RLock()
        self.holders = 0
        self.acked = False  # the server accepted notify at least once: frames can exist for this client
        self.live = False  # listening on an open connection
        self.frame_seen = False  # a frame arrived on the current connection since it opened
        self.opened = None  # the _Realtime this module opened, and so may close
        self.listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.wakers: Dict[str, List[Callable[[], None]]] = {}
        self.linger: Optional[threading.Timer] = None
        self.retry: Optional[threading.Timer] = None
        self.attaching = False

    # ---- state -------------------------------------------------------------------------------------

    def note_ack(self) -> None:
        self.acked = True

    def warm(self) -> bool:
        """True while frames are known to be arriving. Only then may a poll slow down."""
        rt = getattr(self.skapi, "_rt", None)
        up = rt is not None and not rt.closing and rt.ws is not None and not rt.ws.closed
        return self.acked and self.live and up and self.frame_seen

    # ---- wakers and listeners ----------------------------------------------------------------------

    def add_waker(self, request_id: str, wake: Callable[[], None]) -> Callable[[], None]:
        """Run `wake` whenever a frame names this request. Returns the unregister."""
        key = short_request_id(request_id)
        with self.lock:
            self.wakers.setdefault(key, []).append(wake)

        def remove():
            with self.lock:
                lst = self.wakers.get(key)
                if lst and wake in lst:
                    lst.remove(wake)
                    if not lst:
                        del self.wakers[key]
        return remove

    def emit(self, event: Dict[str, Any]) -> None:
        with self.lock:
            listeners = list(self.listeners)
        for cb in listeners:
            try:
                cb(dict(event))
            except Exception as err:
                # a listener that raises must not cost the others their event
                warnings.warn(f"on_request_status callback raised {err!r}", RuntimeWarning, stacklevel=2)

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> Callable[[], None]:
        with self.lock:
            self.listeners.append(callback)
            live = self.live
        unhold = self.hold()
        if live:
            # already listening: this subscriber starts from a live connection too
            def hello():
                with self.lock:
                    still = callback in self.listeners
                if still:
                    try:
                        callback({"type": "connected"})
                    except Exception as err:
                        warnings.warn(f"on_request_status callback raised {err!r}", RuntimeWarning, stacklevel=2)
            t = threading.Timer(0, hello)
            t.daemon = True
            t.start()
        done = []

        def remove():
            with self.lock:
                if done or callback not in self.listeners:
                    return
                done.append(True)
                self.listeners.remove(callback)
            unhold()
        return remove

    # ---- frames and connection events (called from the realtime threads) ---------------------------

    def on_frame(self, data: Dict[str, Any]) -> None:
        body = data.get("#private")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError:
                return
        events = body.get("ev") if isinstance(body, dict) else None
        if not isinstance(events, list):
            return
        if self.live:
            self.frame_seen = True
        for e in events:
            if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not isinstance(e.get("s"), str):
                continue
            event: Dict[str, Any] = {"type": "status", "id": e["id"], "status": e["s"]}
            if isinstance(e.get("q"), str):
                event["queue"] = e["q"]
            if isinstance(e.get("p"), str):
                event["previous"] = e["p"]
            for key, src in (("updated", "t"), ("executed", "att")):
                if isinstance(e.get(src), (int, float)) and not isinstance(e.get(src), bool):
                    event[key] = e[src]
            with self.lock:
                wakers = list(self.wakers.get(e["id"], ()))
            for wake in wakers:
                try:
                    wake()
                except Exception as err:
                    warnings.warn(f"request status waker raised {err!r}", RuntimeWarning, stacklevel=2)
            self.emit(event)

    def socket_up(self) -> None:
        """The realtime connection opened (first open, a reconnect, the planned renewal)."""
        with self.lock:
            self.live = True
            self.frame_seen = False
            holding = self.holders > 0
        if holding:
            self.emit({"type": "connected"})

    def socket_down(self) -> None:
        """The realtime connection went away. Frames sent meanwhile are lost."""
        with self.lock:
            was = self.live
            self.live = False
            self.frame_seen = False
            holding = self.holders > 0
        if was and holding:
            self.emit({"type": "disconnected"})
        self.schedule_attach()

    def app_took_connection(self) -> None:
        """The app called connect_realtime on the connection this module opened: it is the app's now."""
        with self.lock:
            self.opened = None

    def push_opened(self, rt) -> None:
        """connect_realtime opened `rt` for this module (called inside its connect lock)."""
        with self.lock:
            self.opened = rt

    # ---- holding the connection ------------------------------------------------------------------

    def hold(self) -> Callable[[], None]:
        """Keep the listener attached. Returns the matching release."""
        with self.lock:
            self.holders += 1
            if self.linger is not None:
                self.linger.cancel()
                self.linger = None
        threading.Thread(target=self.attach, daemon=True, name="skapi-status-push").start()
        done = []

        def release():
            with self.lock:
                if done:
                    return
                done.append(True)
                self.holders = max(0, self.holders - 1)
                if self.holders > 0:
                    return
                if self.linger is not None:
                    self.linger.cancel()
                self.linger = threading.Timer(STATUS_PUSH_LINGER_SECONDS, self.release_connection)
                self.linger.daemon = True
                self.linger.start()
        return release

    def schedule_attach(self) -> None:
        with self.lock:
            if self.holders == 0 or self.retry is not None:
                return
            self.retry = threading.Timer(STATUS_PUSH_REATTACH_SECONDS, self._retry_attach)
            self.retry.daemon = True
            self.retry.start()

    def _retry_attach(self) -> None:
        with self.lock:
            self.retry = None
        self.attach()

    def attach(self) -> None:
        with self.lock:
            if self.holders == 0 or self.attaching:
                return
            self.attaching = True
        try:
            rt = getattr(self.skapi, "_rt", None)
            if rt is not None and not rt.closing:
                up = rt.ws is not None and not rt.ws.closed
                if up and not self.live:
                    self.socket_up()
                # not up: the connection's own reconnect opens a new socket, which reports itself
                return
            # Nobody has a connection. Opening one needs a signed-in user.
            if not self.skapi._signed_in():
                return
            try:
                # records the connection as this module's (push_opened) only when it opened one
                self.skapi.connect_realtime(lambda event: None, _status_push=True)
            except SkapiError:
                self.schedule_attach()
                return
            with self.lock:
                if self.holders == 0 and self.opened is not None and self.linger is None:
                    # every holder let go while it was connecting, and the linger already ran:
                    # arm it again, so the connection nobody holds is closed
                    self.linger = threading.Timer(STATUS_PUSH_LINGER_SECONDS, self.release_connection)
                    self.linger.daemon = True
                    self.linger.start()
        except Exception:
            # silent: the push is an accelerator, and polls run at their own speed without it
            self.schedule_attach()
        finally:
            with self.lock:
                self.attaching = False

    def release_connection(self) -> None:
        # inside the connect lock: an app connect_realtime cannot take the connection between the
        # check below and the close, and one still opening for this module is waited for
        with self.skapi._rt_connect_lock:
            with self.lock:
                self.linger = None
                if self.holders > 0:
                    return
                opened, self.opened = self.opened, None
                if self.retry is not None:
                    self.retry.cancel()
                    self.retry = None
            rt = getattr(self.skapi, "_rt", None)
            # ours, still the connection in use, and no group joined on it: nothing else uses it
            if opened is not None and rt is opened and not rt.closing and not rt.room:
                try:
                    self.skapi.close_realtime()
                except Exception:
                    pass


class RequestStatusMixin:
    """Mixed into Skapi."""

    def _status_push(self) -> StatusPush:
        with self._lock:
            if self._status_push_state is None:
                self._status_push_state = StatusPush(self)
            return self._status_push_state

    def on_request_status(self, callback: Callable[[Dict[str, Any]], None]) -> Callable[[], None]:
        """
        Listens to status changes of this user's forwarded requests sent with notify=True,
        including ones this client holds no poll for (a pass the server queued as the continuation
        of one, or a request sent from another device). Each change arrives on a background thread
        as {"type": "status", "id", "queue", "status", "previous", "updated", "executed"}.

        The realtime connection is kept open while a listener is registered (one is opened when the
        app has none and a user is signed in; the app's own realtime callback never sees these
        frames). The callback also gets {"type": "connected"} whenever the listener lands on an open
        connection (first time and after every reconnect) and {"type": "disconnected"} when it loses
        it. Frames are not kept for a connection that is down, so re-read what you show on
        "connected". A status event is a hint, not the outcome: read the request for that.

        Returns a function that removes the listener.
        """
        if not callable(callback):
            raise SkapiError("Callback must be a function.", "INVALID_PARAMETER")
        return self._status_push().subscribe(callback)

    def is_request_status_live(self) -> bool:
        """True while request status frames are arriving on this client (see on_request_status)."""
        state = self._status_push_state
        return bool(state and state.warm())
