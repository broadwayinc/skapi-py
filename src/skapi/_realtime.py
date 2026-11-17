"""
Realtime messaging over a WebSocket, ported from skapi-js (src/methods/realtime.ts) without
WebRTC: one connection per Skapi object, one group at a time, private messages to users,
presence notices, keep-alive, planned renewal before the server's 2 hour cut, and reconnects.

The callback runs on a background thread with dicts shaped as in skapi-js:
{"type", "message", "sender", "sender_cid", "sender_rid", "code"} for messages and notices, and
{"type", "message"} for connection events (success, close, error, reconnect).
"""

from __future__ import annotations

import json
import random
import re
import threading
import time
import warnings
from typing import Any, Callable, Dict, Optional

from ._database import user_id as _user_id
from ._ws import WebSocket, WebSocketClosed
from .errors import SkapiError

PING_INTERVAL = 60.0
PONG_TIMEOUT = 10.0
PONGLESS_PINGS_DEAD = 3
CONNECTION_LIFETIME = 7200.0
RENEW_BEFORE = 300.0
RENEW_JITTER = 120.0
JOIN_WAIT = 3.0
SEND_WINDOW = 0.1
SEQ_WAIT = 1.5
MAX_FRAME_BYTES = 32768
BATCH_CHARS = MAX_FRAME_BYTES - 2048
MAX_NOTIFICATION_BYTES = 3072
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_PRESENCE = {"j": [("has joined the message group.", "USER_JOINED")],
             "l": [("has left the message group.", "USER_LEFT")],
             "d": [("has been disconnected.", "USER_DISCONNECTED"), ("has left the message group.", "USER_LEFT")]}


def _p(message: str, code: str = "INVALID_PARAMETER") -> SkapiError:
    return SkapiError(message, code)


class _Realtime:
    """The live state of one Skapi object's realtime connection."""

    def __init__(self, skapi, callback: Callable[[Dict[str, Any]], None]):
        self.skapi = skapi
        self.callback = callback
        self.ws: Optional[WebSocket] = None
        self.lock = threading.RLock()
        self.closing = False
        self.room: Optional[str] = None
        self.reconnect_attempts = 0
        self.seq = 0
        self.order: Dict[str, Dict[str, Any]] = {}
        self.join_wait: Optional[Dict[str, Any]] = None
        self.pong_seen = False
        self.pongless_pings = 0
        self.pong_deadline: Optional[float] = None
        self.ping_sent_at = 0.0
        self.renew_at = 0.0
        self.generation = 0
        self.last_send: Dict[str, float] = {}
        self.window: Optional[Dict[str, Any]] = None
        self.send_lock = threading.Lock()

    # ---- events to the user's callback -----------------------------------------------------------

    def emit(self, msg: Dict[str, Any]) -> None:
        try:
            self.callback(msg)
        except Exception as err:
            warnings.warn(f"realtime callback raised {err!r}", RuntimeWarning, stacklevel=2)

    # ---- connection -------------------------------------------------------------------------------

    def open(self, renew: bool = False) -> None:
        """Opens a socket (fresh token first) and starts its reader and keep-alive threads."""
        token = self.skapi._access_token()
        _, record = self.skapi._requester.endpoints()
        try:
            ws = WebSocket(record["websocket_private"] + "?token=" + token)
        except (WebSocketClosed, OSError) as err:
            raise SkapiError("WebSocket closed before it opened.", "INVALID_REQUEST", err) from None
        with self.lock:
            old = self.ws
            self.ws = ws
            self.generation += 1
            generation = self.generation
            self.pong_seen = False
            self.pongless_pings = 0
            self.pong_deadline = None
            self.reconnect_attempts = 0
            self.renew_at = time.time() + CONNECTION_LIFETIME - RENEW_BEFORE - random.random() * RENEW_JITTER
        if not renew:
            self.emit({"type": "success", "message": "Connected to WebSocket server."})
        self.forget_order()
        if self.room:
            self.send_raw({"action": "joinRoom", "rid": self.room, "token": self.skapi._session.access_token.jwt_token, "ver": 2})
        threading.Thread(target=self.read_loop, args=(ws, generation), daemon=True, name="skapi-realtime-read").start()
        threading.Thread(target=self.ping_loop, args=(ws, generation), daemon=True, name="skapi-realtime-ping").start()
        if renew and old is not None:
            try:
                old.close()
            except OSError:
                pass

    def send_raw(self, frame: Dict[str, Any]) -> None:
        ws = self.ws
        if ws is None or ws.closed:
            raise _p("Realtime connection is not open. Try reconnecting with connect_realtime().", "INVALID_REQUEST")
        ws.send(json.dumps(frame, separators=(",", ":"), ensure_ascii=False))

    def current(self, generation: int) -> bool:
        return generation == self.generation and not self.closing

    def ping_loop(self, ws: WebSocket, generation: int) -> None:
        next_ping = time.time()
        while self.current(generation) and not ws.closed:
            now = time.time()
            if self.pong_deadline is not None and now >= self.pong_deadline:
                if now - self.ping_sent_at > 30:
                    self.pong_deadline = None  # this thread ran late: ping again instead
                    next_ping = now
                else:
                    self.drop(ws, generation)
                    return
            if now >= self.renew_at:
                self.renew_at = float("inf")
                threading.Thread(target=self.renew, args=(generation,), daemon=True).start()
            if now >= next_ping:
                if self.pong_seen:
                    self.pongless_pings += 1
                    if self.pongless_pings >= PONGLESS_PINGS_DEAD:
                        self.drop(ws, generation)
                        return
                    if self.pong_deadline is None:
                        self.ping_sent_at = now
                        self.pong_deadline = now + PONG_TIMEOUT
                try:
                    ws.send('{"action":"keepAlive"}')
                except (OSError, WebSocketClosed):
                    return
                next_ping = now + PING_INTERVAL
            time.sleep(0.5)

    def renew(self, generation: int) -> None:
        if not self.current(generation):
            return
        try:
            self.open(renew=True)
        except SkapiError:
            pass  # the old socket stays

    def drop(self, ws: WebSocket, generation: int) -> None:
        if not self.current(generation):
            return
        try:
            ws.close()
        except OSError:
            pass
        self.emit({"type": "error", "message": "Skapi: WebSocket unexpected close."})
        self.schedule_reconnect(generation)

    def schedule_reconnect(self, generation: int) -> None:
        def run():
            while self.current(generation):
                if not self.skapi._signed_in():
                    self.emit({"type": "error", "message": "Skapi: Realtime connection closed. User login is required."})
                    return
                self.reconnect_attempts += 1
                attempts = self.reconnect_attempts
                base = min(30.0, 3.0 * 2 ** (attempts - 1))
                self.emit({"type": "reconnect", "message": f"Reconnecting to WebSocket server...{attempts}"})
                time.sleep(base * (1 + random.random() * 0.5))
                if not self.current(generation):
                    return
                try:
                    if self.skapi._user and self.skapi._user.get("anonymous"):
                        if self.skapi.verify_anonymous_session() is None:
                            continue
                    self.open()
                    return
                except SkapiError:
                    continue
        threading.Thread(target=run, daemon=True, name="skapi-realtime-reconnect").start()

    def read_loop(self, ws: WebSocket, generation: int) -> None:
        while True:
            try:
                text = ws.recv()
            except (WebSocketClosed, OSError):
                if self.current(generation):
                    self.emit({"type": "error", "message": "Skapi: WebSocket unexpected close."})
                    self.schedule_reconnect(generation)
                elif self.closing and generation == self.generation:
                    self.emit({"type": "close", "message": "WebSocket connection closed."})
                return
            self.pong_deadline = None
            try:
                data = json.loads(text)
            except ValueError:
                continue
            if isinstance(data, dict):
                self.read_frame(data)

    # ---- incoming frames -------------------------------------------------------------------------

    def read_frame(self, data: Dict[str, Any]) -> None:
        if "#pong" in data:
            self.pong_seen = True
            self.pongless_pings = 0
            return
        if isinstance(data.get("#presence"), list):
            rid = data.get("#srid")
            for event in data["#presence"]:
                if not isinstance(event, list) or not event or event[0] not in _PRESENCE:
                    continue
                uid = event[1] if len(event) > 1 else None
                cid = event[2] if len(event) > 2 else None
                for text, code in _PRESENCE[event[0]]:
                    self.notice({"type": "notice", "message": f'User "{uid}" {text}', "sender": uid or None,
                                 "sender_cid": f"cid:{cid}" if cid else None, "sender_rid": rid or None, "code": code})
            return
        if isinstance(data.get("#batch"), list):
            for entry in data["#batch"]:
                if isinstance(entry, dict):
                    self.read_frame(entry)
            return
        kind = None
        for key, name in (("#message", "message"), ("#private", "private"), ("#notice", "notice"), ("#rtc", "rtc"), ("#error", "error"), ("#ice", "ice")):
            if key in data:
                kind = name
                payload = data[key]
                break
        if kind in (None, "rtc", "ice"):
            return
        msg = {"type": kind, "message": payload, "sender": data.get("#user_id") or None,
               "sender_cid": f"cid:{data['#scid']}" if data.get("#scid") else None,
               "sender_rid": data.get("#srid") or None, "code": data.get("#code") or None}
        if kind == "notice":
            self.notice(msg)
        elif kind == "message" and isinstance(data.get("#seq"), (int, float)) and not isinstance(data.get("#seq"), bool) and msg["sender_cid"]:
            self.in_order(msg, int(data["#seq"]))
        else:
            self.deliver(msg)

    def deliver(self, msg: Dict[str, Any]) -> None:
        body = msg.get("message")
        if isinstance(body, dict) and isinstance(body.get("__skapi_batch"), list):
            for item in body["__skapi_batch"]:
                self.emit(dict(msg, message=item))
        else:
            self.emit(msg)

    def notice(self, msg: Dict[str, Any]) -> None:
        if msg.get("code") in ("USER_LEFT", "USER_DISCONNECTED") and msg.get("sender_cid"):
            self.forget_order(msg["sender_cid"])
        wait = self.join_wait
        if (wait and msg.get("code") == "USER_JOINED" and msg.get("sender_rid") == wait["group"]
                and msg.get("sender") == (self.skapi._user or {}).get("user_id")):
            wait["event"].set()
        self.emit(msg)

    # in-order delivery of a sender's numbered group messages (the fan-out can reorder them)
    def in_order(self, msg: Dict[str, Any], seq: int) -> None:
        with self.lock:
            cid = msg["sender_cid"]
            state = self.order.setdefault(cid, {"next": seq, "waiting": {}, "timer": None})
            if seq < state["next"]:
                ready = [msg]
            else:
                state["waiting"][seq] = msg
                ready = self._drain(state)
                if state["waiting"] and state["timer"] is None:
                    state["timer"] = threading.Timer(SEQ_WAIT, self._skip_gap, args=(cid,))
                    state["timer"].daemon = True
                    state["timer"].start()
        for m in ready:
            self.deliver(m)

    def _drain(self, state) -> list:
        out = []
        while state["next"] in state["waiting"]:
            out.append(state["waiting"].pop(state["next"]))
            state["next"] += 1
        return out

    def _skip_gap(self, cid: str) -> None:
        with self.lock:
            state = self.order.get(cid)
            if not state:
                return
            state["timer"] = None
            if state["waiting"]:
                state["next"] = min(state["waiting"])
            ready = self._drain(state)
            if state["waiting"]:
                state["timer"] = threading.Timer(SEQ_WAIT, self._skip_gap, args=(cid,))
                state["timer"].daemon = True
                state["timer"].start()
        for m in ready:
            self.deliver(m)

    def forget_order(self, cid: Optional[str] = None) -> None:
        with self.lock:
            cids = [cid] if cid else list(self.order)
            ready = []
            for c in cids:
                state = self.order.pop(c, None)
                if state:
                    if state["timer"]:
                        state["timer"].cancel()
                    ready += [state["waiting"][k] for k in sorted(state["waiting"])]
        for m in ready:
            self.deliver(m)

    # ---- outgoing group posts: posts within 100 ms travel as one frame, so they arrive in order

    def queue_group_post(self, group: str, content: Any, frame_base: Dict[str, Any]) -> None:
        with self.send_lock:
            if self.window and self.window["group"] != group:
                self._flush_locked()
            if self.window:
                self.window["items"].append(content)
                return
            now = time.time()
            since = now - self.last_send.get(group, 0)
            self.last_send[group] = now
            if since >= SEND_WINDOW:
                self._send_group(frame_base, content)
                return
            timer = threading.Timer(SEND_WINDOW, self.flush)
            timer.daemon = True
            self.window = {"group": group, "items": [content], "base": frame_base, "timer": timer}
            timer.start()

    def flush(self) -> None:
        with self.send_lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        w, self.window = self.window, None
        if not w:
            return
        w["timer"].cancel()
        self.last_send[w["group"]] = time.time()
        items = w["items"]
        while items:
            n = len(items)
            while n > 1 and len(json.dumps({"__skapi_batch": items[:n]}, separators=(",", ":"), ensure_ascii=False).encode("utf-16-le")) // 2 > BATCH_CHARS:
                n = -(-n // 2)
            self._send_group(w["base"], items[0] if n == 1 else {"__skapi_batch": items[:n]})
            items = items[n:]

    def _send_group(self, base: Dict[str, Any], content: Any) -> None:
        with self.lock:
            seq = self.seq
            self.seq += 1
        frame = dict(base, content=content)
        frame["seq"] = seq
        try:
            self.send_raw(frame)
        except (SkapiError, OSError, WebSocketClosed):
            pass  # not open at send time: dropped, as in skapi-js

    def close(self) -> None:
        self.closing = True
        if self.window:
            self.window["timer"].cancel()
            self.window = None
        ws = self.ws
        if self.join_wait:
            self.join_wait["event"].set()
        self.room = None
        if ws is not None:
            ws.close()
        self.forget_order()


class RealtimeMixin:
    """Mixed into Skapi."""

    _rt: Optional[_Realtime] = None

    def connect_realtime(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Opens the realtime connection. callback(event) runs on a background thread for every
        message, notice and connection event. Returns once connected; reconnects on its own.
        """
        if not callable(callback):
            raise SkapiError("Callback must be a function.", "INVALID_REQUEST")
        self._ensure_connection()
        if not self._signed_in():
            raise SkapiError("No access.", "INVALID_REQUEST")
        if self._rt is not None and not self._rt.closing:
            self._rt.callback = callback
            return
        rt = _Realtime(self, callback)
        self._rt = rt
        try:
            rt.open()
        except SkapiError:
            self._rt = None
            rt.emit({"type": "error", "message": "Skapi: WebSocket connection failed."})
            raise

    def close_realtime(self) -> None:
        """Closes the realtime connection; the group hears that you disconnected and left."""
        rt, self._rt = self._rt, None
        if rt is not None:
            rt.close()

    def _live(self) -> _Realtime:
        if self._rt is None or self._rt.closing:
            raise SkapiError("No realtime connection. Execute connect_realtime() before this method.", "INVALID_REQUEST")
        return self._rt

    def join_realtime(self, group: Any) -> Dict[str, str]:
        """Joins a message group (one at a time), or leaves the current one with None."""
        rt = self._live()
        if isinstance(group, dict):
            group = group.get("group")
        group = group or None
        if not group and not rt.room:
            return {"type": "success", "message": "Left realtime message group."}
        if group is not None and not isinstance(group, str):
            raise _p('"group" must be a string | None.')
        token = self._access_token()
        if rt.join_wait:
            rt.join_wait["event"].set()
        if rt.ws is not None and not rt.ws.closed:
            rt.send_raw({"action": "joinRoom", "rid": group, "token": token, "ver": 2})
            if group:
                rt.join_wait = {"group": group, "event": threading.Event(), "until": time.time() + JOIN_WAIT}
        rt.room = group
        return {"type": "success", "message": f'Joined realtime message group: "{group}".' if group else "Left realtime message group."}

    def post_realtime(self, message: Any, recipient: str, notification: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Sends to a user (by user ID) or to the group you joined. notification: {title, body, config?: {always}}."""
        rt = self._live()
        if not recipient:
            raise SkapiError("No recipient.", "INVALID_REQUEST")
        self._fresh_id_token()
        notification_str, config = "", {}
        if notification is not None:
            if not isinstance(notification, dict):
                raise _p('"notification" should be an object with "title" and "body".')
            for key in ("title", "body"):
                if key not in notification:
                    raise _p(f'Key "{key}" is required.')
                if not isinstance(notification[key], str):
                    raise _p(f'"{key}" should be type: <string>.')
            config = notification.get("config") or {}
            if not isinstance(config, dict) or ("always" in config and not isinstance(config["always"], bool)):
                raise _p('"config.always" should be type: <boolean>.')
            notification_str = json.dumps({"title": notification["title"], "body": notification["body"]}, separators=(",", ":"), ensure_ascii=False)
            if len(notification_str.encode("utf-8")) > MAX_NOTIFICATION_BYTES:
                raise _p("Notification size exceeds 3kb.")
        if rt.ws is None or rt.ws.closed:
            raise SkapiError("Realtime connection is not open. Try reconnecting with connect_realtime().", "INVALID_REQUEST")
        token = f"IdT:{self.service}:{self.owner}:{self._session.id_token.jwt_token}"

        def checked(frame):
            size = len(json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            if size > MAX_FRAME_BYTES:
                raise _p(f"Message is {size} bytes; a realtime message can be at most {MAX_FRAME_BYTES} bytes including its headers.")
            return frame

        if isinstance(recipient, str) and _UUID.match(recipient):
            rt.send_raw(checked({"action": "sendMessage", "uid": recipient, "content": message, "notification": notification_str,
                                 "notificationConfig": config, "token": token}))
            return {"type": "success", "message": "Message sent."}

        if recipient != rt.room:
            raise SkapiError(f'User has not joined to the recipient group. Run join_realtime("{recipient}")', "INVALID_REQUEST")
        checked({"action": "broadcast", "rid": recipient, "content": message, "notification": notification_str,
                 "notificationConfig": config, "token": token, "#seq": 0})
        wait = rt.join_wait
        if wait and wait["group"] == recipient:
            # until the server announces your own join, the group would not get the message yet
            wait["event"].wait(max(0.0, wait["until"] - time.time()))
            if rt.join_wait is wait:
                rt.join_wait = None
        base = {"action": "broadcast", "rid": recipient, "notification": notification_str, "notificationConfig": config, "token": token}
        if notification is not None:
            rt._send_group(base, message)  # a post with a notification is never grouped
        else:
            rt.queue_group_post(recipient, message, base)
        return {"type": "success", "message": "Message sent."}

    def get_realtime_users(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """Who is connected in a group (default: the group you joined): [{user_id, cid}]."""
        params = dict(params or {})
        body: Dict[str, Any] = {}
        if "group" in params:
            if not isinstance(params["group"], str):
                raise _p(f'{json.dumps(params["group"], default=repr)} is invalid in "group". allowed type or value is: Type<string>.')
            body["group"] = params["group"]
        else:
            room = self._rt.room if self._rt else None
            if not room:
                raise _p('No group has been joined. Otherwise "group" is required.')
            body["group"] = room
        if "user_id" in params:
            body["user_id"] = _user_id(params["user_id"], 'User ID in "user_id"')
        res = self._call("get-ws-group", body, auth=True, fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [{"user_id": str(i.get("uid", "")).split("#")[1] if "#" in str(i.get("uid", "")) else i.get("uid"),
                            "cid": f"cid:{i.get('cid')}"} for i in res["list"]]
        return res

    def get_realtime_groups(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """Groups that have members now: [{group, number_of_users}]."""
        self._ensure_connection()
        if not params:
            params = {"searchFor": "group", "value": " ", "condition": ">"}
        params = dict(params)
        search_for = params.get("searchFor", "group")
        if search_for not in ("group", "number_of_users"):
            raise _p(f'{json.dumps(search_for, default=repr)} is invalid in "searchFor". allowed types or values are: "group", "number_of_users".')
        value = params.get("value", 0 if search_for == "number_of_users" else " ")
        conditions = [">", ">=", "=", "<", "<=", "!=", "gt", "gte", "eq", "lt", "lte", "ne"]
        condition = params.get("condition")
        if condition is not None and condition not in conditions:
            raise _p(f'{json.dumps(condition, default=repr)} is invalid in "condition". allowed types or values are: ' + ", ".join(json.dumps(c) for c in conditions) + ".")
        if condition is None:
            condition = ">" if value == " " or not value else "="
        body: Dict[str, Any] = {"searchFor": search_for, "value": value}
        if "range" in params and params["range"] is not None:
            body["range"] = params["range"]
            condition = None
        if search_for == "number_of_users" and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise _p('"value" must be a number.')
        if search_for == "group" and not isinstance(value, str):
            raise _p('"value" must be a string.')
        if "range" in body and type(body["range"]) is not type(value):
            raise _p(f'"range" must be a {"number" if isinstance(value, (int, float)) else "string"}.')
        if condition:
            body["condition"] = condition
        res = self._call("get-ws-group", body, auth=True, fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [{"group": str(i.get("rid", "")).split("#")[1] if "#" in str(i.get("rid", "")) else i.get("rid"),
                            "number_of_users": i.get("cnt")} for i in res["list"]]
        return res
