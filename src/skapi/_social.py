"""
User-side newsletters, subscriptions between users, the feed, and ticket listings, ported from
skapi-js (src/methods/subscription.ts, src/methods/user.ts).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Optional

from ._database import from_base62, user_id as _user_id
from ._user import _url, validate_email
from .errors import SkapiError

_RESERVED_GROUPS = {"tp", "admin", "public", "authorized", "newsletter", "forward", "all", "true", "false", "null"}

_TICKET_KEYS = {
    "tkid": "ticket_id", "cond": "condition", "stmp": "timestamp", "upd": "updated", "acts": "actions", "actn": "action",
    "cnt": "count", "ttl": "time_to_live", "plch": "placeholder", "hash": "hash", "desc": "description", "pmc": "limit_per_user",
    "fail": "failed", "rv": "rules_version", "on": "enabled", "qn": "queued", "qdue": "queued_due", "cc": "concurrency",
    "cf": "when_full", "cn": "running", "ln": "waiting", "sc": "self_calling",
}


def _jd(v):
    """A value as it appears in an error message; never fails on odd types."""
    return json.dumps(v, default=repr, ensure_ascii=False)


def _p(message: str, code: str = "INVALID_PARAMETER") -> SkapiError:
    return SkapiError(message, code)


def newsletter_group(group: Any, allow_null: bool = False):
    """'public' -> 0, 'authorized' -> 1, an integer 0..99, or a newsletter group name."""
    if group is None:
        if allow_null:
            return None
        raise _p('"group" is required.')
    if group == "public":
        return 0
    if group == "authorized":
        return 1
    if isinstance(group, (int, float)) and not isinstance(group, bool):
        if group != int(group) or not 0 <= group <= 99:
            raise _p('"group" should be an integer between 0 and 99.')
        return int(group)
    if (isinstance(group, str) and re.match(r"^[a-z0-9]{2,20}$", group) and re.search(r"[a-z]", group)
            and not re.match(r"^[0-9]+e[0-9]+$", group) and group not in _RESERVED_GROUPS):
        return group
    raise _p("Newsletter group name must be 2-20 lowercase alphanumeric characters, contain a letter, and not be a reserved name.")


def map_ticket(t: Dict[str, Any]) -> Dict[str, Any]:
    """A ticket row as skapi-js returns it (short server keys renamed, consume ids split)."""
    out: Dict[str, Any] = {}
    for k, v in t.items():
        if k == "tkid" and isinstance(v, str):
            parts = v.split("#")
            if len(parts) == 1:
                out["ticket_id"] = parts[0]
            else:
                out["ticket_id"] = parts[1]
                consume_id = parts[2] if len(parts) > 2 else ""
                out["consume_id"] = consume_id
                out["user_id"] = "#".join(parts[3:])
                out["is_test"] = consume_id[-4:] == ":CHK"
                if not t.get("stmp"):
                    ts = consume_id[:-4]
                    out["timestamp"] = int(ts) if re.match(r"^[0-9]+$", ts) else from_base62(ts)
        elif k in _TICKET_KEYS:
            out[_TICKET_KEYS[k]] = v
        else:
            out[k] = v
    return out


def _subscription_row(s: Dict[str, Any]) -> Dict[str, Any]:
    sub = s.get("sub")
    grp = s.get("grp") or ""
    parts = sub.split("#") if isinstance(sub, str) else []
    row = {
        "subscriber": parts[2] if len(parts) > 2 else s.get("subscriber"),
        "subscription": parts[0] if parts else s.get("subscription"),
        "timestamp": s.get("timestamp") or s.get("stmp"),
        "blocked": bool(s.get("blocked")) or grp[:1] == "N",
    }
    if isinstance(s.get("opt"), dict):
        row.update(s["opt"])
    return row


class SocialMixin:
    """Mixed into Skapi."""

    def _target(self, params: Any) -> str:
        if not isinstance(params, dict) or "user_id" not in params:
            raise _p('Key "user_id" is required.')
        return self._not_self(params["user_id"])

    def _not_self(self, uid: Any, field: str = '"user_id"') -> str:
        if self._user and uid == self._user.get("user_id"):
            raise _p('"user_id" cannot be the user\'s own ID.')
        return _user_id(uid, field)

    # ---- newsletters ------------------------------------------------------------------------------

    def subscribe_newsletter(self, params: Dict[str, Any]) -> str:
        """
        Subscribes to the project's newsletters of one group. Signed in: the user's verified e-mail.
        Signed out: params["email"], which gets a confirmation e-mail first.
        """
        self._ensure_connection()
        self._refuse_anonymous("subscribe to newsletters")
        params = dict(params or {})
        signed_in = self._signed_in()
        if "group" not in params:
            raise _p('Key "group" is required.')
        if not signed_in and "email" not in params:
            raise _p('Key "email" is required.')
        body: Dict[str, Any] = {}
        if "email" in params:
            e = params["email"]
            if isinstance(e, list) and e:
                body["email"] = validate_email(e[0]) if len(e) == 1 else [validate_email(x) for x in e]
            else:
                body["email"] = validate_email(e) if not isinstance(e, list) else validate_email("")
        body["group"] = newsletter_group(params["group"])
        if "redirect" in params:
            body["redirect"] = _url(params["redirect"])
        path = "subscribe-newsletter" if signed_in else "subscribe-public-newsletter"
        return self._call(path, body, auth=signed_in)

    def unsubscribe_newsletter(self, group: Any) -> str:
        """Unsubscribes the signed-in user from one group, or from every group with group=None."""
        self._ensure_connection()
        self._refuse_anonymous("subscribe to newsletters")
        return self._call("subscribe-newsletter", {"action": "unsubscribe", "group": newsletter_group(group, allow_null=True)}, auth=True)

    def get_newsletters(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """Newsletters sent to a group, newest first by default. Each has a url to its content."""
        self._ensure_connection()
        is_admin = self._is_admin()
        fetch_options = dict(fetch_options or {})
        if params is None:
            fetch_options = dict({"ascending": False}, **fetch_options)
            params = {"searchFor": "timestamp", "value": int(time.time() * 1000), "condition": "<", "group": "public"}
        params = dict(params)
        for key in ("searchFor", "value", "group"):
            if key not in params:
                raise _p(f'Key "{key}" is required.')
        fields = ["message_id", "timestamp", "subject", "complaint", "read", "bounced"]
        search_for = params["searchFor"]
        if search_for not in fields:
            raise _p(f'{_jd(search_for)} is invalid in "searchFor". allowed types or values are: ' + ", ".join(_jd(f) for f in fields) + ".")
        value = params["value"]
        wants_str = search_for in ("message_id", "subject")
        if (wants_str and not isinstance(value, str)) or (not wants_str and (isinstance(value, bool) or not isinstance(value, (int, float)))):
            raise _p(f'"value" type does not match the type of "{search_for}" index.')
        if value == "":
            raise _p('"value" should not be empty string.')
        body: Dict[str, Any] = {"searchFor": search_for, "value": value}
        if "range" in params:
            r = params["range"]
            if type(r) is not type(value) and not (isinstance(r, (int, float)) and isinstance(value, (int, float)) and not isinstance(r, bool)):
                raise _p('"range" should match type of "value".')
            body["range"] = r
        conditions = [">", ">=", "=", "<", "<=", "gt", "gte", "eq", "lt", "lte"]
        body["condition"] = params.get("condition") if params.get("condition") in conditions else "="
        raw_group = params["group"]
        group = newsletter_group(raw_group)
        if isinstance(group, int) and group >= 1:
            if not self._signed_in():
                raise _p("User should be logged in.")
            if not is_admin and group > int(self._user.get("access_group") or 0):
                raise _p("User has no access.")
        body["group"] = group
        signed_in = self._signed_in()
        if group == 0 or (isinstance(group, str) and not signed_in):
            res = self._call("get-public-newsletters", body, auth=signed_in, method="GET", fetch_options=fetch_options)
        else:
            res = self._call("get-newsletters", body, auth=True, method="GET", fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            out = []
            defaults = {"message_id": "", "timestamp": 0, "complaint": 0, "read": 0, "subject": "", "bounced": "", "url": "",
                        "delivered": 0, "group": group, "dry": False, "sent": 0}
            source = {"message_id": "mid", "timestamp": "stmp", "complaint": "cmpl", "read": "read", "subject": "subj", "bounced": "bnce",
                      "url": "url", "delivered": "delv", "group": "grp", "dry": "dry", "sent": "sent"}
            for row in res["list"]:
                item = {k: (row.get(src) or defaults[k]) for k, src in source.items()}
                item["bounced"] = str(item["bounced"])
                item["dry"] = bool(item["dry"])
                if not item["sent"]:
                    del item["sent"]
                out.append(item)
            res["list"] = out
        return res

    def get_newsletter_subscription(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> list:
        """The signed-in user's newsletter subscriptions: [{timestamp, group, subscribed_email, active}]."""
        self._ensure_connection()
        self._refuse_anonymous("subscribe to newsletters")
        params = dict(params or {})
        body: Dict[str, Any] = {}
        if "user_id" in params:
            if params["user_id"] != (self._user or {}).get("user_id") and not self._is_admin():
                raise _p("No access.")
            body["user_id"] = params["user_id"]
        if "group" in params:
            body["group"] = newsletter_group(params["group"], allow_null=True)
        data = self._call("get-newsletter-subscription", body, auth=True, fetch_options=fetch_options)
        rows = data.get("list") if isinstance(data, dict) and "list" in data else data
        out = []
        for r in rows if isinstance(rows, list) else []:
            parts = str(r.get("subt", "")).split("#")
            token = parts[0]
            active = not token.startswith("@")
            token = token.lstrip("@")
            item = {"timestamp": r.get("stmp"), "group": int(token) if re.match(r"^\d+$", token) else token,
                    "subscribed_email": parts[1] if len(parts) > 1 else "", "active": active}
            if isinstance(r.get("email_token"), str) and r["email_token"]:
                item["subscriber_token"] = r["email_token"]
            out.append(item)
        if isinstance(data, dict) and "list" in data:
            data["list"] = out
            return data
        return out

    # ---- subscriptions between users -------------------------------------------------------------

    def subscribe(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Subscribes the signed-in user to another user: {"user_id", "get_feed"?, "get_notified"?, "get_email"?}."""
        self._require_session()
        params = dict(params or {})
        if "user_id" not in params:
            raise _p('Key "user_id" is required.')
        target = self._not_self(params["user_id"])
        option: Dict[str, bool] = {}
        for k in ("get_feed", "get_notified"):
            if k in params:
                if not isinstance(params[k], bool):
                    raise _p(f'{_jd(params[k])} is invalid in "{k}". allowed type or value is: Type<boolean>.')
                option[k] = params[k]
        if "get_email" in params:
            if params["get_email"] and not (self._user.get("email") and self._user.get("email_verified")):
                raise _p("User has no verified email address.")
            option["get_email"] = bool(params["get_email"])
        s = self._call("subscription", {"subscribe": target, "option": option}, auth=True)
        if not isinstance(s, dict):
            raise SkapiError("The subscription is blocked.", "INVALID_REQUEST")
        return _subscription_row(s)

    def unsubscribe(self, params: Dict[str, Any]) -> str:
        self._require_session()
        return self._call("subscription", {"unsubscribe": self._target(params)}, auth=True)

    def block_subscriber(self, params: Dict[str, Any]) -> str:
        """Stops a user from subscribing to the signed-in user (and from getting their feed)."""
        self._require_session()
        return self._call("subscription", {"block": self._target(params)}, auth=True)

    def unblock_subscriber(self, params: Dict[str, Any]) -> str:
        self._require_session()
        return self._call("subscription", {"unblock": self._target(params)}, auth=True)

    def get_subscriptions(self, params: Dict[str, Any], fetch_options: Optional[dict] = None) -> dict:
        """Who a user subscribes to (subscriber=...) or who subscribes to a user (subscription=...)."""
        self._require_session()
        params = dict(params or {})
        body: Dict[str, Any] = {}
        if "subscriber" in params:
            body["subscriber"] = _user_id(params["subscriber"], 'User ID in "subscriber"')
        if "subscription" in params:
            # any user, yourself included: your own id lists your own subscribers
            body["subscription"] = _user_id(params["subscription"], 'User ID in "subscription"')
        if "blocked" in params:
            if not isinstance(params["blocked"], bool):
                raise _p(f'{_jd(params["blocked"])} is invalid in "blocked". allowed type or value is: Type<boolean>.')
            body["blocked"] = params["blocked"]
        if not body.get("subscriber") and not body.get("subscription"):
            raise _p('At least either "subscriber" or "subscription" should have a value.')
        res = self._call("get-subscription", body, auth=True, fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [_subscription_row(r) for r in res["list"]]
        return res

    def get_feed(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """Records the users you subscribe to (with get_feed on) posted to their feed, newest first."""
        self._require_session()
        params = dict(params or {})
        body: Dict[str, Any] = {}
        if "access_group" in params:
            v = params["access_group"]
            g = 1 if v == "authorized" else 0 if v == "public" else v
            if isinstance(g, bool) or not isinstance(g, (int, float)):
                raise _p('"access_group" should be type number.')
            if g < 0:
                raise _p('"access_group" should be zero or a positive number.')
            if g > int(self._user.get("access_group") or 0):
                raise _p("User has no access.")
            body["access_group"] = g
        res = self._call("get-feed", body, auth=True, fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [self._normalize_record(r) for r in res["list"]]
        return res

    # ---- tickets ------------------------------------------------------------------------------------

    def get_tickets(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """The project's tickets (or one, with {"ticket_id": ...}) as a signed-in user sees them."""
        res = self._call("ticket", dict({"exec": "list"}, **(params or {})), auth=True, fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [map_ticket(r) for r in res["list"]]
        return res

    def get_consumed_tickets(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """The signed-in user's own ticket calls (each with ticket_id, consume_id and timestamp)."""
        res = self._call("ticket", dict({"exec": "consumed"}, **(params or {})), auth=True, fetch_options=fetch_options)
        if isinstance(res, dict) and isinstance(res.get("list"), list):
            res["list"] = [map_ticket(r) for r in res["list"]]
        return res
