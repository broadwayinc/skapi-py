"""The Skapi class: one project, its connection, and the signed-in user's session."""

from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable, Dict, Optional

from . import __version__
from ._cognito import CognitoError, UserPool, make_storage
from ._database import DatabaseMixin
from ._forward import ForwardMixin
from ._social import SocialMixin
from ._realtime import RealtimeMixin
from ._request_status import RequestStatusMixin
from ._encryption import EncryptionMixin, EncState, parse_option as parse_encryption_option, _lib as ensure_crypto_available
from ._http import Requester
from ._project import decode_project_id, format_project_id, is_project_id
from ._user import UserMixin, parse_user_attributes
from .errors import SkapiError

TOKEN_REFRESH_SKEW_SECONDS = 60 * 60  # refresh the ID token when it has less than an hour left
# How long a request waits for a token refresh (skapi-js 2.7.0). Past this the waiting request fails
# with TIMEOUT, the user stays signed in, and the next request starts a new refresh. The refresh
# that ran late is still adopted if it finishes, unless a refresh that started after it was already
# adopted or was asked for new claims (then its older tokens are dropped).
TOKEN_REFRESH_TIME_LIMIT_SECONDS = 15


class _RefreshFlight:
    """One token refresh in progress, shared by every thread that needs it."""

    def __init__(self, seq: int):
        self.seq = seq  # refreshes are numbered in the order they start
        self.done = threading.Event()
        self.error: Optional[BaseException] = None


class Skapi(EncryptionMixin, DatabaseMixin, UserMixin, SocialMixin, ForwardMixin, RealtimeMixin, RequestStatusMixin):
    """
    Skapi("<Project ID>")    the Project ID from your project's Settings page on skapi.com

    storage: where the signed-in session is kept between runs. None (default) keeps it in memory for
             this object only; a file path keeps it in that JSON file (created with mode 600); or any
             object with get_item(key), set_item(key, value) and remove_item(key).
    timeout: seconds a request may go with nothing sent or received before it fails with TIMEOUT
             (default 120). An upload may then wait 5 x timeout for its answer.
    encryption: True (or options) seals the data of private records in this client before upload.
             Needs the "cryptography" package: pip install "skapi[encryption]".
    """

    def __init__(self, project_id: str, *, storage: Any = None, timeout: float = 120, target_cdn: Optional[str] = None,
                 encryption: Any = None):
        if not isinstance(project_id, str) or not project_id.strip():
            raise SkapiError("Project ID is required.", "INVALID_PARAMETER")
        if not is_project_id(project_id.strip()):
            raise SkapiError("Project ID is invalid.", "INVALID_PARAMETER")
        service, owner = decode_project_id(project_id)
        self.service: str = service
        self.owner: str = owner
        try:
            self.project_id: str = format_project_id(service, owner)
        except (ValueError, IndexError):
            self.project_id = ""
        self.version: str = __version__
        self.connection: Optional[Dict[str, Any]] = None

        self._requester = Requester(service, owner, __version__, target_cdn=target_cdn, timeout=timeout)
        self._storage = make_storage(storage)
        self._pool: Optional[UserPool] = None
        self._session = None
        self._cognito_username: Optional[str] = None
        self._user: Optional[Dict[str, Any]] = None
        self._restored = False
        self._lock = threading.RLock()
        self._refresh_lock = threading.RLock()  # one token refresh at a time, shared by every thread
        # Counts sign-outs: _clear_session adds one. A token refresh that started before a sign-out
        # compares it before adopting its tokens, so a refresh still running when the user logged out
        # cannot sign them back in (as skapi-js sessionEpoch).
        self._sign_outs = 0
        self._session_lock = threading.RLock()  # makes "not signed out since" + adopting one step
        self._restore_refreshed_token: Optional[str] = None  # the id token _restore just refreshed to
        self._refresh_flight: Optional[_RefreshFlight] = None  # the shared token refresh in progress
        self._refresh_seq = 0  # the number of the last token refresh started
        # A refresh numbered below this is not adopted: one numbered higher was already adopted, or
        # was started for new claims (update_profile, ...), so the older one's tokens may be stale.
        self._adopt_floor = 0
        self._rt_connect_lock = threading.RLock()  # one connect_realtime at a time (see _realtime.py)
        self._status_push_state = None  # request status push (_request_status.StatusPush), made on first use
        enc_cfg = parse_encryption_option(encryption)
        if enc_cfg:
            ensure_crypto_available()  # fails here, with the install hint, when "cryptography" is missing
        self._enc = EncState(enc_cfg) if enc_cfg else None

        # per-instance state, as in skapi-js
        self._private_access_key: Dict[str, str] = {}
        self._my_unique_ids: Dict[str, Dict[str, str]] = {}
        self._handed_out_file_urls: Dict[str, str] = {}  # get_file url given out -> the stored file url
        self._pending_mfa = None
        self._request_signup_confirmation: Optional[str] = None
        self._disabled_account: Optional[str] = None
        self._anonymous_timer: Optional[threading.Timer] = None

    def __repr__(self) -> str:
        return f"Skapi(project_id={self.project_id!r})"

    # ---- connection -----------------------------------------------------------------------------

    def _ensure_connection(self, refresh: bool = False) -> Dict[str, Any]:
        with self._lock:
            if self.connection is None or refresh:
                self.connection = self._requester.request("service", {"service": self.service, "owner": self.owner, "refresh": refresh}, method="GET")
            return self.connection

    def get_connection_info(self, refresh: bool = False) -> Dict[str, Any]:
        """The project's name and settings, and the caller's IP and location as the server sees them."""
        conn = self._ensure_connection(refresh)
        info = {
            "project_id": self.project_id,
            "user_ip": conn.get("ip"),
            "user_agent": conn.get("user_agent"),
            "user_location": conn.get("locale"),
            "service_name": conn.get("service_name"),
            "version": self.version,
            "ai_agent": conn.get("ai_agent"),
            "conf": conn.get("opt"),
        }
        # Only with encryption on and a signed-in user: the encryption recovery code on the first
        # call after it was created, then only a message (see _encryption_recovery_info).
        recovery = self._encryption_recovery_info()
        if recovery is not None:
            info["encryption_recovery"] = recovery
        return info

    # ---- session --------------------------------------------------------------------------------

    def _user_pool(self) -> UserPool:
        if self._pool is None:
            admin, _ = self._requester.endpoints()
            self._pool = UserPool(admin["userpool_id"], admin["userpool_client"], self._storage)
        return self._pool

    def _restore(self) -> None:
        """Once: sign back in from storage (refreshing the tokens when they expired)."""
        with self._lock:
            if self._restored:
                return
            self._restored = True
            pool = self._user_pool()
            username = pool.last_auth_user()
            if not username:
                return
            session = pool.cached_session(username)
            if session is None:
                return
            try:
                if not session.is_valid():
                    if not session.refresh_token:
                        return
                    try:
                        session = pool.refresh(username, session.refresh_token)
                        # get_profile(refresh_token=True) right after this has nothing left to ask for
                        self._restore_refreshed_token = session.id_token.jwt_token
                    except CognitoError as err:
                        if err.code != "NetworkError":
                            raise
                        # The server never answered: that says nothing about the session, which is kept
                        # with its stored tokens. The next signed-in call refreshes again (NETWORK_ERROR
                        # while there is no network), as for a session that expires while running.
                self._adopt_session(username, session)
                if self._user.get("anonymous"):
                    # a temporary account restored from storage: check it still exists, and keep it alive
                    self._start_anonymous_keep_alive(beat_now=True)
            except CognitoError as err:
                if err.code != "NetworkError":
                    self._clear_session(local_only=True)
            except SkapiError:
                pass

    def _adopt_session(self, username: str, session) -> Dict[str, Any]:
        claims = session.id_token.payload
        if claims.get("custom:service") != self.service:
            self._clear_session(local_only=True)
            raise SkapiError("Invalid session.", "INVALID_REQUEST")
        previous = self._cognito_username
        if previous and previous != username:
            # a new sign-in as someone else: nothing the previous user was handed carries over
            self._private_access_key.clear()
            self._my_unique_ids.clear()
            if self._pool:
                # the previous user's tokens leave the storage
                self._stop_anonymous_keep_alive()
                for key in ("idToken", "accessToken", "refreshToken", "clockDrift", "userData"):
                    self._pool.storage.remove_item(f"{self._pool.key_prefix}.{previous}.{key}")
        self._session = session
        self._cognito_username = username
        self._user = parse_user_attributes(claims)
        return self._user

    def _clear_session(self, local_only: bool = True) -> None:
        if getattr(self, "_rt", None) is not None:
            self.close_realtime()  # a signed-in connection does not outlive the session
        self._stop_anonymous_keep_alive()
        self._enc_clear()
        self._pending_mfa = None
        if self._cognito_username and self._pool:
            self._pool.clear_cached_tokens(self._cognito_username)
        with self._session_lock:
            self._session = None
            self._cognito_username = None
            self._user = None
            self._sign_outs += 1  # a refresh still running from before this point is not adopted
            self._restore_refreshed_token = None
        with self._refresh_lock:
            # nor shared: the next sign-in starts its own refresh instead of joining one that ends
            # in "User login is required."
            self._refresh_flight = None
        self._private_access_key.clear()
        self._my_unique_ids.clear()
        self._requester._start_key_history.clear()

    def _signed_in(self) -> bool:
        self._restore()
        return bool(self._user and self._session)

    def _refresh_session(self, new_claims: bool = False) -> None:
        """
        Forced token refresh. A network failure keeps the session; any other refusal ends it.
        Threads that need a refresh at the same time share one, and each waits for it at most
        TOKEN_REFRESH_TIME_LIMIT_SECONDS (TIMEOUT past it, still signed in).

        new_claims: the caller just changed the user (update_profile, verify_email, ...) and needs
        tokens issued after this call. It joins only a refresh that started after it asked; one
        that started earlier could carry the old claims, so it is waited out (within the time
        limit) and a new refresh is started.
        """
        with self._refresh_lock:
            if not self._session:
                raise SkapiError("User login is required.", "INVALID_REQUEST")
            mark = self._refresh_seq  # a refresh numbered above this started after this call
            earlier = self._refresh_flight if new_claims else None
        if earlier is not None:
            try:
                self._wait_refresh(earlier)
            except SkapiError as err:
                if err.code == "TIMEOUT":
                    raise
                # its own failure is not this caller's answer: the new refresh below gives that
        with self._refresh_lock:
            if not self._session:
                raise SkapiError("User login is required.", "INVALID_REQUEST")
            flight = self._refresh_flight
            if flight is None or (new_claims and flight.seq <= mark):
                self._refresh_seq += 1
                flight = _RefreshFlight(self._refresh_seq)
                self._refresh_flight = flight
                if new_claims:
                    # a refresh still running from before this one would bring back the old claims
                    self._adopt_floor = max(self._adopt_floor, flight.seq)
                args = (flight, self._sign_outs, self._cognito_username, self._session.refresh_token)
                threading.Thread(target=self._run_refresh, args=args, daemon=True, name="skapi-token-refresh").start()
        self._wait_refresh(flight)

    def _wait_refresh(self, flight: "_RefreshFlight") -> None:
        """Waits for a refresh at most TOKEN_REFRESH_TIME_LIMIT_SECONDS; raises its error, or TIMEOUT."""
        if not flight.done.wait(TOKEN_REFRESH_TIME_LIMIT_SECONDS):
            with self._refresh_lock:
                # stops sharing the stalled refresh, so the next request tries again
                if self._refresh_flight is flight:
                    self._refresh_flight = None
            raise SkapiError(f"The sign-in token refresh did not answer within {TOKEN_REFRESH_TIME_LIMIT_SECONDS} seconds.", "TIMEOUT")
        if flight.error is not None:
            raise flight.error

    def _run_refresh(self, flight: "_RefreshFlight", epoch: int, username: Optional[str], refresh_token: Optional[str]) -> None:
        try:
            pool = self._user_pool()
            try:
                session = pool.refresh(username, refresh_token)
            except CognitoError as err:
                if self._sign_outs != epoch:
                    self._signed_out_meanwhile(pool, username)
                if err.code == "NetworkError":
                    raise SkapiError(err.message or "Network error", "NETWORK_ERROR", err) from None
                if self._cognito_username == username:
                    self._clear_session()
                raise SkapiError("User login is required.", "INVALID_REQUEST", err) from None
            with self._session_lock:
                if self._sign_outs != epoch:
                    self._signed_out_meanwhile(pool, username)
                with self._refresh_lock:
                    stale = flight.seq < self._adopt_floor
                    if not stale:
                        self._adopt_floor = flight.seq
                if stale:
                    # a newer refresh was adopted or asked for new claims meanwhile: these tokens are
                    # older than that, so the current session stays, also in storage
                    if self._session and self._cognito_username:
                        pool.cache_tokens(self._cognito_username, self._session)
                    return
                self._adopt_session(username, session)
        except BaseException as err:  # handed to the waiting threads
            flight.error = err
        finally:
            with self._refresh_lock:
                if self._refresh_flight is flight:
                    self._refresh_flight = None
            flight.done.set()

    def _signed_out_meanwhile(self, pool, username) -> None:
        """
        logout() ran while a token refresh waited on the server. The refresh is not adopted, and the
        tokens it wrote back to storage are removed again; a sign-in made after the logout keeps its
        own tokens. Raises, as for any call made without a session.
        """
        pool.clear_cached_tokens(username)
        if self._session and self._cognito_username:
            pool.cache_tokens(self._cognito_username, self._session)
        raise SkapiError("User login is required.", "INVALID_REQUEST")

    def _fresh_id_token(self) -> str:
        self._restore()
        if not self._session:
            self._clear_session()
            raise SkapiError("User login is required.", "INVALID_REQUEST")
        session = self._session
        if (session.id_token.expiration or 0) < time.time() + TOKEN_REFRESH_SKEW_SECONDS:
            # joins a refresh another thread already started; waits at most the refresh time limit
            self._refresh_session()
            session = self._session
            if not session:
                raise SkapiError("User login is required.", "INVALID_REQUEST")
        return session.id_token.jwt_token

    def _access_token(self) -> str:
        self._fresh_id_token()
        return self._session.access_token.jwt_token

    def _call(self, path: str, data: Any = None, *, auth: bool = False, method: str = "POST",
              fetch_options: Optional[dict] = None, ignore_service: bool = False,
              keep_paging: Optional[Callable[[], bool]] = None) -> Any:
        self._ensure_connection()
        token = self._fresh_id_token() if auth else None
        return self._requester.request(path, data, auth=auth, method=method, token=token,
                                       fetch_options=fetch_options, ignore_service=ignore_service,
                                       keep_paging=keep_paging)

    @property
    def user(self) -> Optional[Dict[str, Any]]:
        """The signed-in user's profile (a copy), or None."""
        self._restore()
        return copy.deepcopy(self._user) if self._user else None

    @property
    def session(self):
        """The signed-in session's tokens: .id_token.jwt_token, .access_token.jwt_token, .refresh_token."""
        self._restore()
        return self._session
