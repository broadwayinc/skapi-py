"""
The Cognito user pool client skapi-py signs in with, ported from skapi-js (src/cognito/index.ts).

Same requests, error codes and messages, retry timing and storage keys
(CognitoIdentityServiceProvider.<clientId>.LastAuthUser and .<username>.idToken / accessToken /
refreshToken / clockDrift). Sign-in is SRP only: the password never leaves the machine. No device
tracking (off on every Skapi user pool) and no text messages of any kind.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .errors import network_error_message
from ._srp import SrpHelper, cognito_timestamp, hex_to_int

REQUEST_TIMEOUT = 60  # seconds per call to the user pool API


class CognitoError(Exception):
    """An error answered by the user pool API, or a network failure (code 'NetworkError')."""

    def __init__(self, message: Optional[str], code: str, status: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.name = code
        self.status = status


# ---- storage ------------------------------------------------------------------------------------

class MemoryStorage:
    """Kept for the life of the Skapi object only."""

    def __init__(self):
        self._data: Dict[str, str] = {}

    def get_item(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def set_item(self, key: str, value: str) -> None:
        self._data[key] = value

    def remove_item(self, key: str) -> None:
        self._data.pop(key, None)


class FileStorage:
    """
    One JSON file, so a script that runs again stays signed in. The file holds tokens: keep it out
    of version control and readable by you only (it is created with mode 600).
    """

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        self._lock = threading.Lock()

    def _read(self) -> Dict[str, str]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (FileNotFoundError, ValueError):
            return {}

    def _write(self, data: Dict[str, str]) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".skapi-", suffix=".tmp")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def get_item(self, key: str) -> Optional[str]:
        return self._read().get(key)

    def set_item(self, key: str, value: str) -> None:
        with self._lock:
            data = self._read()
            data[key] = value
            self._write(data)

    def remove_item(self, key: str) -> None:
        with self._lock:
            data = self._read()
            if key in data:
                del data[key]
                self._write(data)


def make_storage(storage: Any):
    """None: memory. A str or os.PathLike: a JSON file. Anything else: an object with get_item/set_item/remove_item."""
    if storage is None:
        return MemoryStorage()
    if isinstance(storage, (str, os.PathLike)):
        return FileStorage(os.fspath(storage))
    for name in ("get_item", "set_item", "remove_item"):
        if not callable(getattr(storage, name, None)):
            raise TypeError("storage needs get_item(key), set_item(key, value) and remove_item(key).")
    return storage


# ---- tokens and session -------------------------------------------------------------------------

def _b64_any(text: str) -> bytes:
    """Base64 in the standard or URL-safe alphabet, padding optional, like Node's Buffer.from(text, 'base64')."""
    text = text.split("=")[0].replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text, validate=False)


class JwtToken:
    def __init__(self, token: Optional[str] = None):
        self.jwt_token: str = token or ""
        self.payload: Dict[str, Any] = self._decode_payload()

    def _decode_payload(self) -> Dict[str, Any]:
        try:
            return json.loads(_b64_any(self.jwt_token.split(".")[1]).decode("utf-8"))
        except Exception:
            return {}

    @property
    def expiration(self) -> int:
        return self.payload.get("exp")

    @property
    def issued_at(self) -> int:
        return self.payload.get("iat")


class Session:
    def __init__(self, id_token: str, access_token: str, refresh_token: Optional[str], clock_drift: Optional[int] = None):
        self.id_token = JwtToken(id_token)
        self.access_token = JwtToken(access_token)
        self.refresh_token: str = refresh_token or ""
        self.clock_drift = self._calculate_clock_drift() if clock_drift is None else clock_drift

    def _calculate_clock_drift(self) -> int:
        """Seconds this machine's clock is ahead of the token issuer's, measured when the tokens arrive."""
        return int(time.time()) - min(self.access_token.issued_at, self.id_token.issued_at)

    def is_valid(self) -> bool:
        adjusted = int(time.time()) - self.clock_drift
        return adjusted < self.access_token.expiration and adjusted < self.id_token.expiration


# ---- client ---------------------------------------------------------------------------------------

class CognitoClient:
    def __init__(self, region: str):
        self.endpoint = f"https://cognito-idp.{region}.amazonaws.com/"

    def request(self, operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """One call to the user pool API. Keys whose value is None are left out, as JSON.stringify drops undefined."""
        body = json.dumps({k: v for k, v in params.items() if v is not None}).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=body, method="POST", headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityProviderService.{operation}",
            "Cache-Control": "no-store",
        })
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                raw = resp.read()
                try:
                    return json.loads(raw.decode("utf-8")) if raw else {}
                except ValueError:
                    return {}
        except urllib.error.HTTPError as err:
            raw = err.read()
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except ValueError:
                data = {}
            kind = data.get("__type") or data.get("code")
            if kind:
                code = kind.split("#")[-1]
                raise CognitoError(data.get("message") or data.get("Message"), code, err.code) from None
            header = err.headers.get("x-amzn-errortype") if err.headers else None
            if header:
                raise CognitoError(str(err.code), header.split(":")[0], err.code) from None
            raise CognitoError(str(err.code), "UnknownError", err.code) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as err:
            raise CognitoError(network_error_message(err), "NetworkError") from None

    def request_with_retry(self, operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        request() with jittered exponential retries on ANY error, as skapi-js does for a token
        refresh: waits of about 0.2, 0.4, 0.8, 1.6 and 3.2 seconds (plus up to 0.1 s), then gives
        up when the next wait would pass 5 seconds.
        """
        attempt = 1
        while True:
            try:
                return self.request(operation, params)
            except CognitoError:
                delay = (2 ** attempt) * 100 + 100 * random.random()
                if delay > 5000:
                    raise
                time.sleep(delay / 1000)
                attempt += 1


# ---- the user pool, as skapi-py uses it ---------------------------------------------------------

class Challenge(Exception):
    """Raised by sign-in steps that need one more answer (new password, authenticator code)."""

    def __init__(self, name: str, parameters: Dict[str, Any], session: str):
        super().__init__(name)
        self.name = name
        self.parameters = parameters or {}
        self.session = session


class UserPool:
    def __init__(self, user_pool_id: str, client_id: str, storage):
        if not user_pool_id or not client_id:
            raise ValueError("Both UserPoolId and ClientId are required.")
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.pool_name = user_pool_id.split("_")[1]
        self.client = CognitoClient(user_pool_id.split("_")[0])
        self.storage = storage
        self.key_prefix = f"CognitoIdentityServiceProvider.{client_id}"

    # -- storage --------------------------------------------------------------------------------

    def last_auth_user(self) -> Optional[str]:
        return self.storage.get_item(f"{self.key_prefix}.LastAuthUser")

    def cache_tokens(self, username: str, session: Session) -> None:
        p = f"{self.key_prefix}.{username}"
        self.storage.set_item(f"{p}.idToken", session.id_token.jwt_token)
        self.storage.set_item(f"{p}.accessToken", session.access_token.jwt_token)
        self.storage.set_item(f"{p}.refreshToken", session.refresh_token)
        self.storage.set_item(f"{p}.clockDrift", str(session.clock_drift))
        self.storage.set_item(f"{self.key_prefix}.LastAuthUser", username)

    def clear_cached_tokens(self, username: str) -> None:
        p = f"{self.key_prefix}.{username}"
        for key in (f"{p}.idToken", f"{p}.accessToken", f"{p}.refreshToken", f"{self.key_prefix}.LastAuthUser", f"{p}.clockDrift", f"{p}.userData"):
            self.storage.remove_item(key)

    def cached_session(self, username: str) -> Optional[Session]:
        p = f"{self.key_prefix}.{username}"
        id_token = self.storage.get_item(f"{p}.idToken")
        if not id_token:
            return None
        try:
            clock_drift = int(self.storage.get_item(f"{p}.clockDrift") or 0)
        except ValueError:
            clock_drift = 0
        return Session(id_token, self.storage.get_item(f"{p}.accessToken") or "", self.storage.get_item(f"{p}.refreshToken") or "", clock_drift)

    @staticmethod
    def session_from_result(result: Dict[str, Any], refresh_token: Optional[str] = None) -> Session:
        return Session(result.get("IdToken"), result.get("AccessToken"), result.get("RefreshToken") or refresh_token)

    # -- sign-up and sign-in -------------------------------------------------------------------

    def sign_up(self, username: str, password: str, attributes: list, client_metadata: Optional[dict] = None) -> Dict[str, Any]:
        return self.client.request("SignUp", {
            "ClientId": self.client_id,
            "Username": username,
            "Password": password,
            "UserAttributes": attributes,
            "ValidationData": None,
            "ClientMetadata": client_metadata,
        })

    def authenticate(self, username: str, password: str):
        """
        SRP sign-in. Returns (username_for_srp, Session) on success, or raises Challenge for a next
        step (NEW_PASSWORD_REQUIRED, SOFTWARE_TOKEN_MFA, ...) and CognitoError for a refusal.
        """
        helper = SrpHelper(self.pool_name)
        data = self.client.request("InitiateAuth", {
            "AuthFlow": "USER_SRP_AUTH",
            "ClientId": self.client_id,
            "AuthParameters": {"USERNAME": username, "SRP_A": format(helper.large_a, "x")},
            "ClientMetadata": {},
        })
        params = data["ChallengeParameters"]
        srp_username = params["USER_ID_FOR_SRP"]
        hkdf = helper.get_password_authentication_key(srp_username, password, hex_to_int(params["SRP_B"]), hex_to_int(params["SALT"]))
        now = cognito_timestamp()
        message = self.pool_name.encode("utf-8") + srp_username.encode("utf-8") + _b64_any(params["SECRET_BLOCK"]) + now.encode("utf-8")
        signature = base64.b64encode(hmac.new(hkdf, message, hashlib.sha256).digest()).decode("ascii")
        answer = self.client.request("RespondToAuthChallenge", {
            "ChallengeName": "PASSWORD_VERIFIER",
            "ClientId": self.client_id,
            "ChallengeResponses": {
                "USERNAME": srp_username,
                "PASSWORD_CLAIM_SECRET_BLOCK": params["SECRET_BLOCK"],
                "TIMESTAMP": now,
                "PASSWORD_CLAIM_SIGNATURE": signature,
            },
            "Session": data.get("Session"),
            "ClientMetadata": {},
        })
        return srp_username, self._finish(srp_username, answer)

    def _finish(self, username: str, answer: Dict[str, Any]) -> Session:
        name = answer.get("ChallengeName")
        if name == "DEVICE_SRP_AUTH":
            raise CognitoError("Device authentication is not supported.", "DeviceAuthenticationNotSupported")
        if name:
            raise Challenge(name, answer.get("ChallengeParameters"), answer.get("Session"))
        session = self.session_from_result(answer["AuthenticationResult"])
        self.cache_tokens(username, session)
        return session

    def complete_new_password(self, username: str, new_password: str, challenge_session: str) -> Session:
        answer = self.client.request("RespondToAuthChallenge", {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "ClientId": self.client_id,
            "ChallengeResponses": {"NEW_PASSWORD": new_password, "USERNAME": username},
            "Session": challenge_session,
        })
        return self._finish(username, answer)

    def send_mfa_code(self, username: str, code: str, challenge_session: str) -> Session:
        answer = self.client.request("RespondToAuthChallenge", {
            "ChallengeName": "SOFTWARE_TOKEN_MFA",
            "ChallengeResponses": {"USERNAME": username, "SMS_MFA_CODE": code, "SOFTWARE_TOKEN_MFA_CODE": code},
            "ClientId": self.client_id,
            "Session": challenge_session,
        })
        return self._finish(username, answer)

    def select_mfa_type(self, username: str, answer_name: str, challenge_session: str) -> Challenge:
        data = self.client.request("RespondToAuthChallenge", {
            "ChallengeName": "SELECT_MFA_TYPE",
            "ChallengeResponses": {"USERNAME": username, "ANSWER": answer_name},
            "ClientId": self.client_id,
            "Session": challenge_session,
        })
        return Challenge(data.get("ChallengeName") or answer_name, data.get("ChallengeParameters"), data.get("Session"))

    # -- session --------------------------------------------------------------------------------

    def refresh(self, username: str, refresh_token: str) -> Session:
        """REFRESH_TOKEN_AUTH with retries. A NotAuthorizedException ends the stored session."""
        auth = {"REFRESH_TOKEN": refresh_token}
        if self.last_auth_user():
            username = self.last_auth_user()
            # sent as skapi-js sends it: null, since no device is ever remembered
            auth["DEVICE_KEY"] = self.storage.get_item(f"{self.key_prefix}.{username}.deviceKey")
        params = {"ClientId": self.client_id, "AuthFlow": "REFRESH_TOKEN_AUTH", "AuthParameters": auth}
        try:
            result = self.client.request_with_retry("InitiateAuth", params)
        except CognitoError as err:
            if err.code == "NotAuthorizedException":
                self.clear_cached_tokens(username)
            raise
        session = self.session_from_result(result["AuthenticationResult"], refresh_token)
        self.cache_tokens(username, session)
        return session

    # -- calls made with the access token -----------------------------------------------------

    def call(self, operation: str, access_token: str, **params) -> Dict[str, Any]:
        return self.client.request(operation, dict(params, AccessToken=access_token))

    def call_public(self, operation: str, **params) -> Dict[str, Any]:
        return self.client.request(operation, dict(params, ClientId=self.client_id))
