"""
Account methods, ported from skapi-js (src/methods/user.ts): sign-up, sign-in (with authenticator app
MFA), sessions, profile, password and e-mail verification, and user search.
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any, Dict, Optional
from urllib.parse import quote, urlsplit

from ._cognito import Challenge, CognitoError, JwtToken, Session
from ._md5 import md5_js
from .errors import SkapiError

_SKIP_CLAIMS = {"aud", "cognito:username", "event_id", "exp", "iat", "iss", "jti", "origin_jti", "secret_key", "token_use"}
_RENAME_CLAIMS = {"auth_time": "log", "sub": "user_id"}
_EMAIL = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$")
_BIRTHDATE = re.compile(r"([12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
ANONYMOUS_KEEPALIVE_SECONDS = 600
PROFILE_KEYS = ["email", "name", "address", "gender", "birthdate", "phone_number", "email_public", "address_public",
                "gender_public", "birthdate_public", "phone_number_public", "misc", "picture", "profile", "family_name",
                "given_name", "middle_name", "nickname", "website"]
_CUSTOM = {"email_public", "address_public", "gender_public", "birthdate_public", "phone_number_public", "misc", "service", "owner"}


def _jd(v):
    """A value as it appears in an error message; never fails on odd types."""
    return json.dumps(v, default=repr, ensure_ascii=False)


def _p(message: str, code: str = "INVALID_PARAMETER") -> SkapiError:
    return SkapiError(message, code)


def parse_user_attributes(claims: Dict[str, Any]) -> Dict[str, Any]:
    """The ID token's claims as the user profile skapi-js returns."""
    user: Dict[str, Any] = {}
    username = claims.get("cognito:username")
    if isinstance(username, str):
        parts = username.split("-")
        if len(parts) == 2 and parts[1].startswith("anon"):
            user["anonymous"] = True
    for k, v in claims.items():
        if k in _SKIP_CLAIMS:
            continue
        if k in _RENAME_CLAIMS:
            user[_RENAME_CLAIMS[k]] = v
        elif "custom:" in k:
            user[k.replace("custom:", "")] = v
        elif k == "address":
            if isinstance(v, dict):
                if v.get("formatted"):
                    try:
                        user["address"] = json.loads(v["formatted"])
                    except (ValueError, TypeError):
                        user["address"] = v["formatted"]
            else:
                user["address"] = v
        else:
            user[k] = v
    for k in ("address_public", "birthdate_public", "email_public", "gender_public", "phone_number_public"):
        base = k[:-len("_public")]  # the attribute the flag belongs to: "phone_number" for "phone_number_public"
        if base in user:
            try:
                user[k] = bool(float(user.get(k) or 0))
            except (TypeError, ValueError):
                user[k] = False
        else:
            user.pop(k, None)
    try:
        user["access_group"] = int(float(user.get("access_group") or 0))
    except (TypeError, ValueError):
        user["access_group"] = 0
    for k in ("email", "phone_number"):
        if k in user:
            user[f"{k}_verified"] = user.get(f"{k}_verified") is True
        else:
            user.pop(f"{k}_verified", None)
    return user


def validate_email(v: Any) -> str:
    if not v:
        raise _p('"email" is required.')
    if not isinstance(v, str):
        raise _p('"email" should be type: string.')
    if len(v) < 5:
        raise _p('"email" should be at least 5 characters.')
    if not _EMAIL.match(v) or len(v.strip().split("@")[1].split(".")) < 2:
        raise _p(f'"{v}" is an invalid email.')
    return v.strip().lower()


def validate_password(v: Any, field: str = "password") -> str:
    if not v:
        raise _p(f'"{field}" is required.')
    if not isinstance(v, str):
        raise _p(f'"{field}" should be type: string.')
    if len(v) < 6:
        raise _p(f'"{field}" should be at least 6 characters.')
    if len(v) > 60:
        raise _p(f'"{field}" can be up to 60 characters max.')
    return v


def _phone(v):
    if not v:
        return ""
    if not isinstance(v, str) or not v.startswith("+") or not v[1:].strip().replace(".", "", 1).isdigit():
        raise _p('"phone_number" is invalid. The format should be "+00123456789". Type: string.')
    return v


def _birthdate(v):
    if not v:
        return ""
    if not isinstance(v, str) or len(v) != 10 or len(v.split("-")) != 3 or not _BIRTHDATE.search(v):
        raise _p('"birthdate" is invalid. The format should be "yyyy-mm-dd". Type: string.')
    return v


def _url(v):
    if not v:
        return ""
    if v == "*":
        return v
    try:
        parts = urlsplit(v)
        if not parts.scheme or not parts.netloc:
            raise ValueError
    except (ValueError, TypeError):
        raise _p(f'"{v}" is an invalid url.') from None
    return v if parts.path else v + "/"


def _address(v):
    if not v:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    raise _p('"address" should be type: <string | dict>.')


def _string(field):
    def check(v):
        if not isinstance(v, str):
            raise _p(f'{_jd(v)} is invalid in "{field}". allowed type or value is: Type<string>.')
        return v
    return check


def _boolean(field):
    def check(v):
        if not isinstance(v, bool):
            raise _p(f'{_jd(v)} is invalid in "{field}". allowed type or value is: Type<boolean>.')
        return v
    return check


def _mfa_code(v) -> str:
    code = re.sub(r"\s+", "", str(v if v is not None else ""))
    if not re.match(r"^\d{6}$", code):
        raise _p('"code" should be the 6 digit code from the authenticator app.')
    return code


def _parsed_cognito_error(err: Any) -> SkapiError:
    """'#CODE: text' messages from the pool's triggers carry their own code."""
    code = (getattr(err, "code", None) or "ERROR").strip() if isinstance(getattr(err, "code", None), str) else "ERROR"
    message = (getattr(err, "message", None) or str(err) or "An error occurred.").strip() or "An error occurred."
    m = re.search(r"#([A-Za-z0-9_]+)\s*:\s*([\s\S]+)", message)
    if m:
        return SkapiError(m.group(2).strip(), m.group(1).strip(), err)
    return SkapiError(message, code, err)


class UserMixin:
    """Mixed into Skapi."""

    # ---- helpers ----------------------------------------------------------------------------------

    def _cognito_name(self, name: str) -> str:
        return name if (self.service + "-") in name else f"{self.service}-{md5_js(name)}"

    def _refuse_anonymous(self, what: str) -> None:
        if self._user and self._user.get("anonymous"):
            raise SkapiError(f"Anonymous accounts cannot {what}.", "INVALID_REQUEST")

    def _require_session(self) -> None:
        self._ensure_connection()
        if not self._signed_in():
            raise SkapiError("User login is required.", "INVALID_REQUEST")

    # ---- sign-in ------------------------------------------------------------------------------

    def _authenticate(self, name: str, password: str, raw: bool = False, is_openid: bool = False) -> Dict[str, Any]:
        self._request_signup_confirmation = None
        self._disabled_account = None
        self._pending_mfa = None
        pool = self._user_pool()
        username = name if raw else self._cognito_name(name)
        try:
            srp_username, session = pool.authenticate(username, password)
            self._adopt_session(srp_username, session)
            self._disabled_account = None
            self._enc_after_login(password)
            return self.user
        except Challenge as ch:
            return self._handle_challenge(ch, username, password)
        except CognitoError as err:
            code, message = err.code, err.message or ""
            if code == "NotAuthorizedException":
                if "User is disabled." in message:
                    self._disabled_account = username
                    raise SkapiError("This account is disabled.", "USER_IS_DISABLED", err) from None
                if is_openid:
                    raise SkapiError("The account already exists.", "ACCOUNT_EXISTS", err) from None
                raise SkapiError("Incorrect username or password.", "INCORRECT_USERNAME_OR_PASSWORD", err) from None
            if code == "UserNotFoundException":
                raise SkapiError("Incorrect username or password.", "INCORRECT_USERNAME_OR_PASSWORD", err) from None
            if code == "UserNotConfirmedException":
                self._request_signup_confirmation = username
                raise SkapiError("User's signup confirmation is required.", "SIGNUP_CONFIRMATION_NEEDED", err) from None
            if code in ("TooManyRequestsException", "LimitExceededException"):
                raise SkapiError("Too many attempts. Please try again later.", "REQUEST_EXCEED", err) from None
            if code == "NetworkError":
                raise SkapiError(err.message or "Network error", "NETWORK_ERROR", err) from None
            parsed = _parsed_cognito_error(err)
            if parsed.code == "SIGNUP_CONFIRMATION_NEEDED":
                self._request_signup_confirmation = username
            raise parsed from None

    def _handle_challenge(self, ch: Challenge, username: str, password: str) -> Dict[str, Any]:
        pool = self._user_pool()
        srp_username = ch.parameters.get("USER_ID_FOR_SRP") or username
        if ch.name == "NEW_PASSWORD_REQUIRED":
            self._disabled_account = None
            self._request_signup_confirmation = username
            attrs = {}
            try:
                attrs = json.loads(ch.parameters.get("userAttributes") or "{}")
            except ValueError:
                pass
            if attrs.get("custom:signup_ticket") in ("PASS", "MEMBER", "OIDPASS"):
                # an account an admin created, an invitation, or an OpenID account: confirmed by
                # setting the same password
                try:
                    session = pool.complete_new_password(srp_username, password, ch.session)
                except Challenge as nxt:
                    return self._handle_challenge(nxt, username, password)
                except CognitoError as err:
                    raise SkapiError(err.message or "Failed to authenticate user.", err.code, err) from None
                self._adopt_session(srp_username, session)
                self._enc_after_login(password)
                return self.user
            raise SkapiError("User's signup confirmation is required.", "SIGNUP_CONFIRMATION_NEEDED")
        if ch.name == "SOFTWARE_TOKEN_MFA":
            # the password stays in memory only until verify_mfa, to open the encryption keyring
            self._pending_mfa = {"username": srp_username, "session": ch.session, "password": password}
            raise SkapiError("A code from the authenticator app is required to sign in. Call verify_mfa() with the code.", "MFA_REQUIRED")
        if ch.name == "SELECT_MFA_TYPE":
            nxt = pool.select_mfa_type(srp_username, "SOFTWARE_TOKEN_MFA", ch.session)
            return self._handle_challenge(nxt, username, password)
        if ch.name == "SMS_MFA":
            raise SkapiError("Sign-in codes by SMS are not supported.", "INVALID_REQUEST")
        if ch.name == "MFA_SETUP":
            raise SkapiError("The account must set up an authenticator app before signing in.", "INVALID_REQUEST")
        raise SkapiError(f"Unsupported sign-in step: {ch.name}.", "INVALID_REQUEST")

    def login(self, email: Optional[str] = None, password: Optional[str] = None, *, username: Optional[str] = None) -> Dict[str, Any]:
        """
        Signs in with the e-mail (or username) and password. Returns the user's profile.
        Raises SkapiError code 'MFA_REQUIRED' when the account has two-step login on: call verify_mfa(code).
        """
        if not isinstance(password, str):
            raise _p('Key "password" is required.' if password is None else '"password" should be type: string.')
        self._user_pool()
        normalized = None
        if email:
            try:
                normalized = validate_email(email)
            except SkapiError:
                username = email
                email = None
        if not username and not email:
            raise _p('At least one of "username" or "email" is required.')
        typed = username or email
        first = normalized or typed
        fallback = typed if normalized and normalized != typed else None
        try:
            return self._authenticate(first, password)
        except SkapiError as err:
            retryable = err.code in ("INCORRECT_USERNAME_OR_PASSWORD", "UserNotFoundException", "NotAuthorizedException")
            if retryable and fallback:
                try:
                    return self._authenticate(fallback, password)
                except SkapiError as second:
                    if second.code in ("INCORRECT_USERNAME_OR_PASSWORD", "NOT_EXISTS", "UserNotFoundException", "NotAuthorizedException"):
                        raise err from None
                    raise
            raise

    def verify_mfa(self, code: str) -> Dict[str, Any]:
        """Finishes a login that raised MFA_REQUIRED, with the 6 digit code from the authenticator app (within 3 minutes)."""
        code = _mfa_code(code)
        pending = self._pending_mfa
        if not pending:
            raise SkapiError("No sign-in is waiting for an authenticator code. Call login() first.", "INVALID_REQUEST")
        try:
            session = self._user_pool().send_mfa_code(pending["username"], code, pending["session"])
        except CognitoError as err:
            if err.code in ("CodeMismatchException",):
                raise SkapiError("Incorrect authenticator code.", "INVALID_CODE", err) from None
            if err.code == "ExpiredCodeException":
                raise SkapiError("This authenticator code was already used. Wait for the next code.", "INVALID_CODE", err) from None
            self._pending_mfa = None
            if err.code in ("TooManyRequestsException", "LimitExceededException", "TooManyFailedAttemptsException"):
                raise SkapiError("Too many attempts. Please try again later.", "REQUEST_EXCEED", err) from None
            if err.code == "NotAuthorizedException":
                raise SkapiError("The sign-in has expired. Call login() again.", "INVALID_REQUEST", err) from None
            raise _parsed_cognito_error(err) from None
        self._pending_mfa = None
        self._adopt_session(pending["username"], session)
        self._disabled_account = None
        self._enc_after_login(pending.get("password"))
        return self.user

    def logout(self, global_logout: bool = False) -> str:
        """Signs out. global_logout=True also ends every session of the account on every device."""
        self._restore()
        if self._user and self._user.get("anonymous"):
            try:
                self._call("anonymous-session", {"end": True}, auth=True)
            except SkapiError:
                pass
            self._clear_session()
        elif global_logout and self._session:
            try:
                self._user_pool().call("GlobalSignOut", self._access_token())
            except CognitoError as err:
                raise _parsed_cognito_error(err) from None
            self._clear_session()
        else:
            self._clear_session()
        return "SUCCESS: The user has been logged out."

    def get_profile(self, refresh_token: bool = False) -> Optional[Dict[str, Any]]:
        """The signed-in user's profile, or None. refresh_token=True asks the server for fresh tokens first."""
        if not refresh_token:
            return self.user
        try:
            self._restore()
            if self._session and self._restore_refreshed_token == self._session.id_token.jwt_token:
                # the stored tokens had expired and were just refreshed: one refresh, not two
                self._restore_refreshed_token = None
            else:
                self._refresh_session(new_claims=True)
            return self.user
        except SkapiError:
            return None

    def login_with_token(self, id_token: str, access_token: str, refresh_token: str) -> Dict[str, Any]:
        """
        Adopts the tokens of a sign-in made elsewhere (for example skapi-js on a web page that sent
        skapi.session's tokens to your server). All three tokens are needed to make signed-in calls.
        """
        for name, value in (("id_token", id_token), ("access_token", access_token), ("refresh_token", refresh_token)):
            if not isinstance(value, str) or not value:
                raise _p(f'"{name}" is required.')
        payload = JwtToken(id_token).payload
        if payload.get("custom:service") != self.service:
            raise SkapiError("Token does not belong to this service.", "INVALID_REQUEST")
        import time as _t
        if (payload.get("exp") or 0) < _t.time():
            raise SkapiError("Token has expired.", "INVALID_REQUEST")
        self._restore()
        session = Session(id_token, access_token, refresh_token)
        username = payload.get("cognito:username")
        self._adopt_session(username, session)
        self._user_pool().cache_tokens(username, session)
        return self.user

    # ---- sign-up --------------------------------------------------------------------------------

    def signup(self, params: Dict[str, Any], option: Optional[Dict[str, Any]] = None):
        """
        Creates an account. params: email and password (required), and any profile fields.
        option: signup_confirmation (True or a redirect URL), email_subscription, login (sign in right after).
        """
        self._user_pool()
        params = dict(params or {})
        option = dict(option or {})
        if "email" not in params:
            raise _p('Key "email" is required.')
        if "password" not in params:
            raise _p('Key "password" is required.')
        p: Dict[str, Any] = {}
        checks = {
            "username": _string("username"), "password": validate_password, "email": validate_email, "name": _string("name"),
            "address": _address, "gender": _string("gender"), "birthdate": _birthdate, "phone_number": _phone,
            "misc": _string("misc"), "picture": _url, "profile": _url, "family_name": _string("family_name"),
            "given_name": _string("given_name"), "middle_name": _string("middle_name"), "nickname": _string("nickname"), "website": _url,
        }
        for k, fn in checks.items():
            if k in params:
                p[k] = fn(params[k])
        for k in ("email_public", "address_public", "gender_public", "birthdate_public", "phone_number_public"):
            p[k] = params[k] if isinstance(params.get(k), bool) else False

        self.logout()

        sc = option.get("signup_confirmation", False)
        if isinstance(sc, str):
            sc = _url(sc)
        elif not isinstance(sc, bool):
            raise _p('"option.signup_confirmation" should be type: <string | boolean>.')
        if sc and not p.get("email"):
            raise _p('"email" is required for signup confirmation.')
        es = option.get("email_subscription", False)
        if not isinstance(es, (bool, str, int)) or (isinstance(es, int) and not isinstance(es, bool) and es not in (0, 1)):
            raise _p('"option.email_subscription" takes 0 (public), 1 (authorized), true, false or the name of a newsletter group.')
        if es is not False and not sc:
            raise _p('"option.signup_confirmation" is required for email subscription.')
        login_after = option.get("login", False)
        if not isinstance(login_after, bool):
            raise _p('"option.login" should be type: boolean.')
        if login_after and sc:
            raise _p('"login" is not allowed when "option.signup_confirmation" is true.')
        template = option.get("template") or {}
        if not isinstance(template, dict):
            raise _p('"option.template" should be type: <object>.')
        for key in ("signup_confirmation", "welcome"):
            if key in template and (not isinstance(template[key], str) or not template[key]):
                raise _p(f'"option.template.{key}" should be a non-empty <string> (template message_id).')
        if template.get("signup_confirmation") and not sc:
            raise _p('"option.signup_confirmation" is required when "option.template.signup_confirmation" is set.')
        if p.get("email_public") and not sc:
            raise _p('"option.signup_confirmation" should be true if "email_public" is set to true.')

        cognito_username = self._cognito_name(p.get("username") or p["email"])
        key_reply = self._call("signupkey", {
            "username": cognito_username,
            "signup_confirmation": json.dumps(sc) if isinstance(sc, bool) else sc,
            "email_subscription": es,
            "template_confirmation": template.get("signup_confirmation") or "",
            "template_welcome": template.get("welcome") or "",
        })
        parts = str(key_reply).split(":")
        signup_key, signup_ticket = parts[0], ":".join(parts[1:])
        attributes = [
            {"Name": "custom:signup", "Value": signup_key},
            {"Name": "locale", "Value": signup_ticket.split("#")[1] if "#" in signup_ticket else ""},
            {"Name": "custom:signup_ticket", "Value": signup_ticket},
        ]
        values = dict(p, service=self.service, owner=self.owner)
        for k in ["email", "name", "address", "gender", "birthdate", "phone_number", "email_public", "address_public", "gender_public",
                  "birthdate_public", "phone_number_public", "misc", "picture", "profile", "family_name", "given_name", "middle_name",
                  "nickname", "website", "service", "owner"]:
            v = values.get(k)
            if v == "":
                continue
            if k.endswith("_public"):
                v = "1" if v else "0"
            attributes.append({"Name": f"custom:{k}" if k in _CUSTOM else k, "Value": "" if v is None else str(v)})
        try:
            self._user_pool().sign_up(cognito_username, p["password"], attributes)
        except CognitoError as err:
            parsed = _parsed_cognito_error(err)
            if err.code == "UsernameExistsException":
                raise SkapiError("The account already exists.", "EXISTS", err) from None
            if err.code == "InvalidPasswordException":
                raise SkapiError("Invalid password. Password must be at least 6 characters.", "INVALID_PARAMETER", err) from None
            if err.code == "InvalidParameterException":
                raise SkapiError(parsed.message or "Invalid parameter.", "INVALID_PARAMETER", err) from None
            if err.code in ("TooManyRequestsException", "LimitExceededException"):
                raise SkapiError("Too many attempts. Please try again later.", "REQUEST_EXCEED", err) from None
            if err.code == "CodeDeliveryFailureException":
                raise SkapiError("Failed to deliver verification code.", "CODE_DELIVERY_FAILURE", err) from None
            if err.code == "UserLambdaValidationException":
                raise SkapiError(parsed.message or "Signup validation failed.", "EXISTS" if parsed.code == "EXISTS" else "INVALID_REQUEST", err) from None
            raise parsed from None
        if sc:
            self._request_signup_confirmation = cognito_username
            return "SUCCESS: The account has been created. User's signup confirmation is required."
        if login_after:
            return self.login(p.get("username") or p["email"], p["password"])
        return "SUCCESS: The account has been created."

    def resend_signup_confirmation(self) -> str:
        if not self._request_signup_confirmation:
            raise SkapiError("Least one login attempt is required.", "INVALID_REQUEST")
        return self._call("confirm-signup", {"username": self._request_signup_confirmation})

    def recover_account(self, redirect: Any = False) -> str:
        """Sends the recovery e-mail to a disabled account, after a login attempt answered USER_IS_DISABLED."""
        if isinstance(redirect, str):
            redirect = _url(redirect)
        elif not isinstance(redirect, bool):
            raise SkapiError("Argument should be type: <boolean | string>.", "INVALID_REQUEST")
        if not self._disabled_account:
            raise SkapiError("Least one signin attempt of disabled account is required.", "INVALID_REQUEST")
        self._call("recover-account", {"username": self._disabled_account, "redirect": redirect})
        return "SUCCESS: Recovery e-mail has been sent."

    def disable_account(self) -> str:
        self._require_session()
        self._refuse_anonymous("be disabled")
        result = self._call("remove-account", {"disable": self._user["user_id"]}, auth=True)
        self.logout()
        return result

    # ---- profile and password ---------------------------------------------------------------------

    def update_profile(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Changes the signed-in user's own profile fields. '' clears a field."""
        self._require_session()
        self._refuse_anonymous("edit their profile")
        params = dict(params or {})
        p: Dict[str, Any] = {}
        checks = {
            "email": validate_email, "address": _address, "name": _string("name"), "gender": _string("gender"),
            "birthdate": _birthdate, "phone_number": _phone, "misc": _string("misc"), "picture": _url, "profile": _url,
            "website": _url, "family_name": _string("family_name"), "given_name": _string("given_name"),
            "middle_name": _string("middle_name"), "nickname": _string("nickname"),
        }
        for k in ("email_public", "phone_number_public", "address_public", "gender_public", "birthdate_public"):
            checks[k] = _boolean(k)
        for k, fn in checks.items():
            if k in params:
                p[k] = fn(params[k])
        if not p:
            return self.user
        if p.get("email_public") and not self._user.get("email_verified"):
            raise SkapiError('User\'s e-mail should be verified to set "email_public" to true.', "INVALID_REQUEST")
        current = self._user or {}
        attributes = []
        for k, v in p.items():
            if not isinstance(v, (dict, list)) and k in current and current[k] == v:
                continue
            name = f"custom:{k}" if k in _CUSTOM else k
            if isinstance(v, bool):
                v = "1" if v else "0"
            attributes.append({"Name": name, "Value": "" if v is None else str(v)})
        if attributes:
            try:
                self._user_pool().call("UpdateUserAttributes", self._access_token(), UserAttributes=attributes)
            except CognitoError as err:
                raise SkapiError(err.message or "Failed to update user settings.", err.code or err.name, err) from None
            self._refresh_session(new_claims=True)
        return self.user

    def change_password(self, current_password: str, new_password: str) -> str:
        self._require_session()
        self._refuse_anonymous("change their password")
        if not current_password:
            raise _p('"current_password" is required to change password.')
        if not new_password:
            raise _p('"new_password" is required to change password.')
        validate_password(current_password, "current_password")
        validate_password(new_password, "new_password")
        # the keyring gets a wrap under the new password BEFORE the password changes (fails while locked)
        rewrapped = self._enc_rewrap_password(current_password, new_password)
        try:
            self._user_pool().call("ChangePassword", self._access_token(), PreviousPassword=current_password, ProposedPassword=new_password)
        except CognitoError as err:
            if err.code == "InvalidParameterException":
                raise SkapiError("Invalid password parameter.", "INVALID_PARAMETER", err) from None
            if err.code == "NotAuthorizedException":
                raise SkapiError("Incorrect password.", "INVALID_REQUEST", err) from None
            if err.code in ("TooManyRequestsException", "LimitExceededException"):
                raise SkapiError("Too many attempts. Please try again later.", "REQUEST_EXCEED", err) from None
            raise _parsed_cognito_error(err) from None
        if rewrapped is not None:
            self._enc_prune_wraps()
        return "SUCCESS: Password has been changed."

    def forgot_password(self, email: str, template: Optional[Dict[str, str]] = None) -> str:
        """Sends a password reset code to the account's e-mail. Then call reset_password()."""
        self._ensure_connection()
        email = validate_email(email)
        metadata = None
        if template is not None:
            if not isinstance(template, dict):
                raise _p('"template" should be type: <object>.')
            if "verification" in template:
                raise _p('"template.verification" is not an option of forgot_password(). Use "template.forgot_password" (template message_id).')
            if "forgot_password" in template:
                if not isinstance(template["forgot_password"], str) or not template["forgot_password"]:
                    raise _p('"template.forgot_password" should be a non-empty <string> (template message_id).')
                metadata = {"template_forgot_password": template["forgot_password"]}
        try:
            self._user_pool().call_public("ForgotPassword", Username=self._cognito_name(email), ClientMetadata=metadata)
        except CognitoError as err:
            parsed = _parsed_cognito_error(err)
            code = {"UserNotFoundException": "NOT_EXISTS", "InvalidParameterException": "INVALID_PARAMETER", "NotAuthorizedException": "INVALID_REQUEST",
                    "LimitExceededException": "REQUEST_EXCEED", "TooManyRequestsException": "REQUEST_EXCEED",
                    "CodeDeliveryFailureException": "CODE_DELIVERY_FAILURE"}.get(err.code, parsed.code or err.code or "ERROR")
            raise SkapiError(parsed.message, code, err) from None
        return "SUCCESS: Verification code has been sent."

    def reset_password(self, email: str, code: Any, new_password: str) -> str:
        self._ensure_connection()
        email = validate_email(email)
        if isinstance(code, bool) or not isinstance(code, (str, int)):
            raise _p(f'{_jd(code)} is invalid in "code". allowed types or values are: Type<number>, Type<string>.')
        validate_password(new_password)
        try:
            self._user_pool().call_public("ConfirmForgotPassword", Username=self._cognito_name(email), ConfirmationCode=str(code), Password=new_password)
        except CognitoError as err:
            raise SkapiError(err.message or "Failed to reset password.", err.code or "ERROR", err) from None
        return "SUCCESS: New password has been set."

    def verify_email(self, code: Optional[str] = None, template: Optional[Dict[str, str]] = None) -> str:
        """Without code: sends a verification code to the user's e-mail. With code: verifies it."""
        self._ensure_connection()
        if not self._signed_in():
            raise SkapiError("The user has to be logged in.", "INVALID_REQUEST")
        self._refuse_anonymous("verify an e-mail")
        if "email" not in self._user:
            raise SkapiError("No e-mail to verify", "INVALID_REQUEST")
        if self._user.get("email_verified"):
            return 'SUCCESS: "email" is verified.'
        if code is not None and not isinstance(code, str):
            raise _p(f'{_jd(code)} is invalid in "code". allowed type or value is: Type<string>.')
        metadata = None
        if template and "verification" in template:
            if not isinstance(template["verification"], str) or not template["verification"]:
                raise _p('"template.verification" should be a non-empty <string> (template message_id).')
            metadata = {"template_verification": template["verification"]}
        try:
            if code:
                self._user_pool().call("VerifyUserAttribute", self._access_token(), AttributeName="email", Code=code)
                self._refresh_session(new_claims=True)
                self._user["email_verified"] = True
                return 'SUCCESS: "email" is verified.'
            self._user_pool().call("GetUserAttributeVerificationCode", self._access_token(), AttributeName="email", ClientMetadata=metadata)
            return "SUCCESS: Verification code has been sent."
        except CognitoError as err:
            raise SkapiError(err.message or "Failed to request verification code.", err.code, err) from None

    def last_verified_email(self, revert: Optional[bool] = None):
        self._require_session()
        self._refuse_anonymous("change their e-mail")
        body = {} if revert is None else {"revert": revert}
        reply = self._call("last-verified-email", body, auth=True)
        if isinstance(reply, str) and "SUCCESS" in reply:
            self._refresh_session(new_claims=True)
            return self.user
        return reply

    # ---- OpenID and anonymous -------------------------------------------------------------------

    def open_id_login(self, token: str, id: str, merge: Any = None, template: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Signs in with a token from your OpenID provider, through the OpenID logger set up as `id`."""
        self._ensure_connection()
        body: Dict[str, Any] = {"token": _string("token")(token), "id": _string("id")(id)}
        if merge is not None:
            if isinstance(merge, str):
                merge = [merge]
            if isinstance(merge, list):
                if not all(isinstance(m, str) for m in merge):
                    raise _p('"merge" array items should be type: <string>.')
            elif not isinstance(merge, bool):
                raise _p('"merge" should be type: <boolean | string[]>.')
            body["merge"] = merge
        if template is not None:
            if not isinstance(template, dict):
                raise _p('"template" should be type: <object>.')
            if "welcome" in template:
                if not isinstance(template["welcome"], str) or not template["welcome"]:
                    raise _p('"template.welcome" should be a non-empty <string> (template message_id).')
                body["template_welcome"] = template["welcome"]
        reply = self._call("openid-logger", body)
        logger = str(reply.get("logger", "")).split("#")
        profile = self._authenticate(f"{self.service}-{logger[0]}", logger[1] if len(logger) > 1 else "", raw=True, is_openid=True)
        return {"userProfile": profile, "openid": reply.get("openid")}

    def anonymous_login(self) -> Dict[str, Any]:
        """A temporary account without e-mail or password, deleted 30 minutes after this object stops keeping it alive."""
        self._ensure_connection()
        if self._signed_in():
            if self._user.get("anonymous"):
                self._start_anonymous_keep_alive()
                return self.user
            raise SkapiError("A user is already logged in. Log out first.", "INVALID_REQUEST")
        creds = self._call("anonymous-login", {})
        profile = self._authenticate(creds["username"], creds["password"], raw=True)
        self._start_anonymous_keep_alive()
        return profile

    def verify_anonymous_session(self) -> Optional[Dict[str, Any]]:
        """
        For a temporary account restored from storage: asks the server whether it still exists.
        Returns the profile, or None (and signs out) when the account was already deleted.
        Any other user is returned as is, without a request.
        """
        self._ensure_connection()
        self._restore()
        if not (self._user and self._user.get("anonymous")):
            return self.user
        try:
            self._call("anonymous-session", {}, auth=True)
        except SkapiError as err:
            if err.code == "NOT_EXISTS":
                self._clear_session()
                return None
        return self.user

    def _start_anonymous_keep_alive(self, beat_now: bool = False) -> None:
        self._stop_anonymous_keep_alive()

        def beat():
            if not (self._user and self._user.get("anonymous")):
                return
            try:
                self._call("anonymous-session", {}, auth=True)
            except SkapiError as err:
                if err.code == "NOT_EXISTS":
                    self._clear_session()
                    return
            self._start_anonymous_keep_alive()

        timer = threading.Timer(0 if beat_now else ANONYMOUS_KEEPALIVE_SECONDS, beat)
        timer.daemon = True
        timer.start()
        self._anonymous_timer = timer

    def _stop_anonymous_keep_alive(self) -> None:
        timer = getattr(self, "_anonymous_timer", None)
        if timer:
            timer.cancel()
        self._anonymous_timer = None

    # ---- authenticator app MFA ----------------------------------------------------------------

    def _mfa_user(self, what: str) -> str:
        self._require_session()
        self._refuse_anonymous(what)
        return self._access_token()

    def setup_mfa(self, issuer: Optional[str] = None, account_name: Optional[str] = None) -> Dict[str, str]:
        """Starts two-step login setup: returns {"secret", "uri"}. Show uri as a QR code, then call enable_mfa(code)."""
        token = self._mfa_user("set up MFA")
        try:
            secret = self._user_pool().call("AssociateSoftwareToken", token)["SecretCode"]
        except CognitoError as err:
            raise _parsed_cognito_error(err) from None
        conn = self.connection or {}
        issuer = (issuer or conn.get("service_name") or self.service or "").replace(":", " ").strip()
        u = self._user or {}
        account = (account_name or u.get("email") or u.get("username") or u.get("user_id") or "").replace(":", " ").strip()
        enc = lambda s: quote(s, safe="-_.!~*'()")
        label = f"{enc(issuer)}:{enc(account)}" if issuer else enc(account)
        uri = f"otpauth://totp/{label}?secret={secret}" + (f"&issuer={enc(issuer)}" if issuer else "") + "&algorithm=SHA1&digits=6&period=30"
        return {"secret": secret, "uri": uri}

    def enable_mfa(self, code: str) -> str:
        code = _mfa_code(code)
        token = self._mfa_user("turn on MFA")
        try:
            self._user_pool().call("VerifySoftwareToken", token, UserCode=code)
        except CognitoError as err:
            if err.code == "SoftwareTokenMFANotFoundException" or (err.code == "InvalidParameterException" and re.search(r"software token", err.message or "", re.I)):
                raise SkapiError("Call setup_mfa() first.", "INVALID_REQUEST", err) from None
            if err.code in ("EnableSoftwareTokenMFAException", "CodeMismatchException"):
                raise SkapiError("Incorrect authenticator code.", "INVALID_CODE", err) from None
            if err.code in ("TooManyRequestsException", "LimitExceededException"):
                raise SkapiError("Too many attempts. Please try again later.", "REQUEST_EXCEED", err) from None
            raise _parsed_cognito_error(err) from None
        try:
            self._user_pool().call("SetUserMFAPreference", token, SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True})
        except CognitoError as err:
            raise _parsed_cognito_error(err) from None
        return "SUCCESS: MFA has been enabled."

    def disable_mfa(self) -> str:
        token = self._mfa_user("turn off MFA")
        try:
            self._user_pool().call("SetUserMFAPreference", token, SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False})
        except CognitoError as err:
            raise _parsed_cognito_error(err) from None
        return "SUCCESS: MFA has been disabled."

    def get_mfa_status(self) -> Dict[str, bool]:
        token = self._mfa_user("use MFA")
        try:
            data = self._user_pool().call("GetUser", token)
        except CognitoError as err:
            raise _parsed_cognito_error(err) from None
        return {"enabled": "SOFTWARE_TOKEN_MFA" in (data.get("UserMFASettingList") or [])}

    # ---- users ----------------------------------------------------------------------------------

    def get_users(self, params: Optional[Dict[str, Any]] = None, fetch_options: Optional[dict] = None) -> dict:
        """Searches the project's users by one profile field. Signed-in users only."""
        fetch_options = dict(fetch_options or {})
        if not params:
            params = {"searchFor": "timestamp", "condition": ">", "value": 0}
            fetch_options["ascending"] = False
        params = dict(params)
        fields = ["user_id", "name", "email", "phone_number", "address", "gender", "birthdate", "locale", "subscribers", "timestamp", "access_group", "approved"]
        search_for = params.get("searchFor")
        if "searchFor" not in params:
            raise _p('Key "searchFor" is required.')
        if "value" not in params:
            raise _p('Key "value" is required.')
        if search_for == "":
            raise _p('"searchFor" should not be an empty string.')
        if search_for not in fields:
            raise _p(f'{_jd(search_for)} is invalid in "searchFor". allowed types or values are: ' + ", ".join(_jd(f) for f in fields) + ".")
        conditions = [">", ">=", "=", "<", "<=", "gt", "gte", "eq", "lt", "lte"]
        condition = params.get("condition", "=")
        if condition not in conditions:
            condition = "="

        def check(v, what):
            if search_for == "user_id":
                if not isinstance(v, str) or not _UUID.match(v):
                    raise _p("User ID is invalid.")
            elif search_for == "locale":
                if not isinstance(v, str) or len(v) > 5:
                    raise _p('Value of "locale" should be a country code.')
            elif search_for == "birthdate":
                _birthdate(v)
            elif search_for in ("subscribers", "timestamp", "access_group"):
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise _p(f'{what} does not match the type of "{search_for}" index.')
            elif not isinstance(v, str):
                raise _p(f'{what} does not match the type of "{search_for}" index.')
            return v

        value = params["value"]
        if isinstance(value, list):
            value = [check(v, "Value") for v in value]
        else:
            check(value, "Value")
        body = {"searchFor": search_for, "value": value, "condition": condition}
        if "range" in params:
            check(params["range"], "Range")
            body["range"] = params["range"]
        if condition != "=" and "range" in params:
            raise _p("Conditions does not apply on range search.")
        if isinstance(value, list) and (condition != "=" or params.get("range")):
            raise _p(f'Conditions are not allowed on a list of "{search_for}" values. Search for a single value to use a condition or range.')
        if value == "":
            raise _p("Value should not be an empty string.")
        return self._call("get-users", body, auth=True, fetch_options=fetch_options)

    # ---- tickets --------------------------------------------------------------------------------

    def consume_ticket(self, ticket_id: str, method: str = "POST", data: Any = None, auth: bool = False) -> Any:
        """Calls a ticket of the project (set up on skapi.com) with `data`. Returns its receipt or answer."""
        from ._social import map_ticket
        self._ensure_connection()
        if not ticket_id:
            raise _p("Ticket ID is required.")
        if not isinstance(ticket_id, str) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", ticket_id):
            raise _p('Invalid "ticket_id". Use letters, digits, "_" and "-" (up to 64 chars, starting with a letter or digit).')
        if not method:
            raise _p('Method is required. Should be either "GET" or "POST"')
        method = str(method).upper()
        if method not in ("GET", "POST"):
            raise _p('Method should be either "GET" or "POST".')
        if auth and method == "GET":
            raise _p("Signed-in consumption is POST only.")
        route = "tpa" if auth else ("tg" if method == "GET" else "tp")
        url = f"https://{self.service[:4]}.skapi.dev/{route}/{self.service}/{ticket_id}"
        token = self._fresh_id_token() if auth else None
        reply = self._requester.request(url, data or {}, method=method, token=token, ignore_service=True)
        if isinstance(reply, dict) and "stage" in reply:
            raise SkapiError(reply.get("message") or "Ticket failed.", reply.get("code") or "ERROR", reply)
        if isinstance(reply, dict) and isinstance(reply.get("tkid"), str):
            return map_ticket(reply)
        return reply
