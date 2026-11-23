"""SkapiError: every error skapi-py raises carries a code and a message, the same as skapi-js."""

from __future__ import annotations

import urllib.error
from typing import Any, Optional


class SkapiError(Exception):
    """
    code: a short name such as 'INVALID_PARAMETER', 'INVALID_REQUEST', 'NOT_EXISTS',
    'INCORRECT_USERNAME_OR_PASSWORD' or 'MFA_REQUIRED', the same codes skapi-js uses.
    message: what went wrong, in plain words.
    cause: the underlying error, when there is one.
    """

    def __init__(self, message: str, code: str = "ERROR", cause: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.cause = cause

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def __repr__(self) -> str:
        return f"SkapiError(code={self.code!r}, message={self.message!r})"


def network_error_message(err: BaseException) -> str:
    """'Network error: <reason>' for a failed connection, so the real cause (for example
    '[SSL: CERTIFICATE_VERIFY_FAILED] ...') shows in the message and the traceback."""
    if isinstance(err, urllib.error.URLError) and isinstance(err.reason, BaseException):
        err = err.reason
    elif isinstance(err, urllib.error.URLError):
        err = err.reason or err
    text = str(err).strip()
    return f"Network error: {text}" if text else "Network error"
