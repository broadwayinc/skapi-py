"""
skapi: the Skapi backend for Python. Sign users in, keep their sessions, and read and write your
project's database with the same API as skapi-js.

    from skapi import Skapi
    skapi = Skapi("<Project ID>")
"""

__version__ = "2.5.0"

from .errors import SkapiError  # noqa: E402
from .client import Skapi  # noqa: E402
from ._cognito import FileStorage, MemoryStorage  # noqa: E402

__all__ = ["Skapi", "SkapiError", "FileStorage", "MemoryStorage", "__version__"]
