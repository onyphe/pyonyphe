"""Modern Python client and CLI for the ONYPHE Cyber Defense Search Engine.

    >>> from pyonyphe import Onyphe                    # doctest: +SKIP
    >>> with Onyphe() as api:                          # doctest: +SKIP
    ...     summary = api.summary_ip("8.8.8.8")
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._specs import (
    BEST_CATEGORIES,
    BULK_SIMPLE_CATEGORIES,
    SEARCH_MAX_RESULTS,
    SIMPLE_CATEGORIES,
    SUMMARY_KINDS,
)
from .async_client import AsyncOnyphe
from .client import Onyphe
from .config import DEFAULT_BASE_URL, UNRATED_BASE_URL, Settings, load_settings
from .errors import (
    APIError,
    AuthenticationError,
    ConfigError,
    NotFoundError,
    OnypheError,
    ParamError,
    PaymentRequiredError,
    RateLimitError,
    ServerError,
    TransportError,
)
from .models import Alert, Response

try:
    __version__ = version("pyonyphe")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0.dev0"

__all__ = [
    "BEST_CATEGORIES",
    "BULK_SIMPLE_CATEGORIES",
    "DEFAULT_BASE_URL",
    "SEARCH_MAX_RESULTS",
    "SIMPLE_CATEGORIES",
    "SUMMARY_KINDS",
    "UNRATED_BASE_URL",
    "APIError",
    "Alert",
    "AsyncOnyphe",
    "AuthenticationError",
    "ConfigError",
    "NotFoundError",
    "Onyphe",
    "OnypheError",
    "ParamError",
    "PaymentRequiredError",
    "RateLimitError",
    "Response",
    "ServerError",
    "Settings",
    "TransportError",
    "__version__",
    "load_settings",
]
