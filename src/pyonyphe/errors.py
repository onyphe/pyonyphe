"""Typed exception hierarchy for the ONYPHE API."""

from __future__ import annotations

__all__ = [
    "OnypheError",
    "ConfigError",
    "ParamError",
    "TransportError",
    "APIError",
    "AuthenticationError",
    "PaymentRequiredError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
]


class OnypheError(Exception):
    """Base class for every error raised by this library."""


class ConfigError(OnypheError):
    """No API key could be resolved, or the configuration file is unusable."""


class ParamError(OnypheError):
    """A caller-supplied argument is invalid (bad category, missing file, ...)."""


class TransportError(OnypheError):
    """The request never reached ONYPHE (DNS, TLS, timeout, connection reset)."""


class APIError(OnypheError):
    """ONYPHE answered with a non-2xx status code.

    :param message: human readable error, taken from the ``text`` field when present
    :param status_code: HTTP status code returned by the API
    :param payload: decoded JSON body, when the body was valid JSON
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        payload: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.payload = payload or {}

    def __str__(self) -> str:
        if self.status_code is None:
            return self.message
        return f"[{self.status_code}] {self.message}"


class AuthenticationError(APIError):
    """401/403 - the API key is missing, invalid, or not allowed on this endpoint."""


class PaymentRequiredError(APIError):
    """402 - the subscription does not cover this API or the credits are exhausted."""


class NotFoundError(APIError):
    """404 - unknown endpoint or no such object."""


class RateLimitError(APIError):
    """429 - rate limit reached.

    :param retry_after: seconds to wait before retrying, when the API said so
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        payload: dict[str, object] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, payload=payload)
        self.retry_after = retry_after


class ServerError(APIError):
    """5xx - ONYPHE is having a bad day."""
