"""Transport-agnostic plumbing shared by :mod:`pyonyphe.client` and
:mod:`pyonyphe.async_client`."""

from __future__ import annotations

import base64
import json as jsonlib
from dataclasses import dataclass
from typing import Any

import httpx

from ._specs import Spec
from .config import Settings, load_settings
from .errors import (
    APIError,
    AuthenticationError,
    NotFoundError,
    PaymentRequiredError,
    RateLimitError,
    ServerError,
)
from .models import Response

__all__ = ["USER_AGENT", "BaseClient", "PreparedRequest"]

USER_AGENT = "pyonyphe/3.0.0 (+https://github.com/sebdraven/pyonyphe)"

#: Status codes worth retrying: rate limit plus transient server-side failures.
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class PreparedRequest:
    """A :class:`~pyonyphe._specs.Spec` resolved against the client settings."""

    method: str
    url: str
    params: dict[str, Any]
    headers: dict[str, str]
    content: bytes | None
    json: dict[str, Any] | None
    stream: bool


class BaseClient:
    """Shared configuration, request building and error mapping.

    :param api_key: ONYPHE API key; resolved from env/config files when omitted
    :param base_url: API root override
    :param unrated_email: login email, switches to the Unrated endpoint
    :param timeout: per-request timeout in seconds
    :param max_retries: how many times a retryable failure is retried
    :param backoff: base delay in seconds for the exponential backoff
    :param user_agent: value sent in the ``User-Agent`` header
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        unrated_email: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff: float = 0.5,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.settings: Settings = load_settings(
            api_key, base_url=base_url, unrated_email=unrated_email
        )
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.user_agent = user_agent

    # -- request building ---------------------------------------------------

    @property
    def base_url(self) -> str:
        """API root in use, without a trailing slash."""
        return self.settings.base_url

    def _auth_headers(self) -> dict[str, str]:
        if self.settings.is_unrated:
            login = (self.settings.unrated_email or "").replace("@", "_")
            token = base64.b64encode(f"{login}:{self.settings.api_key}".encode()).decode()
            return {"Authorization": f"basic {token}"}
        return {"Authorization": f"bearer {self.settings.api_key}"}

    def prepare(self, spec: Spec) -> PreparedRequest:
        """Turn a :class:`Spec` into an absolute, authenticated request."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
            **self._auth_headers(),
        }
        params = dict(spec.params)
        if self.settings.is_unrated:
            # The Unrated endpoint uses the Authorization header for basic auth,
            # so the key has to travel as a query parameter as well.
            params["k"] = self.settings.api_key
        return PreparedRequest(
            method=spec.method,
            url=f"{self.base_url}/{spec.path.lstrip('/')}",
            params=params,
            headers=headers,
            content=spec.content,
            json=spec.json,
            stream=spec.stream,
        )

    # -- response handling --------------------------------------------------

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError:
            return {}
        return payload if isinstance(payload, dict) else {"results": payload}

    def raise_for_status(self, response: httpx.Response, payload: dict[str, Any]) -> None:
        """Map an HTTP status code onto the exception hierarchy.

        :raises APIError: or one of its subclasses, for any non-2xx status
        """
        status = response.status_code
        if status < 400:
            return
        message = str(payload.get("text") or payload.get("message") or response.reason_phrase)
        if status in (401, 403):
            raise AuthenticationError(message or "access forbidden", status_code=status,
                                      payload=payload)
        if status == 402:
            raise PaymentRequiredError(message or "payment required", status_code=status,
                                       payload=payload)
        if status == 404:
            raise NotFoundError(message or f"not found: {response.url}", status_code=status,
                                payload=payload)
        if status == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                message or "too many requests",
                status_code=status,
                payload=payload,
                retry_after=float(retry_after) if retry_after and retry_after.isdigit() else None,
            )
        if status >= 500:
            raise ServerError(message or "onyphe server error", status_code=status,
                              payload=payload)
        raise APIError(message or "unknown error", status_code=status, payload=payload)

    def to_response(self, response: httpx.Response) -> Response:
        """Validate a successful JSON body into a :class:`Response`."""
        payload = self._decode(response)
        self.raise_for_status(response, payload)
        return Response.model_validate(payload)

    def retry_delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Delay before retry number ``attempt`` (0-indexed)."""
        if retry_after is not None:
            return retry_after
        return self.backoff * (2**attempt)

    @staticmethod
    def parse_ndjson_line(line: str) -> dict[str, Any] | None:
        """Decode one line of a streamed response, skipping blanks and junk."""
        stripped = line.strip()
        if not stripped:
            return None
        try:
            decoded = jsonlib.loads(stripped)
        except ValueError:
            return None
        return decoded if isinstance(decoded, dict) else None
