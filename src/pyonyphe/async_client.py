"""Asynchronous ONYPHE client, mirroring :class:`pyonyphe.client.Onyphe`."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx

from . import _specs as specs
from ._base import RETRY_STATUS, BaseClient, PreparedRequest
from ._specs import (
    SEARCH_MAX_RESULTS,
    BestCategory,
    BulkSimpleCategory,
    SimpleCategory,
    Spec,
    SummaryKind,
)
from .errors import TransportError
from .models import Alert, Response

__all__ = ["AsyncOnyphe"]

BulkSource = str | Path | Iterable[str] | bytes


class AsyncOnyphe(BaseClient):
    """Non-blocking client for the ONYPHE APIv2.

    >>> async with AsyncOnyphe() as api:              # doctest: +SKIP
    ...     page = await api.search("category:datascan product:Nginx")
    ...     async for hit in api.export("domain:example.com"):
    ...         ...
    """

    def __init__(self, api_key: str | None = None, **kwargs: Any) -> None:
        super().__init__(api_key, **kwargs)
        self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)

    # -- lifecycle ----------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncOnyphe:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- transport ----------------------------------------------------------

    @staticmethod
    def _kwargs(prepared: PreparedRequest) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"params": prepared.params, "headers": prepared.headers}
        if prepared.content is not None:
            kwargs["content"] = prepared.content
        elif prepared.json is not None:
            kwargs["json"] = prepared.json
        return kwargs

    async def send(self, spec: Spec) -> Response:
        """Send a non-streaming spec, retrying transient failures."""
        prepared = self.prepare(spec)
        kwargs = self._kwargs(prepared)
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.request(prepared.method, prepared.url, **kwargs)
            except httpx.HTTPError as exc:
                last_error = TransportError(f"unable to reach ONYPHE: {exc}")
                if attempt >= self.max_retries:
                    raise last_error from exc
                await asyncio.sleep(self.retry_delay(attempt))
                continue
            if response.status_code in RETRY_STATUS and attempt < self.max_retries:
                header = response.headers.get("Retry-After", "")
                after = float(header) if header.replace(".", "", 1).isdigit() else None
                await asyncio.sleep(self.retry_delay(attempt, after))
                continue
            return self.to_response(response)
        raise last_error or TransportError("request failed")  # pragma: no cover

    async def stream(self, spec: Spec) -> AsyncIterator[dict[str, Any]]:
        """Send a streaming spec and yield one dict per NDJSON line."""
        prepared = self.prepare(spec)
        kwargs = self._kwargs(prepared)
        try:
            async with self._client.stream(prepared.method, prepared.url, **kwargs) as response:
                if response.status_code >= 400:
                    await response.aread()
                    self.raise_for_status(response, self._decode(response))
                async for line in response.aiter_lines():
                    item = self.parse_ndjson_line(line)
                    if item is not None:
                        yield item
        except httpx.HTTPError as exc:
            raise TransportError(f"unable to reach ONYPHE: {exc}") from exc

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        content: bytes | None = None,
    ) -> Response:
        """Escape hatch for endpoints this library does not wrap yet."""
        return await self.send(
            Spec(method.upper(), path, params=params or {}, json=json, content=content)
        )

    # -- general APIs -------------------------------------------------------

    async def user(self) -> Response:
        """Return license, credits and authorisations for the current key."""
        return await self.send(specs.user())

    async def search(
        self,
        query: str,
        *,
        page: int = 1,
        size: int | None = None,
        trackquery: bool = False,
        calculated: bool = False,
    ) -> Response:
        """Run an OQL query and return a single page of results."""
        return await self.send(
            specs.search(query, page=page, size=size, trackquery=trackquery, calculated=calculated)
        )

    async def search_iter(
        self,
        query: str,
        *,
        size: int = 100,
        max_results: int | None = None,
        max_pages: int | None = None,
        trackquery: bool = False,
        calculated: bool = False,
    ) -> AsyncIterator[dict[str, Any]]:
        """Iterate over every result of a query, walking the pages for you.

        :param max_results: stop after this many documents
        :param max_pages: stop after this many API calls, whichever comes first
        """
        fetched = 0
        pages = 0
        page = 1
        while True:
            response = await self.search(
                query, page=page, size=size, trackquery=trackquery, calculated=calculated
            )
            pages += 1
            if not response.results:
                return
            for hit in response.results:
                yield hit
                fetched += 1
                if max_results is not None and fetched >= max_results:
                    return
                if fetched >= SEARCH_MAX_RESULTS:
                    return
            if max_pages is not None and pages >= max_pages:
                return
            if response.max_page is not None and page >= response.max_page:
                return
            page += 1

    def export(
        self, query: str, *, trackquery: bool = False, calculated: bool = False
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream every document matching an OQL query (Eagle View and above)."""
        return self.stream(specs.export(query, trackquery=trackquery, calculated=calculated))

    async def summary(self, kind: SummaryKind, value: str) -> Response:
        """Summary API for an IP, a domain or a hostname."""
        return await self.send(specs.summary(kind, value))

    async def summary_ip(self, ip: str) -> Response:
        """Shortcut for ``summary("ip", ip)``."""
        return await self.summary("ip", ip)

    async def summary_domain(self, domain: str) -> Response:
        """Shortcut for ``summary("domain", domain)``."""
        return await self.summary("domain", domain)

    async def summary_hostname(self, hostname: str) -> Response:
        """Shortcut for ``summary("hostname", hostname)``."""
        return await self.summary("hostname", hostname)

    async def simple(self, category: SimpleCategory, value: str) -> Response:
        """Simple API. Deprecated upstream, scheduled for removal in APIv3."""
        return await self.send(specs.simple(category, value))

    async def simple_best(self, category: BestCategory, value: str) -> Response:
        """Best-matching document for an IP."""
        return await self.send(specs.simple_best(category, value))

    async def simple_datamd5(self, md5: str) -> Response:
        """Datascan documents sharing a ``datamd5`` fingerprint."""
        return await self.send(specs.simple_datamd5(md5))

    async def resolver_forward(self, value: str) -> Response:
        """Forward DNS records for a domain or hostname."""
        return await self.send(specs.simple_resolver_forward(value))

    async def resolver_reverse(self, ip: str) -> Response:
        """Reverse DNS records for an IP address."""
        return await self.send(specs.simple_resolver_reverse(ip))

    # -- bulk APIs ----------------------------------------------------------

    def bulk_summary(self, kind: SummaryKind, source: BulkSource) -> AsyncIterator[dict[str, Any]]:
        """Bulk Summary API."""
        return self.stream(specs.bulk_summary(kind, source))

    def bulk_simple(
        self, category: BulkSimpleCategory, source: BulkSource
    ) -> AsyncIterator[dict[str, Any]]:
        """Bulk Simple API over a list of IP addresses."""
        return self.stream(specs.bulk_simple(category, source))

    def bulk_simple_best(
        self, category: BestCategory, source: BulkSource
    ) -> AsyncIterator[dict[str, Any]]:
        """Bulk Simple Best API over a list of IP addresses."""
        return self.stream(specs.bulk_simple_best(category, source))

    def discovery(self, category: str, source: BulkSource) -> AsyncIterator[dict[str, Any]]:
        """Discovery API: several OQL queries at once (Griffin View only)."""
        return self.stream(specs.discovery(category, source))

    # -- alerts -------------------------------------------------------------

    async def alerts(self) -> list[Alert]:
        """List the alerts configured on the account."""
        response = await self.send(specs.alert_list())
        return [Alert.model_validate(item) for item in response.results]

    async def add_alert(self, name: str, query: str, email: str, threshold: str = ">0") -> Response:
        """Create an alert triggered when the daily count matches ``threshold``."""
        return await self.send(specs.alert_add(name, query, email, threshold))

    async def del_alert(self, alert_id: int | str) -> Response:
        """Delete an alert by identifier."""
        return await self.send(specs.alert_del(alert_id))
