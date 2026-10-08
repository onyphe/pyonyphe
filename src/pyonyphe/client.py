"""Synchronous ONYPHE client."""

from __future__ import annotations

import time
from collections.abc import Iterable, Iterator
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
from .errors import APIError, TransportError
from .models import Alert, Response

__all__ = ["Onyphe"]

BulkSource = str | Path | Iterable[str] | bytes


class Onyphe(BaseClient):
    """Blocking client for the ONYPHE APIv2.

    >>> with Onyphe() as api:                     # doctest: +SKIP
    ...     page = api.search("category:datascan product:Nginx")
    ...     print(page.total)

    The API key is taken from the ``api_key`` argument, then from
    ``ONYPHE_API_KEY``, then from the configuration files -- see
    :func:`pyonyphe.config.load_settings`.
    """

    def __init__(self, api_key: str | None = None, **kwargs: Any) -> None:
        super().__init__(api_key, **kwargs)
        self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> Onyphe:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- transport ----------------------------------------------------------

    @staticmethod
    def _kwargs(prepared: PreparedRequest) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"params": prepared.params, "headers": prepared.headers}
        if prepared.content is not None:
            kwargs["content"] = prepared.content
        elif prepared.json is not None:
            kwargs["json"] = prepared.json
        return kwargs

    def send(self, spec: Spec, *, retry: bool = True) -> Response:
        """Send a non-streaming spec, retrying transient failures.

        :param retry: ``False`` sends the request exactly once, for calls that
            are not idempotent -- no replay on 429/5xx, none on a transport
            failure either
        :raises TransportError: when the request never reached ONYPHE
        :raises APIError: on any non-2xx answer
        """
        prepared = self.prepare(spec)
        kwargs = self._kwargs(prepared)
        max_retries = self.max_retries if retry else 0
        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                response = self._client.request(prepared.method, prepared.url, **kwargs)
            except httpx.HTTPError as exc:
                last_error = TransportError(f"unable to reach ONYPHE: {exc}")
                if attempt >= max_retries:
                    raise last_error from exc
                time.sleep(self.retry_delay(attempt))
                continue
            if response.status_code in RETRY_STATUS and attempt < max_retries:
                header = response.headers.get("Retry-After", "")
                after = float(header) if header.replace(".", "", 1).isdigit() else None
                time.sleep(self.retry_delay(attempt, after))
                continue
            return self.to_response(response)
        raise last_error or TransportError("request failed")  # pragma: no cover

    def stream(self, spec: Spec) -> Iterator[dict[str, Any]]:
        """Send a streaming spec and yield one dict per NDJSON line."""
        prepared = self.prepare(spec)
        kwargs = self._kwargs(prepared)
        try:
            with self._client.stream(prepared.method, prepared.url, **kwargs) as response:
                if response.status_code >= 400:
                    response.read()
                    self.raise_for_status(response, self._decode(response))
                for line in response.iter_lines():
                    item = self.parse_ndjson_line(line)
                    if item is not None:
                        yield item
        except httpx.HTTPError as exc:
            raise TransportError(f"unable to reach ONYPHE: {exc}") from exc

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        content: bytes | None = None,
    ) -> Response:
        """Escape hatch for endpoints this library does not wrap yet.

        :param path: path relative to the API root, e.g. ``"user"``
        """
        return self.send(
            Spec(method.upper(), path, params=params or {}, json=json, content=content)
        )

    # -- general APIs -------------------------------------------------------

    def user(self) -> Response:
        """Return license, credits and authorisations for the current key."""
        return self.send(specs.user())

    def search(
        self,
        query: str,
        *,
        page: int = 1,
        size: int | None = None,
        trackquery: bool = False,
        calculated: bool = False,
    ) -> Response:
        """Run an OQL query and return a single page of results.

        :param query: ONYPHE Query Language expression
        :param page: 1-indexed page number
        :param size: results per page, up to 10000
        :param trackquery: ask ONYPHE which sub-query matched each result
        :param calculated: ask ONYPHE for the enriched ``calculated`` fields
        """
        return self.send(
            specs.search(query, page=page, size=size, trackquery=trackquery, calculated=calculated)
        )

    def search_iter(
        self,
        query: str,
        *,
        size: int = 100,
        max_results: int | None = None,
        max_pages: int | None = None,
        trackquery: bool = False,
        calculated: bool = False,
    ) -> Iterator[dict[str, Any]]:
        """Iterate over every result of a query, walking the pages for you.

        :param size: results per page, so ``max_pages`` costs at most
            ``size * max_pages`` documents
        :param max_results: stop after this many documents
        :param max_pages: stop after this many API calls, whichever comes first

        Stops at ``max_results`` or ``max_pages`` when given, at the last page
        ONYPHE reports, and never goes past the 10000 results the Search API is
        willing to serve -- use :meth:`export` beyond that.
        """
        fetched = 0
        pages = 0
        page = 1
        while True:
            response = self.search(
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
    ) -> Iterator[dict[str, Any]]:
        """Stream every document matching an OQL query (Eagle View and above)."""
        return self.stream(specs.export(query, trackquery=trackquery, calculated=calculated))

    def summary(self, kind: SummaryKind, value: str) -> Response:
        """Summary API for an IP, a domain or a hostname."""
        return self.send(specs.summary(kind, value))

    def summary_ip(self, ip: str) -> Response:
        """Shortcut for ``summary("ip", ip)``."""
        return self.summary("ip", ip)

    def summary_domain(self, domain: str) -> Response:
        """Shortcut for ``summary("domain", domain)``."""
        return self.summary("domain", domain)

    def summary_hostname(self, hostname: str) -> Response:
        """Shortcut for ``summary("hostname", hostname)``."""
        return self.summary("hostname", hostname)

    def simple(self, category: SimpleCategory, value: str) -> Response:
        """Simple API. Deprecated upstream, scheduled for removal in APIv3."""
        return self.send(specs.simple(category, value))

    def simple_best(self, category: BestCategory, value: str) -> Response:
        """Best-matching document for an IP in ``geoloc``, ``inetnum``,
        ``threatlist`` or ``whois``."""
        return self.send(specs.simple_best(category, value))

    def simple_datamd5(self, md5: str) -> Response:
        """Datascan documents sharing a ``datamd5`` fingerprint."""
        return self.send(specs.simple_datamd5(md5))

    def resolver_forward(self, value: str) -> Response:
        """Forward DNS records for a domain or hostname."""
        return self.send(specs.simple_resolver_forward(value))

    def resolver_reverse(self, ip: str) -> Response:
        """Reverse DNS records for an IP address."""
        return self.send(specs.simple_resolver_reverse(ip))

    # -- bulk APIs ----------------------------------------------------------

    def bulk_summary(self, kind: SummaryKind, source: BulkSource) -> Iterator[dict[str, Any]]:
        """Bulk Summary API.

        :param source: a file path, a raw newline-separated string, or any
            iterable of assets
        """
        return self.stream(specs.bulk_summary(kind, source))

    def bulk_simple(
        self, category: BulkSimpleCategory, source: BulkSource
    ) -> Iterator[dict[str, Any]]:
        """Bulk Simple API over a list of IP addresses."""
        return self.stream(specs.bulk_simple(category, source))

    def bulk_simple_best(
        self, category: BestCategory, source: BulkSource
    ) -> Iterator[dict[str, Any]]:
        """Bulk Simple Best API over a list of IP addresses."""
        return self.stream(specs.bulk_simple_best(category, source))

    def discovery(self, category: str, source: BulkSource) -> Iterator[dict[str, Any]]:
        """Discovery API: several OQL queries at once (Griffin View only)."""
        return self.stream(specs.discovery(category, source))

    # -- on-demand scope ----------------------------------------------------

    def ondemand_scope_ip(
        self,
        ip: str,
        *,
        import_results: bool | None = None,
        vulnscan: bool | None = None,
        urlscan: bool | None = None,
        ports: Iterable[int] | None = None,
        maxscantime: int | None = None,
    ) -> Response:
        """Launch an active scan of one IP address or CIDR.

        Needs an On-demand subscription. Sent once, never retried: replaying
        the POST would start a second scan.

        :param ip: ``X.Y.Z.K`` or ``X.Y.Z.K/24``
        :param import_results: import the results into the ONYPHE dataset,
            which makes them **PUBLIC** -- visible to every ONYPHE user
        :param vulnscan: also run the vulnerability scan
        :param urlscan: also crawl the HTTP services found
        :param ports: ports to scan instead of the ONYPHE default
        :param maxscantime: scan budget, in seconds
        :returns: the raw envelope, which carries the scan identifier to hand
            to :meth:`ondemand_scope_result`
        """
        return self.send(
            specs.ondemand_scope_ip(
                ip,
                import_results=import_results,
                vulnscan=vulnscan,
                urlscan=urlscan,
                ports=ports,
                maxscantime=maxscantime,
            ),
            retry=False,
        )

    def ondemand_scope_domain(
        self,
        domain: str,
        *,
        import_results: bool | None = None,
        vulnscan: bool | None = None,
        urlscan: bool | None = None,
        ports: Iterable[int] | None = None,
        maxscantime: int | None = None,
    ) -> Response:
        """Launch an active scan of one domain.

        Needs an On-demand subscription. Options are the ones of
        :meth:`ondemand_scope_ip`, ``import_results`` included: it makes the
        results **PUBLIC** on ONYPHE.
        """
        return self.send(
            specs.ondemand_scope_domain(
                domain,
                import_results=import_results,
                vulnscan=vulnscan,
                urlscan=urlscan,
                ports=ports,
                maxscantime=maxscantime,
            ),
            retry=False,
        )

    def ondemand_scope_ip_bulk(
        self,
        ips: Iterable[str],
        *,
        import_results: bool | None = None,
        vulnscan: bool | None = None,
        urlscan: bool | None = None,
        ports: Iterable[int] | None = None,
        maxscantime: int | None = None,
    ) -> Response:
        """Launch one active scan covering several IP addresses or CIDRs.

        Needs an On-demand subscription. Served from the ``/dev/`` prefix, so
        ONYPHE may still move it. Options are the ones of
        :meth:`ondemand_scope_ip`, ``import_results`` included: it makes the
        results **PUBLIC** on ONYPHE.

        :param ips: any iterable of assets; joined with commas for you
        """
        return self.send(
            specs.ondemand_scope_ip_bulk(
                ips,
                import_results=import_results,
                vulnscan=vulnscan,
                urlscan=urlscan,
                ports=ports,
                maxscantime=maxscantime,
            ),
            retry=False,
        )

    def ondemand_scope_domain_bulk(
        self,
        domains: Iterable[str],
        *,
        import_results: bool | None = None,
        vulnscan: bool | None = None,
        urlscan: bool | None = None,
        ports: Iterable[int] | None = None,
        maxscantime: int | None = None,
    ) -> Response:
        """Launch one active scan covering several domains.

        Needs an On-demand subscription. Served from the ``/dev/`` prefix, so
        ONYPHE may still move it. Options are the ones of
        :meth:`ondemand_scope_ip`, ``import_results`` included: it makes the
        results **PUBLIC** on ONYPHE.

        :param domains: any iterable of domains; joined with commas for you
        """
        return self.send(
            specs.ondemand_scope_domain_bulk(
                domains,
                import_results=import_results,
                vulnscan=vulnscan,
                urlscan=urlscan,
                ports=ports,
                maxscantime=maxscantime,
            ),
            retry=False,
        )

    def ondemand_scope_result(self, scan_id: str) -> Response:
        """Fetch the results of a scan launched earlier.

        :param scan_id: identifier returned when the scan was launched
        :raises ScanInProgressError: while the scan runs or its results are
            being built -- retry later, nothing failed
        """
        try:
            response = self.send(specs.ondemand_scope_result(scan_id))
        except APIError as exc:
            self.raise_for_scan(scan_id, exc.payload, status_code=exc.status_code)
            raise
        self.raise_for_scan(scan_id, response.model_dump())
        return response

    # -- alerts -------------------------------------------------------------

    def alerts(self) -> list[Alert]:
        """List the alerts configured on the account."""
        response = self.send(specs.alert_list())
        return [Alert.model_validate(item) for item in response.results]

    def add_alert(self, name: str, query: str, email: str, threshold: str = ">0") -> Response:
        """Create an alert triggered when the daily count matches ``threshold``."""
        return self.send(specs.alert_add(name, query, email, threshold))

    def del_alert(self, alert_id: int | str) -> Response:
        """Delete an alert by identifier."""
        return self.send(specs.alert_del(alert_id))
