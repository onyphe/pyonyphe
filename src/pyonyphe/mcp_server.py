"""MCP server exposing ONYPHE to an LLM client.

Installed as an optional extra::

    uv add 'pyonyphe[mcp]'
    pyonyphe-mcp

The module is named ``mcp_server`` rather than ``mcp`` so that it never
shadows the ``mcp`` SDK package it imports.

Deliberate restrictions, because an assistant driving this server spends real
API credits and fills a context window:

- only the read-only, low-volume endpoints are exposed; ``export`` and the
  bulk APIs stream thousands of documents and have no place in a conversation
- ``size`` and ``max_pages`` are clamped, so a loop cannot drain the account
- long string fields are truncated: a single datascan document carries up to
  16 KB in its ``data`` field
"""

from __future__ import annotations

import os
from typing import Any, cast

from mcp.server.mcpserver import MCPServer

from . import __version__
from ._specs import SummaryKind
from .async_client import AsyncOnyphe
from .errors import OnypheError

__all__ = ["main", "server"]

#: Hard ceilings applied to whatever the model asks for.
MAX_SIZE = 100
MAX_PAGES = 5
#: Truncation applied per document before returning it.
MAX_FIELD_CHARS = 500
MAX_LIST_ITEMS = 20

server = MCPServer(
    "pyonyphe",
    # Everything but the name is keyword-only on purpose: the second
    # positional parameter is `title` in SDK v2, so a positional string here
    # would silently land there instead of in `instructions`.
    version=__version__,
    instructions=(
        "Query ONYPHE, a cyber defence search engine, for internet-wide scan "
        "data: open services, TLS certificates, DNS records, threat lists and "
        "vulnerability findings. Use ONYPHE Query Language (OQL) with the "
        "search tool, for example 'category:datascan product:Nginx "
        "country:FR'. Every call consumes API credits, so prefer a narrow "
        "query over a broad one, and check the remaining credits with the "
        "user tool when unsure."
    ),
)

_client: AsyncOnyphe | None = None


def _get_client() -> AsyncOnyphe:
    """Return the shared client, built on first use."""
    global _client
    if _client is None:
        _client = AsyncOnyphe(os.environ.get("ONYPHE_API_KEY"))
    return _client


def _trim(document: dict[str, Any]) -> dict[str, Any]:
    """Shorten the fields that would otherwise flood the context window."""
    trimmed: dict[str, Any] = {}
    for key, value in document.items():
        if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
            dropped = len(value) - MAX_FIELD_CHARS
            trimmed[key] = f"{value[:MAX_FIELD_CHARS]}... (+{dropped} more characters)"
        elif isinstance(value, list) and len(value) > MAX_LIST_ITEMS:
            rest = len(value) - MAX_LIST_ITEMS
            trimmed[key] = [*value[:MAX_LIST_ITEMS], f"... (+{rest} more items)"]
        else:
            trimmed[key] = value
    return trimmed


def _clamp(value: int, ceiling: int) -> int:
    return max(1, min(value, ceiling))


def _failure(exc: OnypheError) -> dict[str, Any]:
    """Turn an exception into something the model can act on."""
    return {"error": str(exc), "type": type(exc).__name__}


@server.tool()
async def search(query: str, size: int = 20, max_pages: int = 1) -> dict[str, Any]:
    """Search ONYPHE with an OQL expression.

    :param query: ONYPHE Query Language, e.g. ``category:datascan
        product:Nginx country:FR``. A bare domain, hostname or port is
        rewritten to the matching filter automatically.
    :param size: documents per page, capped at 100
    :param max_pages: how many pages to walk, capped at 5
    :returns: the matching documents, with a ``total`` count that covers the
        whole result set, not just what was returned
    """
    size = _clamp(size, MAX_SIZE)
    max_pages = _clamp(max_pages, MAX_PAGES)
    client = _get_client()
    try:
        first = await client.search(query, page=1, size=size)
        documents = list(first.results)
        page = 2
        while page <= max_pages:
            if first.max_page is not None and page > first.max_page:
                break
            more = await client.search(query, page=page, size=size)
            if not more.results:
                break
            documents.extend(more.results)
            page += 1
    except OnypheError as exc:
        return _failure(exc)
    return {
        "query": query,
        "total": first.total,
        "returned": len(documents),
        "results": [_trim(document) for document in documents],
    }


@server.tool()
async def summary(kind: str, value: str) -> dict[str, Any]:
    """Everything ONYPHE knows about one asset, across every category.

    :param kind: ``ip``, ``domain`` or ``hostname``
    :param value: the asset itself, e.g. ``8.8.8.8`` or ``example.com``
    """
    client = _get_client()
    try:
        response = await client.summary(cast(SummaryKind, kind), value)
    except OnypheError as exc:
        return _failure(exc)
    return {
        "kind": kind,
        "value": value,
        "total": response.total,
        "results": [_trim(document) for document in response.results],
    }


@server.tool()
async def resolve(value: str, reverse: bool = False) -> dict[str, Any]:
    """DNS records ONYPHE has observed for a domain, hostname or IP.

    :param value: a domain or hostname for a forward lookup, an IP address
        when ``reverse`` is true
    :param reverse: look up the names pointing at an IP instead
    """
    client = _get_client()
    try:
        response = (
            await client.resolver_reverse(value)
            if reverse
            else await client.resolver_forward(value)
        )
    except OnypheError as exc:
        return _failure(exc)
    return {
        "value": value,
        "direction": "reverse" if reverse else "forward",
        "total": response.total,
        "results": [_trim(document) for document in response.results],
    }


@server.tool()
async def user() -> dict[str, Any]:
    """License details and remaining API credits for the configured key.

    Cheap to call, and worth checking before running a broad search.
    """
    client = _get_client()
    try:
        response = await client.user()
    except OnypheError as exc:
        return _failure(exc)
    return {"results": [_trim(document) for document in response.results]}


def main() -> None:
    """Console-script entry point: serve over stdio."""
    server.run()


if __name__ == "__main__":  # pragma: no cover
    main()
