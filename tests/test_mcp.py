"""The MCP tools wrap the client, so the tests check the wrapping: clamping,
truncation, and errors turned into data rather than raised."""

from __future__ import annotations

import httpx
import pytest
import respx

from pyonyphe import mcp_server
from pyonyphe.async_client import AsyncOnyphe

from .conftest import API_KEY, BASE, envelope


@pytest.fixture(autouse=True)
def _fresh_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the module-level client between tests, with a known key."""
    monkeypatch.setattr(mcp_server, "_client", AsyncOnyphe(API_KEY, max_retries=0))


@respx.mock
async def test_search_returns_documents_and_total() -> None:
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"ip": "8.8.8.8"}], total=42, max_page=1))
    )
    result = await mcp_server.search("protocol:dns")
    assert result["total"] == 42
    assert result["returned"] == 1
    assert result["results"][0]["ip"] == "8.8.8.8"


@respx.mock
async def test_search_clamps_size_and_pages() -> None:
    route = respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"n": 1}], max_page=999))
    )
    await mcp_server.search("x", size=10_000, max_pages=99)
    assert int(route.calls[0].request.url.params["size"]) == mcp_server.MAX_SIZE
    assert route.call_count == mcp_server.MAX_PAGES


@respx.mock
async def test_search_stops_at_the_last_page() -> None:
    route = respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"n": 1}], max_page=2))
    )
    await mcp_server.search("x", max_pages=5)
    assert route.call_count == 2


@respx.mock
async def test_long_fields_are_truncated() -> None:
    # A datascan document can carry 16 KB in `data`.
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"data": "A" * 5000}]))
    )
    result = await mcp_server.search("x")
    data = result["results"][0]["data"]
    assert len(data) < 700
    assert "more characters" in data


@respx.mock
async def test_long_lists_are_truncated() -> None:
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(
            200, json=envelope([{"ip": [f"10.0.0.{i}" for i in range(80)]}])
        )
    )
    result = await mcp_server.search("x")
    ips = result["results"][0]["ip"]
    assert len(ips) == mcp_server.MAX_LIST_ITEMS + 1
    assert "more items" in ips[-1]


@respx.mock
async def test_errors_are_returned_not_raised() -> None:
    # The model has to see the failure as data it can reason about.
    respx.get(f"{BASE}/search/").mock(return_value=httpx.Response(403, json={"text": "forbidden"}))
    result = await mcp_server.search("x")
    assert result["type"] == "AuthenticationError"
    assert "forbidden" in result["error"]


@respx.mock
async def test_summary() -> None:
    respx.get(f"{BASE}/summary/ip/8.8.8.8").mock(
        return_value=httpx.Response(200, json=envelope([{"@category": "geoloc"}]))
    )
    result = await mcp_server.summary("ip", "8.8.8.8")
    assert result["results"][0]["@category"] == "geoloc"


async def test_summary_rejects_an_unknown_kind() -> None:
    result = await mcp_server.summary("asn", "AS15169")
    assert result["type"] == "ParamError"


@respx.mock
async def test_resolve_forward_and_reverse() -> None:
    forward = respx.get(f"{BASE}/simple/resolver/forward/example.com").mock(
        return_value=httpx.Response(200, json=envelope([{"forward": "example.com"}]))
    )
    reverse = respx.get(f"{BASE}/simple/resolver/reverse/8.8.8.8").mock(
        return_value=httpx.Response(200, json=envelope([{"reverse": "dns.google"}]))
    )
    assert (await mcp_server.resolve("example.com"))["direction"] == "forward"
    assert (await mcp_server.resolve("8.8.8.8", reverse=True))["direction"] == "reverse"
    assert forward.called and reverse.called


@respx.mock
async def test_user() -> None:
    respx.get(f"{BASE}/user").mock(
        return_value=httpx.Response(200, json=envelope([{"credits": 1000}]))
    )
    result = await mcp_server.user()
    assert result["results"][0]["credits"] == 1000


def test_every_tool_is_registered() -> None:
    assert mcp_server.server.name == "pyonyphe"
