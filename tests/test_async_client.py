"""The async client must behave exactly like the sync one."""

from __future__ import annotations

import httpx
import pytest
import respx

from pyonyphe import AsyncOnyphe
from pyonyphe.errors import AuthenticationError, ServerError, TransportError

from .conftest import API_KEY, BASE, envelope


@respx.mock
async def test_search(async_client: AsyncOnyphe) -> None:
    route = respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"ip": "8.8.8.8"}], total=12))
    )
    async with async_client as client:
        response = await client.search("protocol:ssh")
    assert response.total == 12
    assert route.calls.last.request.headers["Authorization"] == f"bearer {API_KEY}"


@respx.mock
async def test_search_iter(async_client: AsyncOnyphe) -> None:
    respx.get(f"{BASE}/search/").mock(
        side_effect=[
            httpx.Response(200, json=envelope([{"n": 1}], max_page=2, page=1)),
            httpx.Response(200, json=envelope([{"n": 2}], max_page=2, page=2)),
        ]
    )
    seen = []
    async with async_client as client:
        async for hit in client.search_iter("x", size=1):
            seen.append(hit["n"])
    assert seen == [1, 2]


@respx.mock
async def test_export_streams(async_client: AsyncOnyphe) -> None:
    respx.get(f"{BASE}/export/").mock(
        return_value=httpx.Response(200, text='{"ip":"1.1.1.1"}\n{"ip":"8.8.8.8"}\n')
    )
    seen = []
    async with async_client as client:
        async for row in client.export("domain:example.com"):
            seen.append(row["ip"])
    assert seen == ["1.1.1.1", "8.8.8.8"]


@respx.mock
async def test_bulk_summary(async_client: AsyncOnyphe) -> None:
    route = respx.post(f"{BASE}/bulk/summary/ip").mock(
        return_value=httpx.Response(200, text='{"ip":"1.1.1.1"}\n')
    )
    async with async_client as client:
        rows = [row async for row in client.bulk_summary("ip", ["1.1.1.1"])]
    assert rows == [{"ip": "1.1.1.1"}]
    assert route.calls.last.request.content == b"1.1.1.1\n"


@respx.mock
async def test_errors_are_shared(async_client: AsyncOnyphe) -> None:
    respx.get(f"{BASE}/user").mock(return_value=httpx.Response(403, json={"text": "nope"}))
    async with async_client as client:
        with pytest.raises(AuthenticationError):
            await client.user()


@respx.mock
async def test_transport_failure(async_client: AsyncOnyphe) -> None:
    respx.get(f"{BASE}/user").mock(side_effect=httpx.ConnectError("boom"))
    async with async_client as client:
        with pytest.raises(TransportError):
            await client.user()


@respx.mock
async def test_retries_a_rate_limit_then_succeeds() -> None:
    route = respx.get(f"{BASE}/user").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}, json={"text": "slow down"}),
            httpx.Response(200, json=envelope([{"ok": True}])),
        ]
    )
    async with AsyncOnyphe(API_KEY, max_retries=2, backoff=0.0) as client:
        response = await client.user()
    assert response.results == [{"ok": True}]
    assert route.call_count == 2


@respx.mock
async def test_gives_up_after_max_retries() -> None:
    route = respx.get(f"{BASE}/user").mock(return_value=httpx.Response(503, json={"text": "busy"}))
    async with AsyncOnyphe(API_KEY, max_retries=2, backoff=0.0) as client:
        with pytest.raises(ServerError):
            await client.user()
    assert route.call_count == 3  # the initial attempt plus two retries
