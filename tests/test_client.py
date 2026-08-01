"""Synchronous client behaviour, against a mocked ONYPHE."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from pyonyphe import Onyphe
from pyonyphe.errors import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    TransportError,
)

from .conftest import API_KEY, BASE, envelope


@respx.mock
def test_bearer_authentication(client: Onyphe) -> None:
    route = respx.get(f"{BASE}/user").mock(return_value=httpx.Response(200, json=envelope()))
    client.user()
    request = route.calls.last.request
    assert request.headers["Authorization"] == f"bearer {API_KEY}"
    assert "apikey" not in str(request.url)


@respx.mock
def test_unrated_uses_basic_auth_and_k_parameter() -> None:
    with Onyphe(API_KEY, unrated_email="user@example.com", max_retries=0) as client:
        url = f"{client.base_url}/user"
        route = respx.get(url).mock(return_value=httpx.Response(200, json=envelope()))
        client.user()
    request = route.calls.last.request
    expected = base64.b64encode(f"user_example.com:{API_KEY}".encode()).decode()
    assert request.headers["Authorization"] == f"basic {expected}"
    assert request.url.params["k"] == API_KEY


@respx.mock
def test_search_returns_the_envelope(client: Onyphe) -> None:
    payload = envelope([{"ip": "8.8.8.8"}], total=445, max_page=5, page=1, page_size=100)
    route = respx.get(f"{BASE}/search/").mock(return_value=httpx.Response(200, json=payload))
    response = client.search("protocol:rdp", page=1, size=10)
    assert response.total == 445
    assert response.results[0]["ip"] == "8.8.8.8"
    assert response.took == pytest.approx(0.010)
    assert route.calls.last.request.url.params["q"] == "protocol:rdp"


@respx.mock
def test_response_is_iterable(client: Onyphe) -> None:
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"ip": "1.1.1.1"}]))
    )
    response = client.search("x")
    assert [hit["ip"] for hit in response] == ["1.1.1.1"]
    assert len(response) == 1


@respx.mock
def test_search_iter_walks_pages(client: Onyphe) -> None:
    pages = [
        httpx.Response(200, json=envelope([{"n": 1}, {"n": 2}], max_page=2, page=1)),
        httpx.Response(200, json=envelope([{"n": 3}], max_page=2, page=2)),
    ]
    respx.get(f"{BASE}/search/").mock(side_effect=pages)
    assert [hit["n"] for hit in client.search_iter("x", size=2)] == [1, 2, 3]


@respx.mock
def test_search_iter_honours_max_results(client: Onyphe) -> None:
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"n": 1}, {"n": 2}], max_page=9))
    )
    assert len(list(client.search_iter("x", max_results=1))) == 1


@respx.mock
def test_export_yields_ndjson(client: Onyphe) -> None:
    body = '{"ip":"1.1.1.1"}\n\n{"ip":"8.8.8.8"}\n'
    respx.get(f"{BASE}/export/").mock(return_value=httpx.Response(200, text=body))
    assert [row["ip"] for row in client.export("domain:example.com")] == ["1.1.1.1", "8.8.8.8"]


@respx.mock
def test_bulk_simple_posts_the_asset_list(client: Onyphe) -> None:
    route = respx.post(f"{BASE}/bulk/simple/datascan/ip").mock(
        return_value=httpx.Response(200, text='{"ip":"1.1.1.1"}\n')
    )
    rows = list(client.bulk_simple("datascan", ["1.1.1.1", "8.8.8.8"]))
    assert rows == [{"ip": "1.1.1.1"}]
    assert route.calls.last.request.content == b"1.1.1.1\n8.8.8.8\n"


@respx.mock
def test_alerts_are_parsed(client: Onyphe) -> None:
    payload = envelope(
        [{"id": 0, "name": "My alert", "query": "domain:x", "email": "a@b.tld", "threshold": ">0"}]
    )
    respx.get(f"{BASE}/alert/list").mock(return_value=httpx.Response(200, json=payload))
    alerts = client.alerts()
    assert alerts[0].threshold == ">0"
    assert alerts[0].name == "My alert"


@respx.mock
def test_add_alert_sends_a_json_body(client: Onyphe) -> None:
    route = respx.post(f"{BASE}/alert/add").mock(return_value=httpx.Response(200, json=envelope()))
    client.add_alert("n", "category:vulnscan domain:x", "a@b.tld", ">2")
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "name": "n",
        "query": "category:vulnscan domain:x",
        "email": "a@b.tld",
        "threshold": ">2",
    }


@respx.mock
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (403, AuthenticationError),
        (404, NotFoundError),
        (500, ServerError),
    ],
)
def test_status_codes_map_to_exceptions(
    client: Onyphe, status: int, expected: type[Exception]
) -> None:
    respx.get(f"{BASE}/user").mock(
        return_value=httpx.Response(status, json={"text": "nope", "error": 1})
    )
    with pytest.raises(expected) as info:
        client.user()
    assert "nope" in str(info.value)


@respx.mock
def test_rate_limit_exposes_retry_after(client: Onyphe) -> None:
    respx.get(f"{BASE}/user").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "7"}, json={"text": "slow down"})
    )
    with pytest.raises(RateLimitError) as info:
        client.user()
    assert info.value.retry_after == 7.0


@respx.mock
def test_retries_then_succeeds() -> None:
    with Onyphe(API_KEY, max_retries=2, backoff=0.0) as client:
        respx.get(f"{BASE}/user").mock(
            side_effect=[
                httpx.Response(503, json={"text": "busy"}),
                httpx.Response(200, json=envelope([{"ok": True}])),
            ]
        )
        assert client.user().results == [{"ok": True}]


@respx.mock
def test_transport_failure_is_wrapped(client: Onyphe) -> None:
    respx.get(f"{BASE}/user").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(TransportError):
        client.user()


@respx.mock
def test_streaming_error_is_raised_before_iteration(client: Onyphe) -> None:
    respx.get(f"{BASE}/export/").mock(
        return_value=httpx.Response(403, json={"text": "no export for you"})
    )
    with pytest.raises(AuthenticationError):
        list(client.export("x"))


@respx.mock
def test_request_escape_hatch(client: Onyphe) -> None:
    route = respx.get(f"{BASE}/some/new/endpoint").mock(
        return_value=httpx.Response(200, json=envelope())
    )
    client.request("GET", "some/new/endpoint", params={"a": "b"})
    assert route.calls.last.request.url.params["a"] == "b"
