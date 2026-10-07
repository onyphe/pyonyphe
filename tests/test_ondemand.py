"""On-demand scope API: specs, both clients, and the CLI.

No integration test here: the feature needs an On-demand subscription, and a
scan costs credits and touches third-party hosts.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from pyonyphe import AsyncOnyphe, Onyphe, _specs as specs
from pyonyphe.cli import app
from pyonyphe.errors import (
    NotFoundError,
    ParamError,
    RateLimitError,
    ScanInProgressError,
    ServerError,
    TransportError,
)

from .conftest import API_KEY, BASE, envelope

runner = CliRunner()

SINGLE_IP = f"{BASE}/ondemand/scope/ip/single"
SINGLE_DOMAIN = f"{BASE}/ondemand/scope/domain/single"
BULK_IP = f"{BASE}/dev/ondemand/scope/ip/bulk"
BULK_DOMAIN = f"{BASE}/dev/ondemand/scope/domain/bulk"
RESULT = f"{BASE}/ondemand/scope/result/abc123"

#: The four launch endpoints, with the call that reaches each of them.
LAUNCHES = [
    (SINGLE_IP, lambda client: client.ondemand_scope_ip("8.8.8.8")),
    (SINGLE_DOMAIN, lambda client: client.ondemand_scope_domain("example.com")),
    (BULK_IP, lambda client: client.ondemand_scope_ip_bulk(["8.8.8.8"])),
    (BULK_DOMAIN, lambda client: client.ondemand_scope_domain_bulk(["a.tld"])),
]


def launched(scan_id: str = "abc123") -> dict[str, object]:
    """Envelope of a successful launch. ONYPHE does not document the field
    name carrying the scan id, hence the raw passthrough."""
    return envelope(text="Success", scan_id=scan_id)


# -- specs -----------------------------------------------------------------


def test_single_paths() -> None:
    assert specs.ondemand_scope_ip("8.8.8.8").path == "ondemand/scope/ip/single"
    assert specs.ondemand_scope_domain("example.com").path == "ondemand/scope/domain/single"


def test_bulk_paths_live_under_the_dev_prefix() -> None:
    assert specs.ondemand_scope_ip_bulk(["8.8.8.8"]).path == "dev/ondemand/scope/ip/bulk"
    assert specs.ondemand_scope_domain_bulk(["a.tld"]).path == "dev/ondemand/scope/domain/bulk"
    assert specs.DEV_PREFIX == "dev"


def test_result_path_carries_the_scan_id() -> None:
    spec = specs.ondemand_scope_result("abc123")
    assert spec.method == "GET"
    assert spec.path == "ondemand/scope/result/abc123"


def test_single_body_is_posted_as_json() -> None:
    spec = specs.ondemand_scope_ip("8.8.8.0/24")
    assert spec.method == "POST"
    assert spec.json == {"ip": "8.8.8.0/24"}
    assert spec.content is None
    assert spec.stream is False


def test_options_are_serialised_the_way_onyphe_wants_them() -> None:
    spec = specs.ondemand_scope_ip(
        "8.8.8.8",
        import_results=True,
        vulnscan=True,
        urlscan=False,
        ports=[80, 443],
        maxscantime=120,
    )
    assert spec.json == {
        "ip": "8.8.8.8",
        "import": "true",
        "vulnscan": "true",
        "urlscan": "false",
        "ports": "80,443",
        "maxscantime": 120,
    }


def test_options_left_out_are_not_sent() -> None:
    assert specs.ondemand_scope_domain("example.com").json == {"domain": "example.com"}


def test_false_is_sent_explicitly_when_asked_for() -> None:
    # None means "say nothing"; False means "say false".
    spec = specs.ondemand_scope_ip("8.8.8.8", import_results=False)
    assert spec.json == {"ip": "8.8.8.8", "import": "false"}


def test_bulk_joins_the_targets_with_commas() -> None:
    spec = specs.ondemand_scope_ip_bulk(["1.1.1.1", " 8.8.8.8 ", "", "10.0.0.0/24"])
    assert spec.json == {"ip": "1.1.1.1,8.8.8.8,10.0.0.0/24"}


def test_bulk_accepts_any_iterable() -> None:
    spec = specs.ondemand_scope_domain_bulk(iter(("a.tld", "b.tld")))
    assert spec.json == {"domain": "a.tld,b.tld"}


def test_bulk_does_not_split_a_bare_string() -> None:
    assert specs.ondemand_scope_ip_bulk("1.1.1.1").json == {"ip": "1.1.1.1"}


def test_bulk_rejects_an_empty_list() -> None:
    with pytest.raises(ParamError):
        specs.ondemand_scope_ip_bulk([])


@pytest.mark.parametrize(
    "call",
    [
        lambda: specs.ondemand_scope_ip(""),
        lambda: specs.ondemand_scope_domain(""),
        lambda: specs.ondemand_scope_result(""),
    ],
)
def test_empty_target_is_rejected_before_any_request(call: Callable[[], object]) -> None:
    with pytest.raises(ParamError):
        call()


# -- sync client -----------------------------------------------------------


@respx.mock
def test_scan_ip_posts_the_json_body(client: Onyphe) -> None:
    route = respx.post(SINGLE_IP).mock(return_value=httpx.Response(200, json=launched()))
    response = client.ondemand_scope_ip("8.8.8.8", vulnscan=True, ports=[80, 443])
    request = route.calls.last.request
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["Authorization"] == f"bearer {API_KEY}"
    assert json.loads(request.content) == {
        "ip": "8.8.8.8",
        "vulnscan": "true",
        "ports": "80,443",
    }
    # The scan id is handed back untouched: ONYPHE does not document its name.
    assert response.model_dump()["scan_id"] == "abc123"


@respx.mock
def test_scan_domain_posts_the_json_body(client: Onyphe) -> None:
    route = respx.post(SINGLE_DOMAIN).mock(return_value=httpx.Response(200, json=launched()))
    client.ondemand_scope_domain("example.com", import_results=True)
    assert json.loads(route.calls.last.request.content) == {
        "domain": "example.com",
        "import": "true",
    }


@respx.mock
def test_scan_ip_bulk_joins_and_uses_the_dev_prefix(client: Onyphe) -> None:
    route = respx.post(BULK_IP).mock(return_value=httpx.Response(200, json=launched()))
    client.ondemand_scope_ip_bulk(["1.1.1.1", "8.8.8.8", "10.0.0.0/24"], maxscantime=60)
    assert json.loads(route.calls.last.request.content) == {
        "ip": "1.1.1.1,8.8.8.8,10.0.0.0/24",
        "maxscantime": 60,
    }


@respx.mock
def test_scan_domain_bulk_joins_and_uses_the_dev_prefix(client: Onyphe) -> None:
    route = respx.post(BULK_DOMAIN).mock(return_value=httpx.Response(200, json=launched()))
    client.ondemand_scope_domain_bulk(["a.tld", "b.tld"])
    assert json.loads(route.calls.last.request.content) == {"domain": "a.tld,b.tld"}


@respx.mock
def test_result_returns_the_envelope(client: Onyphe) -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(200, json=envelope([{"ip": "8.8.8.8", "port": 443}]))
    )
    response = client.ondemand_scope_result("abc123")
    assert response.results[0]["port"] == 443


@respx.mock
@pytest.mark.parametrize("code", [103, 111])
def test_result_in_progress_on_a_2xx_body(client: Onyphe, code: int) -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(200, json={"error": code, "text": "Scan ID is in progress"})
    )
    with pytest.raises(ScanInProgressError) as info:
        client.ondemand_scope_result("abc123")
    assert info.value.scan_id == "abc123"
    assert "in progress" in str(info.value)


@respx.mock
@pytest.mark.parametrize("code", [103, 111])
def test_result_in_progress_on_an_error_status(client: Onyphe, code: int) -> None:
    # Same two codes, this time carried by a non-2xx answer: still not a failure.
    respx.get(RESULT).mock(
        return_value=httpx.Response(404, json={"error": code, "text": "results being built"})
    )
    with pytest.raises(ScanInProgressError) as info:
        client.ondemand_scope_result("abc123")
    assert info.value.scan_id == "abc123"
    assert info.value.status_code == 404


@respx.mock
def test_other_error_codes_keep_the_existing_mapping(client: Onyphe) -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(404, json={"error": 100, "text": "no such scan"})
    )
    with pytest.raises(NotFoundError):
        client.ondemand_scope_result("abc123")


# -- launches are never replayed -------------------------------------------


@respx.mock
@pytest.mark.parametrize(("url", "launch"), LAUNCHES)
def test_launch_is_not_replayed_on_a_server_error(
    url: str, launch: Callable[[Onyphe], object]
) -> None:
    # Replaying a POST would start a second scan and burn credits.
    route = respx.post(url).mock(return_value=httpx.Response(502, json={"text": "bad gateway"}))
    with (
        Onyphe(API_KEY, max_retries=3, backoff=0.0) as client,
        pytest.raises(ServerError),
    ):
        launch(client)
    assert route.call_count == 1


@respx.mock
def test_launch_is_not_replayed_on_a_rate_limit() -> None:
    route = respx.post(SINGLE_IP).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"}, json={"text": "slow down"})
    )
    with (
        Onyphe(API_KEY, max_retries=3, backoff=0.0) as client,
        pytest.raises(RateLimitError),
    ):
        client.ondemand_scope_ip("8.8.8.8")
    assert route.call_count == 1


@respx.mock
def test_launch_is_not_replayed_on_a_transport_failure() -> None:
    # The scan may well have started: ONYPHE just never got to answer.
    route = respx.post(SINGLE_IP).mock(side_effect=httpx.ConnectError("boom"))
    with (
        Onyphe(API_KEY, max_retries=3, backoff=0.0) as client,
        pytest.raises(TransportError),
    ):
        client.ondemand_scope_ip("8.8.8.8")
    assert route.call_count == 1


@respx.mock
def test_result_is_still_replayed() -> None:
    route = respx.get(RESULT).mock(
        side_effect=[
            httpx.Response(502, json={"text": "bad gateway"}),
            httpx.Response(200, json=envelope([{"ip": "8.8.8.8"}])),
        ]
    )
    with Onyphe(API_KEY, max_retries=3, backoff=0.0) as client:
        response = client.ondemand_scope_result("abc123")
    assert response.results == [{"ip": "8.8.8.8"}]
    assert route.call_count == 2


# -- async client ----------------------------------------------------------


@respx.mock
async def test_async_scan_ip(async_client: AsyncOnyphe) -> None:
    route = respx.post(SINGLE_IP).mock(return_value=httpx.Response(200, json=launched()))
    async with async_client as client:
        await client.ondemand_scope_ip("8.8.8.8", import_results=False, urlscan=True)
    assert json.loads(route.calls.last.request.content) == {
        "ip": "8.8.8.8",
        "import": "false",
        "urlscan": "true",
    }


@respx.mock
async def test_async_scan_domain_bulk(async_client: AsyncOnyphe) -> None:
    route = respx.post(BULK_DOMAIN).mock(return_value=httpx.Response(200, json=launched()))
    async with async_client as client:
        await client.ondemand_scope_domain_bulk(["a.tld", "b.tld"], ports=[80])
    assert route.calls.last.request.url.path == "/api/v2/dev/ondemand/scope/domain/bulk"
    assert json.loads(route.calls.last.request.content) == {
        "domain": "a.tld,b.tld",
        "ports": "80",
    }


@respx.mock
async def test_async_result(async_client: AsyncOnyphe) -> None:
    respx.get(RESULT).mock(return_value=httpx.Response(200, json=envelope([{"ip": "8.8.8.8"}])))
    async with async_client as client:
        response = await client.ondemand_scope_result("abc123")
    assert response.results == [{"ip": "8.8.8.8"}]


@respx.mock
@pytest.mark.parametrize("code", [103, 111])
async def test_async_result_in_progress(async_client: AsyncOnyphe, code: int) -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(200, json={"error": code, "text": "being built"})
    )
    async with async_client as client:
        with pytest.raises(ScanInProgressError) as info:
            await client.ondemand_scope_result("abc123")
    assert info.value.scan_id == "abc123"


@respx.mock
async def test_async_launch_is_not_replayed_on_a_server_error() -> None:
    route = respx.post(BULK_IP).mock(return_value=httpx.Response(502, json={"text": "bad gateway"}))
    async with AsyncOnyphe(API_KEY, max_retries=3, backoff=0.0) as client:
        with pytest.raises(ServerError):
            await client.ondemand_scope_ip_bulk(["8.8.8.8"])
    assert route.call_count == 1


@respx.mock
async def test_async_launch_is_not_replayed_on_a_rate_limit() -> None:
    route = respx.post(SINGLE_DOMAIN).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"}, json={"text": "slow down"})
    )
    async with AsyncOnyphe(API_KEY, max_retries=3, backoff=0.0) as client:
        with pytest.raises(RateLimitError):
            await client.ondemand_scope_domain("example.com")
    assert route.call_count == 1


@respx.mock
async def test_async_launch_is_not_replayed_on_a_transport_failure() -> None:
    route = respx.post(SINGLE_IP).mock(side_effect=httpx.ConnectError("boom"))
    async with AsyncOnyphe(API_KEY, max_retries=3, backoff=0.0) as client:
        with pytest.raises(TransportError):
            await client.ondemand_scope_ip("8.8.8.8")
    assert route.call_count == 1


@respx.mock
async def test_async_result_is_still_replayed() -> None:
    route = respx.get(RESULT).mock(
        side_effect=[
            httpx.Response(502, json={"text": "bad gateway"}),
            httpx.Response(200, json=envelope([{"ip": "8.8.8.8"}])),
        ]
    )
    async with AsyncOnyphe(API_KEY, max_retries=3, backoff=0.0) as client:
        response = await client.ondemand_scope_result("abc123")
    assert response.results == [{"ip": "8.8.8.8"}]
    assert route.call_count == 2


# -- CLI -------------------------------------------------------------------


@respx.mock
def test_cli_ip_passes_every_option() -> None:
    route = respx.post(SINGLE_IP).mock(return_value=httpx.Response(200, json=launched()))
    result = runner.invoke(
        app,
        [
            "--api-key",
            API_KEY,
            "ondemand",
            "ip",
            "8.8.8.0/24",
            "--import",
            "--no-vulnscan",
            "--urlscan",
            "--ports",
            "80,443",
            "--maxscantime",
            "120",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content) == {
        "ip": "8.8.8.0/24",
        "import": "true",
        "vulnscan": "false",
        "urlscan": "true",
        "ports": "80,443",
        "maxscantime": 120,
    }
    assert "abc123" in result.stdout


@respx.mock
def test_cli_ip_sends_no_option_by_default() -> None:
    route = respx.post(SINGLE_IP).mock(return_value=httpx.Response(200, json=launched()))
    result = runner.invoke(app, ["--api-key", API_KEY, "ondemand", "ip", "8.8.8.8"])
    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content) == {"ip": "8.8.8.8"}


@respx.mock
def test_cli_domain() -> None:
    route = respx.post(SINGLE_DOMAIN).mock(return_value=httpx.Response(200, json=launched()))
    result = runner.invoke(
        app, ["--api-key", API_KEY, "ondemand", "domain", "example.com", "--no-import"]
    )
    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content) == {
        "domain": "example.com",
        "import": "false",
    }


@respx.mock
def test_cli_ip_bulk_reads_one_target_per_line(tmp_path: Path) -> None:
    targets = tmp_path / "ips.txt"
    targets.write_text("1.1.1.1\n\n 8.8.8.8 \n10.0.0.0/24\n", encoding="utf-8")
    route = respx.post(BULK_IP).mock(return_value=httpx.Response(200, json=launched()))
    result = runner.invoke(
        app, ["--api-key", API_KEY, "ondemand", "ip-bulk", str(targets), "--vulnscan"]
    )
    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content) == {
        "ip": "1.1.1.1,8.8.8.8,10.0.0.0/24",
        "vulnscan": "true",
    }


@respx.mock
def test_cli_domain_bulk_reads_one_target_per_line(tmp_path: Path) -> None:
    targets = tmp_path / "domains.txt"
    targets.write_text("a.tld\nb.tld\n", encoding="utf-8")
    route = respx.post(BULK_DOMAIN).mock(return_value=httpx.Response(200, json=launched()))
    result = runner.invoke(app, ["--api-key", API_KEY, "ondemand", "domain-bulk", str(targets)])
    assert result.exit_code == 0
    assert json.loads(route.calls.last.request.content) == {"domain": "a.tld,b.tld"}


def test_cli_bulk_missing_file_exits_with_2(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["--api-key", API_KEY, "ondemand", "ip-bulk", str(tmp_path / "nope.txt")]
    )
    assert result.exit_code == 2


def test_cli_rejects_a_bad_port_list() -> None:
    result = runner.invoke(
        app, ["--api-key", API_KEY, "ondemand", "ip", "8.8.8.8", "--ports", "80,https"]
    )
    assert result.exit_code == 2


@respx.mock
def test_cli_result() -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(200, json=envelope([{"ip": "8.8.8.8", "port": 443}]))
    )
    result = runner.invoke(app, ["--api-key", API_KEY, "ondemand", "result", "abc123"])
    assert result.exit_code == 0
    assert "8.8.8.8" in result.stdout


@respx.mock
@pytest.mark.parametrize("code", [103, 111])
def test_cli_result_exits_with_3_while_the_scan_runs(code: int) -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(200, json={"error": code, "text": "Scan ID is in progress"})
    )
    result = runner.invoke(app, ["--api-key", API_KEY, "ondemand", "result", "abc123"])
    assert result.exit_code == 3


@respx.mock
def test_cli_result_api_error_exits_with_1() -> None:
    respx.get(RESULT).mock(
        return_value=httpx.Response(403, json={"text": "no on-demand in your license"})
    )
    result = runner.invoke(app, ["--api-key", API_KEY, "ondemand", "result", "abc123"])
    assert result.exit_code == 1
