"""CLI smoke tests: exit codes, output formats, and error reporting."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from pyonyphe.cli import app

from .conftest import API_KEY, BASE, envelope

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "pyonyphe" in result.stdout


def test_missing_api_key_exits_with_2() -> None:
    result = runner.invoke(app, ["user"])
    assert result.exit_code == 2


@respx.mock
def test_search_table() -> None:
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(
            200, json=envelope([{"@category": "datascan", "ip": "8.8.8.8", "port": 53}])
        )
    )
    result = runner.invoke(app, ["--api-key", API_KEY, "search", "protocol:dns"])
    assert result.exit_code == 0
    assert "8.8.8.8" in result.stdout


@respx.mock
def test_search_json_to_file(tmp_path: Path) -> None:
    respx.get(f"{BASE}/search/").mock(
        return_value=httpx.Response(200, json=envelope([{"ip": "8.8.8.8"}]))
    )
    target = tmp_path / "out.json"
    result = runner.invoke(
        app,
        ["--api-key", API_KEY, "search", "x", "--format", "json", "--output", str(target)],
    )
    assert result.exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8")) == [{"ip": "8.8.8.8"}]


@respx.mock
def test_export_writes_ndjson(tmp_path: Path) -> None:
    respx.get(f"{BASE}/export/").mock(
        return_value=httpx.Response(200, text='{"ip":"1.1.1.1"}\n{"ip":"8.8.8.8"}\n')
    )
    target = tmp_path / "out.ndjson"
    result = runner.invoke(
        app, ["--api-key", API_KEY, "export", "domain:x", "--output", str(target)]
    )
    assert result.exit_code == 0
    assert target.read_text(encoding="utf-8").count("\n") == 2


@respx.mock
def test_api_error_exits_with_1() -> None:
    respx.get(f"{BASE}/search/").mock(return_value=httpx.Response(403, json={"text": "nope"}))
    result = runner.invoke(app, ["--api-key", API_KEY, "search", "x"])
    assert result.exit_code == 1


@respx.mock
def test_alert_list() -> None:
    respx.get(f"{BASE}/alert/list").mock(
        return_value=httpx.Response(
            200,
            json=envelope(
                [{"id": 1, "name": "n", "query": "q", "email": "a@b.tld", "threshold": ">0"}]
            ),
        )
    )
    result = runner.invoke(app, ["--api-key", API_KEY, "alert", "list"])
    assert result.exit_code == 0
    assert "a@b.tld" in result.stdout


@pytest.mark.parametrize("args", [["simple", "synscan", "8.8.8.8"], ["summary", "asn", "x"]])
def test_unknown_category_exits_with_1(args: list[str]) -> None:
    result = runner.invoke(app, ["--api-key", API_KEY, *args])
    assert result.exit_code == 1


def test_config_masks_the_key() -> None:
    result = runner.invoke(app, ["--api-key", API_KEY, "config"])
    assert result.exit_code == 0
    assert API_KEY not in result.stdout
