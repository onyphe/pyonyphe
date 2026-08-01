"""Credential resolution order and file parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from pyonyphe.config import DEFAULT_BASE_URL, UNRATED_BASE_URL, load_settings
from pyonyphe.errors import ConfigError


def test_explicit_key_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ONYPHE_API_KEY", "from-env")
    assert load_settings("explicit").api_key == "explicit"


def test_environment_is_used_when_no_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ONYPHE_API_KEY", "from-env")
    settings = load_settings()
    assert settings.api_key == "from-env"
    assert settings.base_url == DEFAULT_BASE_URL


def test_toml_config(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('[onyphe]\napi_key = "from-toml"\n', encoding="utf-8")
    assert load_settings(config_path=path).api_key == "from-toml"


def test_onyphe_ini_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".onyphe.ini").write_text(
        "api_endpoint = https://www.onyphe.io/api/v2\napi_key = from-ini\n", encoding="utf-8"
    )
    settings = load_settings(config_path=tmp_path / "missing.toml")
    assert settings.api_key == "from-ini"
    assert settings.base_url == "https://www.onyphe.io/api/v2"


def test_missing_key_raises() -> None:
    with pytest.raises(ConfigError):
        load_settings(config_path=Path("/nonexistent/config.toml"))


def test_unrated_email_switches_the_base_url() -> None:
    settings = load_settings("k", unrated_email="user@example.com")
    assert settings.base_url == UNRATED_BASE_URL
    assert settings.is_unrated is True


def test_trailing_slash_is_stripped() -> None:
    assert load_settings("k", base_url="https://example.com/api/v2/").base_url == (
        "https://example.com/api/v2"
    )
