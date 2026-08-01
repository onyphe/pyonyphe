"""Shared fixtures.

Every test runs with a sandboxed HOME so that a real ``~/.onyphe.ini`` on the
developer machine can never leak into the assertions.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from pyonyphe import AsyncOnyphe, Onyphe

API_KEY = "0123456789abcdef"
BASE = "https://www.onyphe.io/api/v2"


@pytest.fixture(autouse=True)
def _sandbox_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("ONYPHE_API_KEY", raising=False)
    monkeypatch.delenv("ONYPHE_BASE_URL", raising=False)
    monkeypatch.delenv("ONYPHE_UNRATED_EMAIL", raising=False)
    # Run from an empty directory so a developer's .env never leaks in.
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def client() -> Iterator[Onyphe]:
    with Onyphe(API_KEY, max_retries=0) as instance:
        yield instance


@pytest.fixture
async def async_client() -> AsyncOnyphe:
    return AsyncOnyphe(API_KEY, max_retries=0)


def envelope(results: list[dict[str, object]] | None = None, **extra: object) -> dict[str, object]:
    """Build a minimal ONYPHE envelope for a mocked answer."""
    payload: dict[str, object] = {
        "count": len(results or []),
        "error": 0,
        "status": "ok",
        "text": "Success",
        "took": "0.010",
        "total": len(results or []),
        "results": results or [],
    }
    payload.update(extra)
    return payload
