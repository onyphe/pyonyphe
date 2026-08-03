"""Tests that hit the real ONYPHE API.

Deselected by default -- ``pytest -m 'not integration'`` is what CI runs.
Run them with ``uv run pytest -m integration``; they need a valid
``ONYPHE_API_KEY`` and **they consume credits**.

The key is captured at import time, on purpose: the autouse ``_sandbox_home``
fixture strips ``ONYPHE_API_KEY`` from the environment so that unit tests stay
hermetic, so these tests have to pass it explicitly.
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from pyonyphe import AsyncOnyphe, Onyphe

# Read .env before the environment is sandboxed, so a key stored there works
# just like an exported variable.
load_dotenv(override=False)
LIVE_API_KEY = os.environ.get("ONYPHE_API_KEY")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not LIVE_API_KEY, reason="ONYPHE_API_KEY is not set"),
]


def test_user_endpoint_answers() -> None:
    with Onyphe(LIVE_API_KEY) as client:
        response = client.user()
    assert response.status == "ok"
    assert response.error == 0


def test_summary_on_a_well_known_address() -> None:
    with Onyphe(LIVE_API_KEY) as client:
        response = client.summary_ip("8.8.8.8")
    assert response.error == 0
    assert response.results


def test_search_returns_a_page() -> None:
    with Onyphe(LIVE_API_KEY) as client:
        response = client.search("category:datascan protocol:ssh", size=1)
    assert response.error == 0
    assert len(response.results) <= 1


async def test_async_user_endpoint_answers() -> None:
    async with AsyncOnyphe(LIVE_API_KEY) as client:
        response = await client.user()
    assert response.status == "ok"
