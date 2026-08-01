"""The 2.x import name must keep resolving, loudly."""

from __future__ import annotations

import sys

import pytest

import pyonyphe


def test_shim_warns_and_reexports() -> None:
    sys.modules.pop("onyphe", None)
    with pytest.warns(DeprecationWarning, match="renamed to 'pyonyphe'"):
        import onyphe

    assert onyphe.Onyphe is pyonyphe.Onyphe
    assert onyphe.AsyncOnyphe is pyonyphe.AsyncOnyphe
    assert onyphe.APIError is pyonyphe.APIError
    assert onyphe.ParamError is pyonyphe.ParamError


def test_shim_exports_nothing_extra() -> None:
    sys.modules.pop("onyphe", None)
    with pytest.warns(DeprecationWarning):
        import onyphe

    assert sorted(onyphe.__all__) == [
        "APIError",
        "AsyncOnyphe",
        "Onyphe",
        "OnypheError",
        "ParamError",
    ]
