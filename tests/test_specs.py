"""Specs are pure functions: assert the exact URLs and bodies we send."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from pyonyphe import _specs as specs
from pyonyphe._specs import BestCategory, SimpleCategory, SummaryKind
from pyonyphe.errors import ParamError


def test_search_puts_the_query_in_the_q_parameter() -> None:
    spec = specs.search("protocol:rdp domain:google.com", page=2, size=10)
    assert spec.method == "GET"
    assert spec.path == "search/"
    assert spec.params == {"q": "protocol:rdp domain:google.com", "page": 2, "size": 10}
    assert spec.stream is False


def test_search_flags_are_lowercase_strings() -> None:
    spec = specs.search("x", trackquery=True, calculated=True)
    assert spec.params["trackquery"] == "true"
    assert spec.params["calculated"] == "true"


def test_search_omits_flags_when_false() -> None:
    spec = specs.search("x")
    assert "trackquery" not in spec.params
    assert "calculated" not in spec.params


def test_export_streams() -> None:
    spec = specs.export("domain:example.com")
    assert spec.path == "export/"
    assert spec.params["q"] == "domain:example.com"
    assert spec.stream is True


def test_summary_paths() -> None:
    assert specs.summary("ip", "8.8.8.8").path == "summary/ip/8.8.8.8"
    assert specs.summary("domain", "example.com").path == "summary/domain/example.com"


def test_summary_rejects_unknown_kind() -> None:
    with pytest.raises(ParamError):
        specs.summary(cast(SummaryKind, "asn"), "AS15169")


def test_simple_and_best_paths() -> None:
    assert specs.simple("datascan", "8.8.8.8").path == "simple/datascan/8.8.8.8"
    assert specs.simple_best("whois", "8.8.8.8").path == "simple/whois/best/8.8.8.8"


def test_simple_rejects_categories_dropped_by_onyphe() -> None:
    # synscan disappeared from the Simple API; it must not silently 404.
    with pytest.raises(ParamError):
        specs.simple(cast(SimpleCategory, "synscan"), "8.8.8.8")


def test_best_is_limited_to_four_categories() -> None:
    assert sorted(specs.BEST_CATEGORIES) == ["geoloc", "inetnum", "threatlist", "whois"]
    with pytest.raises(ParamError):
        specs.simple_best(cast(BestCategory, "datascan"), "8.8.8.8")


def test_bulk_paths_are_spelled_correctly() -> None:
    # The 2.0 client shipped "clt" and "inetenum" typos: both endpoints 404'd.
    assert specs.bulk_simple("ctl", ["8.8.8.8"]).path == "bulk/simple/ctl/ip"
    assert specs.bulk_simple("inetnum", ["8.8.8.8"]).path == "bulk/simple/inetnum/ip"
    assert specs.bulk_simple_best("whois", ["8.8.8.8"]).path == "bulk/simple/whois/best/ip"
    assert specs.bulk_summary("ip", ["8.8.8.8"]).path == "bulk/summary/ip"
    assert specs.discovery("datascan", ["protocol:rdp"]).path == "bulk/discovery/datascan/asset"


def test_bulk_payload_from_iterable() -> None:
    spec = specs.bulk_simple("datascan", ["1.1.1.1", " 8.8.8.8 ", ""])
    assert spec.content == b"1.1.1.1\n8.8.8.8\n"
    assert spec.method == "POST"
    assert spec.stream is True


def test_bulk_payload_from_file(tmp_path: Path) -> None:
    path = tmp_path / "ip.txt"
    path.write_text("1.1.1.1\n8.8.8.8\n", encoding="utf-8")
    assert specs.bulk_simple("datascan", path).content == b"1.1.1.1\n8.8.8.8\n"


def test_bulk_payload_normalises_crlf() -> None:
    # A list produced on Windows must not ship carriage returns to ONYPHE.
    spec = specs.bulk_simple("datascan", b"1.1.1.1\r\n8.8.8.8\r\n")
    assert spec.content == b"1.1.1.1\n8.8.8.8\n"


def test_bulk_payload_normalises_lone_cr() -> None:
    spec = specs.bulk_simple("datascan", b"1.1.1.1\r8.8.8.8\r")
    assert spec.content == b"1.1.1.1\n8.8.8.8\n"


def test_bulk_payload_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ParamError):
        specs.bulk_simple("datascan", tmp_path / "nope.txt")


def test_bulk_payload_rejects_empty_iterable() -> None:
    with pytest.raises(ParamError):
        specs.bulk_simple("datascan", [])


def test_alert_add_carries_threshold() -> None:
    spec = specs.alert_add("n", "q", "a@b.tld")
    assert spec.json == {"name": "n", "query": "q", "email": "a@b.tld", "threshold": ">0"}


def test_alert_add_requires_every_field() -> None:
    with pytest.raises(ParamError):
        specs.alert_add("", "q", "a@b.tld")


def test_alert_del_uses_the_id_in_the_path() -> None:
    assert specs.alert_del(3).path == "alert/del/3"
