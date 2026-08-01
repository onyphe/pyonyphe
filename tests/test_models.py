"""The response envelope is the only thing we model, so it has to be solid."""

from __future__ import annotations

import pytest

from pyonyphe.models import Alert, AlertList, Response


def test_took_accepts_a_string() -> None:
    # /alert/list returns "0.000", /search returns 0.032. Both must parse.
    assert Response.model_validate({"took": "0.010"}).took == pytest.approx(0.010)


def test_took_accepts_a_float() -> None:
    assert Response.model_validate({"took": 0.032}).took == pytest.approx(0.032)


def test_took_survives_garbage() -> None:
    assert Response.model_validate({"took": "not-a-number"}).took is None


def test_paging_fields_accept_strings() -> None:
    response = Response.model_validate({"page": "2", "max_page": "5", "page_size": "100"})
    assert (response.page, response.max_page, response.page_size) == (2, 5, 100)


def test_paging_fields_survive_garbage() -> None:
    assert Response.model_validate({"page": "n/a"}).page is None


def test_defaults_are_empty_not_none() -> None:
    response = Response()
    assert response.results == []
    assert response.total == 0
    assert response.count == 0


def test_unknown_fields_are_kept() -> None:
    # A new ONYPHE field must never break the client.
    response = Response.model_validate({"brand_new_field": "value"})
    assert response.brand_new_field == "value"  # ty: ignore[unresolved-attribute]


def test_response_iterates_and_sizes_its_results() -> None:
    response = Response.model_validate({"results": [{"ip": "1.1.1.1"}, {"ip": "8.8.8.8"}]})
    assert [hit["ip"] for hit in response] == ["1.1.1.1", "8.8.8.8"]
    assert len(response) == 2


def test_empty_response_is_falsy_by_length() -> None:
    assert len(Response()) == 0


def test_alert_parses_the_documented_shape() -> None:
    alert = Alert.model_validate(
        {"id": 0, "name": "My alert", "query": "domain:x", "email": "a@b.tld", "threshold": ">0"}
    )
    assert alert.id == 0
    assert alert.threshold == ">0"


def test_alert_tolerates_missing_fields() -> None:
    alert = Alert.model_validate({"name": "partial"})
    assert alert.name == "partial"
    assert alert.id is None


def test_alert_list_from_response() -> None:
    response = Response.model_validate(
        {"results": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}], "total": 2}
    )
    alerts = AlertList.from_response(response)
    assert [alert.name for alert in alerts.alerts] == ["a", "b"]
    assert alerts.total == 2
    assert alerts.results == response.results
