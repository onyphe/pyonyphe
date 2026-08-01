"""Pydantic models for the ONYPHE response envelope.

Only the envelope is modelled. The content of ``results`` stays as plain
dictionaries on purpose: the ONYPHE data model spans dozens of categories with
hundreds of optional fields, and pinning it down here would break every time
ONYPHE ships a new field.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["Alert", "AlertList", "Response"]


class Response(BaseModel):
    """Standard ONYPHE JSON envelope returned by every non-streaming endpoint.

    :param count: number of results in this page
    :param error: ONYPHE error code, ``0`` when the call succeeded
    :param max_page: last reachable page for this query
    :param results: raw result documents, one dict per hit
    :param total: total number of matching documents, all pages included
    """

    model_config = ConfigDict(extra="allow")

    count: int = 0
    error: int = 0
    max_page: int | None = None
    myip: str | None = None
    page: int | None = None
    page_size: int | None = None
    results: list[dict[str, Any]] = Field(default_factory=list)
    status: str | None = None
    text: str | None = None
    took: float | None = None
    total: int = 0

    @field_validator("took", mode="before")
    @classmethod
    def _coerce_took(cls, value: Any) -> Any:
        """Accept ``"0.000"`` as well as ``0.0`` -- ONYPHE returns both."""
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return None
        return value

    @field_validator("page", "max_page", "page_size", mode="before")
    @classmethod
    def _coerce_int(cls, value: Any) -> Any:
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return value

    def __iter__(self) -> Any:  # type: ignore[override]
        """Iterate over ``results`` so ``for hit in response`` just works."""
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)


class Alert(BaseModel):
    """A single alert as returned by ``/alert/list``.

    :param threshold: comparison string such as ``">0"`` that triggers the alert
    """

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    name: str | None = None
    query: str | None = None
    email: str | None = None
    threshold: str | None = None


class AlertList(Response):
    """``/alert/list`` envelope, with ``results`` parsed into :class:`Alert`."""

    alerts: list[Alert] = Field(default_factory=list)

    @classmethod
    def from_response(cls, response: Response) -> AlertList:
        """Build an :class:`AlertList` from a generic :class:`Response`."""
        data = response.model_dump()
        data["alerts"] = [Alert.model_validate(item) for item in response.results]
        return cls.model_validate(data)
