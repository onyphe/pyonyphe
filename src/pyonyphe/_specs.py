"""Request specifications shared by the sync and async clients.

Each public API call is described here as a pure, side-effect-free
:class:`Spec`. The clients only know how to *send* a spec, which keeps the two
transports in sync and makes every endpoint testable without any I/O.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .errors import ParamError

__all__ = [
    "BEST_CATEGORIES",
    "BULK_SIMPLE_CATEGORIES",
    "SEARCH_MAX_RESULTS",
    "SIMPLE_CATEGORIES",
    "SUMMARY_KINDS",
    "BestCategory",
    "BulkSimpleCategory",
    "SimpleCategory",
    "Spec",
    "SummaryKind",
    "to_payload",
]

#: Hard limit enforced by the Search API; beyond that you need Export.
SEARCH_MAX_RESULTS = 10_000

SimpleCategory = Literal[
    "ctl",
    "datascan",
    "datashot",
    "geoloc",
    "inetnum",
    "onionscan",
    "onionshot",
    "pastries",
    "resolver",
    "sniffer",
    "threatlist",
    "topsite",
    "vulnscan",
    "whois",
]
BestCategory = Literal["geoloc", "inetnum", "threatlist", "whois"]
BulkSimpleCategory = Literal[
    "ctl",
    "datascan",
    "datashot",
    "geoloc",
    "inetnum",
    "pastries",
    "resolver",
    "sniffer",
    "threatlist",
    "topsite",
    "vulnscan",
    "whois",
]
SummaryKind = Literal["ip", "domain", "hostname"]

SIMPLE_CATEGORIES: frozenset[str] = frozenset(
    (
        "ctl",
        "datascan",
        "datashot",
        "geoloc",
        "inetnum",
        "onionscan",
        "onionshot",
        "pastries",
        "resolver",
        "sniffer",
        "threatlist",
        "topsite",
        "vulnscan",
        "whois",
    )
)
BEST_CATEGORIES: frozenset[str] = frozenset(("geoloc", "inetnum", "threatlist", "whois"))
BULK_SIMPLE_CATEGORIES: frozenset[str] = SIMPLE_CATEGORIES - {"onionscan", "onionshot"}
SUMMARY_KINDS: frozenset[str] = frozenset(("ip", "domain", "hostname"))


@dataclass(frozen=True, slots=True)
class Spec:
    """A single HTTP call against the ONYPHE API.

    :param method: ``GET`` or ``POST``
    :param path: path relative to the API root, without a leading slash
    :param params: query string parameters
    :param json: JSON body, for ``POST`` endpoints that take one
    :param content: raw body, used by the bulk endpoints
    :param stream: ``True`` when the API answers with newline-delimited JSON
    """

    method: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)
    json: dict[str, Any] | None = None
    content: bytes | None = None
    stream: bool = False


def _check(value: str, allowed: frozenset[str], label: str) -> str:
    if value not in allowed:
        raise ParamError(f"unknown {label} {value!r}; expected one of {sorted(allowed)}")
    return value


def _flag(value: bool) -> str:
    return "true" if value else "false"


def to_payload(source: str | Path | Iterable[str] | bytes) -> bytes:
    """Normalise a bulk input into the newline-delimited body ONYPHE expects.

    :param source: a path to a text file, a raw string, an iterable of assets,
        or already-encoded bytes
    :returns: UTF-8 bytes, one asset per line
    :raises ParamError: when a path is given but does not point to a file
    """
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        if not source.is_file():
            raise ParamError(f"{source} is not a file")
        return source.read_bytes()
    if isinstance(source, str):
        candidate = Path(source)
        if candidate.is_file():
            return candidate.read_bytes()
        return source.encode("utf-8")
    items = [str(item).strip() for item in source]
    items = [item for item in items if item]
    if not items:
        raise ParamError("empty bulk payload")
    return ("\n".join(items) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# General APIs
# --------------------------------------------------------------------------


def user() -> Spec:
    """License, credits, authorisations and scanned-ports list."""
    return Spec("GET", "user")


def search(
    query: str,
    *,
    page: int = 1,
    size: int | None = None,
    trackquery: bool = False,
    calculated: bool = False,
) -> Spec:
    """Search API: OQL goes in the ``q`` parameter, never in the path."""
    params: dict[str, Any] = {"q": query, "page": page}
    if size is not None:
        params["size"] = size
    if trackquery:
        params["trackquery"] = _flag(True)
    if calculated:
        params["calculated"] = _flag(True)
    return Spec("GET", "search/", params=params)


def export(query: str, *, trackquery: bool = False, calculated: bool = False) -> Spec:
    """Export API: same OQL, streamed as newline-delimited JSON."""
    params: dict[str, Any] = {"q": query}
    if trackquery:
        params["trackquery"] = _flag(True)
    if calculated:
        params["calculated"] = _flag(True)
    return Spec("GET", "export/", params=params, stream=True)


def summary(kind: SummaryKind, value: str) -> Spec:
    """Summary API for an IP, a domain or a hostname."""
    _check(kind, SUMMARY_KINDS, "summary kind")
    return Spec("GET", f"summary/{kind}/{value}")


def simple(category: SimpleCategory, value: str) -> Spec:
    """Simple API (deprecated upstream, kept until APIv3 drops it)."""
    _check(category, SIMPLE_CATEGORIES, "simple category")
    return Spec("GET", f"simple/{category}/{value}")


def simple_best(category: BestCategory, value: str) -> Spec:
    """Simple Best API: single best-matching document for an IP."""
    _check(category, BEST_CATEGORIES, "best category")
    return Spec("GET", f"simple/{category}/best/{value}")


def simple_datamd5(md5: str) -> Spec:
    """Datascan documents sharing the same ``datamd5`` fingerprint."""
    return Spec("GET", f"simple/datascan/datamd5/{md5}")


def simple_resolver_forward(value: str) -> Spec:
    """Forward DNS records for a domain or hostname."""
    return Spec("GET", f"simple/resolver/forward/{value}")


def simple_resolver_reverse(value: str) -> Spec:
    """Reverse DNS records for an IP address."""
    return Spec("GET", f"simple/resolver/reverse/{value}")


# --------------------------------------------------------------------------
# Bulk APIs -- POST a newline-delimited body, get streamed NDJSON back
# --------------------------------------------------------------------------


def bulk_summary(kind: SummaryKind, source: str | Path | Iterable[str] | bytes) -> Spec:
    """Bulk Summary API for a list of IPs, domains or hostnames."""
    _check(kind, SUMMARY_KINDS, "summary kind")
    return Spec("POST", f"bulk/summary/{kind}", content=to_payload(source), stream=True)


def bulk_simple(category: BulkSimpleCategory, source: str | Path | Iterable[str] | bytes) -> Spec:
    """Bulk Simple API for a list of IP addresses."""
    _check(category, BULK_SIMPLE_CATEGORIES, "bulk simple category")
    return Spec("POST", f"bulk/simple/{category}/ip", content=to_payload(source), stream=True)


def bulk_simple_best(category: BestCategory, source: str | Path | Iterable[str] | bytes) -> Spec:
    """Bulk Simple Best API for a list of IP addresses."""
    _check(category, BEST_CATEGORIES, "best category")
    return Spec("POST", f"bulk/simple/{category}/best/ip", content=to_payload(source), stream=True)


def discovery(category: str, source: str | Path | Iterable[str] | bytes) -> Spec:
    """Discovery API: run several OQL queries at once against one category."""
    return Spec("POST", f"bulk/discovery/{category}/asset", content=to_payload(source), stream=True)


# --------------------------------------------------------------------------
# Alert API
# --------------------------------------------------------------------------


def alert_list() -> Spec:
    """List the alerts currently configured on the account."""
    return Spec("GET", "alert/list")


def alert_add(name: str, query: str, email: str, threshold: str = ">0") -> Spec:
    """Create an alert.

    :param threshold: comparison expression evaluated on the daily result count
    """
    if not (name and query and email):
        raise ParamError("name, query and email are all required")
    body = {"name": name, "query": query, "email": email, "threshold": threshold}
    return Spec("POST", "alert/add", json=body)


def alert_del(alert_id: int | str) -> Spec:
    """Delete the alert with the given identifier."""
    if alert_id is None or str(alert_id) == "":
        raise ParamError("an alert id is required")
    return Spec("POST", f"alert/del/{alert_id}")
