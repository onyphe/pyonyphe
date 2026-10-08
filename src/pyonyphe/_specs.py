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
    "DEV_PREFIX",
    "ONDEMAND_SCOPE_DOMAIN_BULK_PATH",
    "ONDEMAND_SCOPE_DOMAIN_PATH",
    "ONDEMAND_SCOPE_IP_BULK_PATH",
    "ONDEMAND_SCOPE_IP_PATH",
    "ONDEMAND_SCOPE_RESULT_PATH",
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

#: Prefix of the endpoints ONYPHE still serves from its development tree. The
#: On-demand bulk endpoints live there and may move without notice.
DEV_PREFIX = "dev"

ONDEMAND_SCOPE_IP_PATH = "ondemand/scope/ip/single"
#: Deduced by analogy with :data:`ONDEMAND_SCOPE_IP_PATH`; the ONYPHE
#: documentation does not spell this one out.
ONDEMAND_SCOPE_DOMAIN_PATH = "ondemand/scope/domain/single"
ONDEMAND_SCOPE_IP_BULK_PATH = f"{DEV_PREFIX}/ondemand/scope/ip/bulk"
ONDEMAND_SCOPE_DOMAIN_BULK_PATH = f"{DEV_PREFIX}/ondemand/scope/domain/bulk"
ONDEMAND_SCOPE_RESULT_PATH = "ondemand/scope/result"

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


def _normalise_newlines(payload: bytes) -> bytes:
    """Force LF line endings.

    A list of assets written on Windows carries CRLF, and ONYPHE expects one
    clean asset per line: a trailing carriage return would otherwise travel as
    part of the asset value itself.
    """
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def to_payload(source: str | Path | Iterable[str] | bytes) -> bytes:
    """Normalise a bulk input into the newline-delimited body ONYPHE expects.

    :param source: a path to a text file, a raw string, an iterable of assets,
        or already-encoded bytes
    :returns: UTF-8 bytes, one asset per line, LF-terminated
    :raises ParamError: when a path is given but does not point to a file
    """
    if isinstance(source, bytes):
        return _normalise_newlines(source)
    if isinstance(source, Path):
        if not source.is_file():
            raise ParamError(f"{source} is not a file")
        return _normalise_newlines(source.read_bytes())
    if isinstance(source, str):
        candidate = Path(source)
        if candidate.is_file():
            return _normalise_newlines(candidate.read_bytes())
        return _normalise_newlines(source.encode("utf-8"))
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
# On-demand scope API -- POST a JSON body, get a scan identifier back
# --------------------------------------------------------------------------


def _scan_options(
    import_results: bool | None,
    vulnscan: bool | None,
    urlscan: bool | None,
    ports: Iterable[int] | None,
    maxscantime: int | None,
) -> dict[str, Any]:
    """Serialise the optional scan tuning, omitting whatever was left out.

    ``import_results`` travels as ``import``, a Python keyword, and the three
    booleans travel as the strings ONYPHE documents rather than as JSON
    booleans.
    """
    body: dict[str, Any] = {}
    if import_results is not None:
        body["import"] = _flag(import_results)
    if vulnscan is not None:
        body["vulnscan"] = _flag(vulnscan)
    if urlscan is not None:
        body["urlscan"] = _flag(urlscan)
    if ports is not None:
        body["ports"] = ",".join(str(port) for port in ports)
    if maxscantime is not None:
        body["maxscantime"] = maxscantime
    return body


def _scope_spec(path: str, field: str, value: str, options: dict[str, Any]) -> Spec:
    if not value:
        raise ParamError(f"a {field} is required")
    return Spec("POST", path, json={field: value, **options})


def _join(values: Iterable[str], label: str) -> str:
    """Join scan targets into the comma-separated string ONYPHE expects."""
    # A bare string is iterable: wrap it, or it would be split per character.
    items = [str(value).strip() for value in ([values] if isinstance(values, str) else values)]
    items = [item for item in items if item]
    if not items:
        raise ParamError(f"empty {label} list")
    return ",".join(items)


def ondemand_scope_ip(
    ip: str,
    *,
    import_results: bool | None = None,
    vulnscan: bool | None = None,
    urlscan: bool | None = None,
    ports: Iterable[int] | None = None,
    maxscantime: int | None = None,
) -> Spec:
    """On-demand scan of a single IP address or CIDR."""
    return _scope_spec(
        ONDEMAND_SCOPE_IP_PATH,
        "ip",
        ip,
        _scan_options(import_results, vulnscan, urlscan, ports, maxscantime),
    )


def ondemand_scope_domain(
    domain: str,
    *,
    import_results: bool | None = None,
    vulnscan: bool | None = None,
    urlscan: bool | None = None,
    ports: Iterable[int] | None = None,
    maxscantime: int | None = None,
) -> Spec:
    """On-demand scan of a single domain."""
    return _scope_spec(
        ONDEMAND_SCOPE_DOMAIN_PATH,
        "domain",
        domain,
        _scan_options(import_results, vulnscan, urlscan, ports, maxscantime),
    )


def ondemand_scope_ip_bulk(
    ips: Iterable[str],
    *,
    import_results: bool | None = None,
    vulnscan: bool | None = None,
    urlscan: bool | None = None,
    ports: Iterable[int] | None = None,
    maxscantime: int | None = None,
) -> Spec:
    """On-demand scan of several IP addresses or CIDRs at once."""
    return _scope_spec(
        ONDEMAND_SCOPE_IP_BULK_PATH,
        "ip",
        _join(ips, "ip"),
        _scan_options(import_results, vulnscan, urlscan, ports, maxscantime),
    )


def ondemand_scope_domain_bulk(
    domains: Iterable[str],
    *,
    import_results: bool | None = None,
    vulnscan: bool | None = None,
    urlscan: bool | None = None,
    ports: Iterable[int] | None = None,
    maxscantime: int | None = None,
) -> Spec:
    """On-demand scan of several domains at once."""
    return _scope_spec(
        ONDEMAND_SCOPE_DOMAIN_BULK_PATH,
        "domain",
        _join(domains, "domain"),
        _scan_options(import_results, vulnscan, urlscan, ports, maxscantime),
    )


def ondemand_scope_result(scan_id: str) -> Spec:
    """Results of a scan launched earlier, by scan identifier."""
    if not scan_id:
        raise ParamError("a scan id is required")
    return Spec("GET", f"{ONDEMAND_SCOPE_RESULT_PATH}/{scan_id}")


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
