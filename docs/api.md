# API reference

Every method exists on both `Onyphe` and `AsyncOnyphe`. On the async client,
the ones returning a `Response` are coroutines; the ones returning an iterator
return an async iterator.

## General

| method | HTTP | endpoint |
| --- | --- | --- |
| `user()` | GET | `/user` |
| `search(query, page=1, size=None, trackquery=False, calculated=False)` | GET | `/search/?q=...` |
| `search_iter(query, size=100, max_results=None, max_pages=None, ...)` | GET | `/search/`, page by page |
| `export(query, trackquery=False, calculated=False)` | GET | `/export/?q=...` (NDJSON) |
| `summary(kind, value)` | GET | `/summary/{kind}/{value}` |
| `summary_ip(ip)` | GET | `/summary/ip/{ip}` |
| `summary_domain(domain)` | GET | `/summary/domain/{domain}` |
| `summary_hostname(fqdn)` | GET | `/summary/hostname/{fqdn}` |
| `request(method, path, params=, json=, content=)` | any | anything else |

`kind` is one of `ip`, `domain`, `hostname`.

## Simple (deprecated upstream)

| method | endpoint |
| --- | --- |
| `simple(category, value)` | `/simple/{category}/{value}` |
| `simple_best(category, value)` | `/simple/{category}/best/{value}` |
| `simple_datamd5(md5)` | `/simple/datascan/datamd5/{md5}` |
| `resolver_forward(value)` | `/simple/resolver/forward/{value}` |
| `resolver_reverse(ip)` | `/simple/resolver/reverse/{ip}` |

Simple categories: `ctl`, `datascan`, `datashot`, `geoloc`, `inetnum`,
`onionscan`, `onionshot`, `pastries`, `resolver`, `sniffer`, `threatlist`,
`topsite`, `vulnscan`, `whois`.

Best categories: `geoloc`, `inetnum`, `threatlist`, `whois`.

Passing anything else raises `ParamError` before any request is sent — that is
deliberate, an unknown category would otherwise come back as an opaque 404.

## Bulk — POST a newline-delimited body, get NDJSON back

| method | endpoint |
| --- | --- |
| `bulk_summary(kind, source)` | `/bulk/summary/{kind}` |
| `bulk_simple(category, source)` | `/bulk/simple/{category}/ip` |
| `bulk_simple_best(category, source)` | `/bulk/simple/{category}/best/ip` |
| `discovery(category, source)` | `/bulk/discovery/{category}/asset` |

Bulk Simple categories are the Simple ones minus `onionscan` and `onionshot`.

`source` accepts a `Path`, a path string, a raw string, an iterable of assets,
or bytes.

## On-demand scan

Active scanning, **On-demand subscription required** — every other API on this
page only reads data ONYPHE already collected.

| method | HTTP | endpoint |
| --- | --- | --- |
| `ondemand_scope_ip(ip, ...)` | POST | `/ondemand/scope/ip/single` |
| `ondemand_scope_domain(domain, ...)` | POST | `/ondemand/scope/domain/single` |
| `ondemand_scope_ip_bulk(ips, ...)` | POST | `/dev/ondemand/scope/ip/bulk` |
| `ondemand_scope_domain_bulk(domains, ...)` | POST | `/dev/ondemand/scope/domain/bulk` |
| `ondemand_scope_result(scan_id)` | GET | `/ondemand/scope/result/{scan_id}` |

`ip` is `X.Y.Z.K` or `X.Y.Z.K/24`. The two bulk methods take any iterable of
strings and join it with commas themselves.

The two bulk endpoints live under the `/dev/` prefix (`DEV_PREFIX`), which
ONYPHE serves from its development tree: they may move or change shape without
notice. `/ondemand/scope/domain/single` is **not** documented by ONYPHE
either — it is deduced by analogy with `ip/single`, and kept in a single
constant (`ONDEMAND_SCOPE_DOMAIN_PATH`) so that one edit fixes it if it turns
out to be wrong.

The four launch methods share these optional arguments, and send a key only
when you pass one:

| argument | sent as | value |
| --- | --- | --- |
| `import_results` | `import` | `"true"` / `"false"` |
| `vulnscan` | `vulnscan` | `"true"` / `"false"` |
| `urlscan` | `urlscan` | `"true"` / `"false"` |
| `ports` | `ports` | `[80, 443]` becomes `"80,443"` |
| `maxscantime` | `maxscantime` | an integer, in seconds |

`import_results` is named that way because `import` is a Python keyword.
**Setting it publishes the scan results in the ONYPHE dataset, where every
ONYPHE user can see them.**

A launch returns the raw `Response`: ONYPHE documents that it carries a Scan
ID but not under which field name, so nothing is parsed out of it. Read it
from `response.model_dump()` and feed it back to `ondemand_scope_result`.

The four launch methods are sent exactly once and never retried automatically,
on a 429, a 5xx or a transport failure alike: replaying the POST would start a
second scan. `ondemand_scope_result` is a GET and keeps the usual retry
behaviour.

`ondemand_scope_result` raises `ScanInProgressError` when ONYPHE answers with
error code 103 (`Scan ID is in progress`) or 111 (`Scan ID results are being
built`), whatever HTTP status carries it. That is not a failure: the same
`scan_id` is worth asking for again later. The exception carries `.scan_id`.
Every other error code goes through the usual mapping. There is no polling
helper yet.

## Alerts

| method | HTTP | endpoint |
| --- | --- | --- |
| `alerts()` | GET | `/alert/list` — returns `list[Alert]` |
| `add_alert(name, query, email, threshold=">0")` | POST | `/alert/add` |
| `del_alert(alert_id)` | POST | `/alert/del/{id}` |

## Models

### `Response`

`count`, `error`, `max_page`, `myip`, `page`, `page_size`, `results`,
`status`, `text`, `took`, `total`. Extra fields are kept. `took` is coerced to
a float — ONYPHE returns it both as a number and as a string depending on the
endpoint. Iterating a `Response` iterates `results`; `len()` gives the number
of results in the page.

### `Alert`

`id`, `name`, `query`, `email`, `threshold`.

## Exceptions

```
OnypheError
├── ConfigError
├── ParamError
├── TransportError
└── APIError
    ├── AuthenticationError   401 / 403
    ├── PaymentRequiredError  402
    ├── NotFoundError         404
    ├── RateLimitError        429  (.retry_after)
    ├── ScanInProgressError   ONYPHE error 103 / 111  (.scan_id)
    └── ServerError           5xx
```

## Constants

`SIMPLE_CATEGORIES`, `BEST_CATEGORIES`, `BULK_SIMPLE_CATEGORIES`,
`SUMMARY_KINDS`, `SEARCH_MAX_RESULTS` (10000), `DEFAULT_BASE_URL`,
`UNRATED_BASE_URL`, `SCAN_IN_PROGRESS_CODES` (103, 111), `DEV_PREFIX`.
