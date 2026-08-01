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
    └── ServerError           5xx
```

## Constants

`SIMPLE_CATEGORIES`, `BEST_CATEGORIES`, `BULK_SIMPLE_CATEGORIES`,
`SUMMARY_KINDS`, `SEARCH_MAX_RESULTS` (10000), `DEFAULT_BASE_URL`,
`UNRATED_BASE_URL`.
