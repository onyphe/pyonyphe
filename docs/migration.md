# Migrating from 2.x

3.0 is a rewrite. The import name changed, and several 2.x methods were built
against an API shape ONYPHE no longer serves.

## Import name

```python
from onyphe import Onyphe, APIError      # 2.x
from pyonyphe import Onyphe, APIError    # 3.x
```

The distribution has always been `pyonyphe`; only the importable package
changed, so that both match.

## What was actually broken in 2.x

| 2.x behaviour | reality today |
| --- | --- |
| key sent as `?apikey=` | APIv2 expects `Authorization: bearer KEY` |
| `search()` put the OQL in the path | it goes in the `q` query parameter |
| `export()` put the OQL in the path | same, `q` parameter |
| `bulk_simple_ctl_ip()` hit `bulk/simple/clt/ip` | typo — the endpoint is `ctl` |
| `bulk_simple_inetnum_ip()` hit `bulk/simple/inetenum/ip` | typo — `inetnum` |
| `synscan()` / `simple_synscan()` | synscan is gone from the Simple API |
| `add_alert()` had no `threshold` | the field is now part of the payload |

If your 2.x code still "worked", it was almost certainly only using the
endpoints that tolerate the legacy shape.

## Method mapping

| 2.x | 3.x |
| --- | --- |
| `simple_geoloc(ip)` | `simple("geoloc", ip)` |
| `simple_datascan(v)` | `simple("datascan", v)` |
| `simple_geoloc_best(ip)` | `simple_best("geoloc", ip)` |
| `simple_inetnum_best(ip)` | `simple_best("inetnum", ip)` |
| `simple_threatlist_best(ip)` | `simple_best("threatlist", ip)` |
| `simple_datascan_datamd5(md5)` | `simple_datamd5(md5)` |
| `simple_resolver_forward(v)` | `resolver_forward(v)` |
| `simple_resolver_reverse(ip)` | `resolver_reverse(ip)` |
| `bulk_summary_ip(path)` | `bulk_summary("ip", path)` |
| `bulk_summary_domain(path)` | `bulk_summary("domain", path)` |
| `bulk_summary_hostname(path)` | `bulk_summary("hostname", path)` |
| `bulk_simple_<cat>_ip(path)` | `bulk_simple("<cat>", path)` |
| `alert_list()` | `alerts()` — returns `list[Alert]`, not a raw dict |
| `synscan(ip)` / `simple_synscan(ip)` | removed; use `search("category:synscan ip:...")` |

`summary_ip`, `summary_domain`, `summary_hostname`, `add_alert` and
`del_alert` kept their names and signatures (`add_alert` gained an optional
`threshold`).

## Return types

2.x returned raw dicts. 3.x returns a `Response` model. The quickest fix:

```python
response = api.summary_ip("8.8.8.8")
response.results      # what you used to iterate
response.model_dump() # a plain dict again, if you really need one
```

Streaming methods still yield plain dicts, one per document.

## Errors

`APIError` and `ParamError` still exist and still mean the same thing, but
they now sit under `OnypheError` alongside more precise subclasses. Code
catching `APIError` keeps working for HTTP failures; add `TransportError` if
you were relying on `APIError("Unable to connect to Onyphe")`, which no longer
covers network failures.

## Packaging

`setup.py` and `requirements.txt` are gone. Use `uv add pyonyphe`, or
`uv sync --dev` in a clone.
