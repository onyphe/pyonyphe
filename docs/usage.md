# Usage

## Clients

`Onyphe` is blocking, `AsyncOnyphe` is not. They expose the same methods with
the same arguments; only `await` and the iteration syntax differ. Both are
context managers and should be closed.

```python
from pyonyphe import Onyphe

with Onyphe() as api:
    ...
```

```python
from pyonyphe import AsyncOnyphe

async with AsyncOnyphe() as api:
    ...
```

Constructor arguments:

| argument | default | meaning |
| --- | --- | --- |
| `api_key` | resolved from env/config | ONYPHE API key |
| `base_url` | `https://www.onyphe.io/api/v2` | API root |
| `unrated_email` | `None` | switches to the Unrated endpoint |
| `timeout` | `30.0` | per-request timeout, seconds |
| `max_retries` | `3` | retries on 429 and 5xx |
| `backoff` | `0.5` | base delay for the exponential backoff |

## Responses

Non-streaming calls return a `Response`: the ONYPHE envelope, validated by
pydantic, with the raw documents left as dictionaries in `results`.

```python
page = api.search("category:datascan product:Nginx")
page.total       # total matching documents
page.count       # documents in this page
page.max_page    # last reachable page
page.results     # list[dict]
list(page)       # iterating a Response iterates its results
```

Unknown fields are preserved, so a new ONYPHE field never breaks the client.

## Searching

One page at a time:

```python
page = api.search("protocol:rdp country:FR", page=2, size=50)
```

Or let the client walk the pages:

```python
for hit in api.search_iter("domain:example.com", size=100, max_results=1000):
    print(hit["ip"])
```

`search_iter` stops at `max_results`, at the last page ONYPHE reports, or at
the 10 000-result ceiling the Search API enforces — whichever comes first.
Past that ceiling, use `export`.

`trackquery=True` asks ONYPHE which sub-query matched each document, and
`calculated=True` adds the enriched `calculated.*` fields.

## Streaming

`export`, every `bulk_*` method and `discovery` return an iterator of
dictionaries, decoded from the newline-delimited JSON ONYPHE streams. Nothing
is buffered in memory.

```python
with open("out.ndjson", "w") as fh:
    for doc in api.export("category:vulnscan domain:example.com"):
        fh.write(json.dumps(doc) + "\n")
```

Async:

```python
async for doc in api.export("category:vulnscan domain:example.com"):
    ...
```

HTTP errors are raised when the stream opens, before the first document, so a
`try` around the loop is enough.

## Bulk inputs

Bulk methods accept a `Path`, a path as a string, a raw newline-separated
string, an iterable of assets, or ready-made bytes:

```python
api.bulk_simple("datascan", "ips.txt")
api.bulk_simple("datascan", Path("ips.txt"))
api.bulk_simple("datascan", ["1.1.1.1", "8.8.8.8"])
api.bulk_summary("domain", domains_from_your_database)
```

## Alerts

```python
api.add_alert(
    name="nginx in FR",
    query="category:vulnscan domain:example.com -exists:cve",
    email="soc@example.com",
    threshold=">0",
)

for alert in api.alerts():
    print(alert.id, alert.name, alert.threshold)

api.del_alert(0)
```

## Errors

Every exception derives from `OnypheError`:

| exception | when |
| --- | --- |
| `ConfigError` | no API key could be resolved |
| `ParamError` | bad category, missing file, empty bulk payload |
| `TransportError` | DNS, TLS, timeout, connection reset |
| `AuthenticationError` | 401 / 403 |
| `PaymentRequiredError` | 402 — credits exhausted, or API not in your license |
| `NotFoundError` | 404 |
| `RateLimitError` | 429, with `.retry_after` when ONYPHE says so |
| `ServerError` | 5xx |

`AuthenticationError`, `PaymentRequiredError`, `NotFoundError`,
`RateLimitError` and `ServerError` all subclass `APIError`, which carries
`.status_code` and the decoded `.payload`.

429 and 5xx are retried automatically (`max_retries`, exponential backoff,
honouring `Retry-After`); the exception only surfaces once the retries are
exhausted.

## Endpoints not wrapped yet

The Ondemand APIv3 (`scope`, `resolver`) and the beta ASD APIv1 are not
wrapped. Reach them with the escape hatch, which handles auth, retries and
error mapping like any other call:

```python
api.request("GET", "some/new/endpoint", params={"q": "..."})
```
