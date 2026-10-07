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
page.total  # total matching documents
page.count  # documents in this page
page.max_page  # last reachable page
page.results  # list[dict]
list(page)  # iterating a Response iterates its results
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

`search_iter` stops at `max_results`, at `max_pages`, at the last page ONYPHE
reports, or at the 10 000-result ceiling the Search API enforces — whichever
comes first. Past that ceiling, use `export`.

`max_pages` caps the number of API calls rather than the number of documents,
which is what you want when the budget is credits rather than volume:

```python
# at most 5 calls, so at most 500 documents
for hit in api.search_iter("domain:example.com", size=100, max_pages=5):
    ...
```

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

## On-demand scan

Everything else on this page reads what ONYPHE already collected. The
On-demand scope API makes ONYPHE *scan* an asset for you, which needs an
**On-demand subscription** — without it the call comes back as a
`PaymentRequiredError`.

```python
from pyonyphe import Onyphe

with Onyphe() as api:
    launch = api.ondemand_scope_ip("8.8.8.0/24", vulnscan=True, ports=[80, 443])
    print(launch.model_dump())   # the Scan ID is in there
```

Then, with that Scan ID in hand:

```python
from pyonyphe import ScanInProgressError

try:
    page = api.ondemand_scope_result(scan_id)
except ScanInProgressError as exc:
    print(f"{exc.scan_id} is not done yet, try again later")
else:
    for document in page:
        print(document)
```

ONYPHE states that a launch returns a Scan ID, but does not document the field
it travels in, so the client returns the envelope as it came and parses
nothing out of it. There is no polling helper yet either: retry
`ondemand_scope_result` yourself.

Four launch methods, two of them taking a list of targets and joining it for
you:

```python
api.ondemand_scope_ip("8.8.8.8")              # or "8.8.8.0/24"
api.ondemand_scope_domain("example.com")
api.ondemand_scope_ip_bulk(["1.1.1.1", "8.8.8.8", "10.0.0.0/24"])
api.ondemand_scope_domain_bulk(["a.tld", "b.tld"])
```

The two `_bulk` ones are served under the `/dev/` prefix, ONYPHE's development
tree: they can move without notice.

All four take the same optional arguments, and send nothing at all for the ones
you leave out:

| argument | sent as | meaning |
| --- | --- | --- |
| `import_results` | `import` | import the results into the ONYPHE dataset |
| `vulnscan` | `vulnscan` | also run the vulnerability scan |
| `urlscan` | `urlscan` | also crawl the HTTP services found |
| `ports` | `ports` | `[80, 443]` is sent as `"80,443"` |
| `maxscantime` | `maxscantime` | scan budget, in seconds |

`import_results` spells out what `import` cannot: the name is a Python
keyword. **Importing makes the results PUBLIC** — they land in the ONYPHE
dataset and every ONYPHE user can see them. Leave it alone unless that is what
you want.

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
| `ScanInProgressError` | an On-demand scan has no results yet, with `.scan_id` |
| `ServerError` | 5xx |

`AuthenticationError`, `PaymentRequiredError`, `NotFoundError`,
`RateLimitError`, `ScanInProgressError` and `ServerError` all subclass
`APIError`, which carries `.status_code` and the decoded `.payload`.

`ScanInProgressError` is the odd one: it reports ONYPHE error code 103 or 111
on an On-demand scan, which means "not ready", not "failed". Catch it to retry
rather than to give up.

429 and 5xx are retried automatically (`max_retries`, exponential backoff,
honouring `Retry-After`); the exception only surfaces once the retries are
exhausted.

## Endpoints not wrapped yet

The Ondemand `resolver` endpoints and the beta ASD APIv1 are not wrapped
(`ondemand/scope` is, see above). Reach them with the escape hatch, which
handles auth, retries and error mapping like any other call:

```python
api.request("GET", "some/new/endpoint", params={"q": "..."})
```
