# pyonyphe

[![CI](https://github.com/sebdraven/pyonyphe/actions/workflows/ci.yml/badge.svg)](https://github.com/sebdraven/pyonyphe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pyonyphe.svg)](https://pypi.org/project/pyonyphe/)
[![Python](https://img.shields.io/pypi/pyversions/pyonyphe.svg)](https://pypi.org/project/pyonyphe/)

Python client and command line interface for [ONYPHE](https://www.onyphe.io),
the Cyber Defense Search Engine.

- Sync (`Onyphe`) and async (`AsyncOnyphe`) clients, both fully typed.
- Covers APIv2: User, Search, Export, Summary, Simple, Simple Best, the Bulk
  variants, Discovery and Alert — plus a `request()` escape hatch for anything
  ONYPHE ships next.
- `pyonyphe` CLI with table / JSON / NDJSON output.
- Automatic pagination, retries with backoff, `Retry-After` support.

## Install

```bash
uv add pyonyphe
uv run pyonyphe --help
```

## Library

```python
from pyonyphe import Onyphe

with Onyphe() as api:                     # key read from ONYPHE_API_KEY
    page = api.search("category:datascan product:Nginx country:FR")
    print(page.total, "results")

    for hit in api.search_iter("domain:example.com", max_results=500):
        print(hit["ip"], hit.get("port"))

    for doc in api.export("category:vulnscan domain:example.com"):
        ...
```

Async, same surface:

```python
import asyncio
from pyonyphe import AsyncOnyphe

async def main() -> None:
    async with AsyncOnyphe() as api:
        page = await api.search("protocol:rdp")
        async for hit in api.export("domain:example.com"):
            print(hit["ip"])

asyncio.run(main())
```

## CLI

```bash
export ONYPHE_API_KEY=...

pyonyphe user
pyonyphe search 'protocol:rdp country:FR' --size 20
pyonyphe search 'domain:example.com' --all --format ndjson -o results.ndjson
pyonyphe export 'category:vulnscan domain:example.com' -o export.ndjson
pyonyphe summary ip 8.8.8.8
pyonyphe simple whois 8.8.8.8 --best
pyonyphe resolve example.com
pyonyphe bulk simple datascan ips.txt -o out.ndjson
pyonyphe alert list
```

## Configuration

The API key is resolved in this order:

1. `api_key=` argument, or `--api-key` on the CLI
2. the `ONYPHE_API_KEY` environment variable
3. `~/.config/pyonyphe/config.toml`
4. `~/.onyphe.ini` — the file used by the official ONYPHE CLI

```toml
# ~/.config/pyonyphe/config.toml
[onyphe]
api_key = "..."
```

## Documentation

- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [CLI reference](docs/cli.md)
- [API reference](docs/api.md)
- [Migrating from 2.x](docs/migration.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT — see [LICENSE](LICENSE).
